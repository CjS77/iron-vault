//! Charging requests against route and caller rate limits under concurrency (spec §3.5, §3.12, §3.15, R-1).
//!
//! Each route has one [`TokenBucket`] shared by all its callers, and a caller may also have a stricter bucket on that
//! route. A request passes only if both allow it, and it takes a token from both or from neither: otherwise a request
//! refused by its caller's limit would still drain the shared route bucket and starve the route's other callers.

use std::collections::BTreeMap;
use std::sync::{Mutex, PoisonError};
use std::time::Instant;

use thiserror::Error;

use crate::activation::ActivePolicy;
use crate::name::{CallerName, RouteName};
use crate::route::RouteConfig;
use crate::token_bucket::{RetryAfter, TokenBucket};
use crate::validated::ValidatedConfig;

/// The token buckets for one [`ActivePolicy`], shared by every thread that serves requests.
///
/// The service charges a request after authorizing it and before confirmation or credential resolution (spec §3.5
/// step 5). Each route's buckets sit behind their own lock, so requests on different routes never contend, and a
/// charge locks exactly one route, so there is no lock ordering to get wrong.
///
/// **Reload.** A new policy gets a new limiter, and like a restart every bucket starts empty. Levels are deliberately
/// not carried over: an empty bucket never grants more than the old one held, so neither a reload nor a restart can
/// replenish an allowance instantly.
#[derive(Debug)]
pub struct RateLimiter {
    routes: BTreeMap<RouteName, Mutex<RouteBuckets>>,
}

/// One route's shared bucket and, for each caller granted the route, its stricter bucket if it has one.
#[derive(Debug)]
struct RouteBuckets {
    route: TokenBucket,
    callers: BTreeMap<CallerName, Option<TokenBucket>>,
}

/// Which limit refused a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExhaustedLimit {
    /// The route's bucket, shared by all its callers, is empty.
    Route,
    /// The caller's stricter bucket for this route is empty.
    Caller,
    /// Both buckets are empty.
    Both,
}

/// A request refused because a rate limit is exhausted; the service answers `429` (spec §3.12).
///
/// It names only the requesting caller's own limit or the route's aggregate one, never another caller's usage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("rate limit exhausted; retry after {} s", .retry_after.as_secs())]
pub struct RateLimited {
    retry_after: RetryAfter,
    limit: ExhaustedLimit,
}

impl RateLimited {
    /// How long until both limits would allow the request: the longer of the two waits.
    pub fn retry_after(&self) -> RetryAfter {
        self.retry_after
    }

    /// Which limit refused the request.
    pub fn limit(&self) -> ExhaustedLimit {
        self.limit
    }
}

/// Why a charge did not pass.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ChargeError {
    /// A rate limit is exhausted.
    #[error(transparent)]
    Limited(#[from] RateLimited),
    /// The route is not in the policy. Authorization passes only known routes, so this is a defect, not a caller error.
    #[error("rate limiter has no route {route}")]
    UnknownRoute {
        /// The route charged.
        route: RouteName,
    },
    /// The caller is not granted the route, which includes a caller the policy does not know; like an unknown route,
    /// this is a defect.
    #[error("caller {caller} is not granted route {route}")]
    NotGranted {
        /// The caller charged.
        caller: CallerName,
        /// The route charged.
        route: RouteName,
    },
}

impl RateLimiter {
    /// Creates every bucket for `policy`, all empty and accounting for time from `now` (spec §3.5).
    ///
    /// Routes that are unavailable get buckets too; authorization keeps requests off them, and a limiter whose routes
    /// match the configuration needs no rebuild rule of its own.
    pub fn new(policy: &ActivePolicy, now: Instant) -> Self {
        let config = policy.config();
        let routes = config.routes().iter().map(|(name, route)| (name.clone(), Mutex::new(RouteBuckets::new(config, name, route, now))));
        Self { routes: routes.collect() }
    }

    /// Charges one request by `caller` on `route` at `now`, taking a token from the route bucket and from the caller's
    /// stricter bucket if it has one, or from neither.
    ///
    /// Safe to call from many threads at once: the check and the take happen under the route's lock, so concurrent
    /// requests can never overspend a bucket.
    pub fn charge(&self, caller: &CallerName, route: &RouteName, now: Instant) -> Result<(), ChargeError> {
        let buckets = self.routes.get(route).ok_or_else(|| ChargeError::UnknownRoute { route: route.clone() })?;
        // A panic elsewhere while holding the lock cannot leave the buckets inconsistent: they are plain numbers
        // updated in single assignments, so the guard is safe to reuse.
        let mut buckets = buckets.lock().unwrap_or_else(PoisonError::into_inner);
        buckets.charge(caller, route, now)
    }
}

impl RouteBuckets {
    /// Buckets for `route`: its shared bucket, and an entry for every caller granted it.
    fn new(config: &ValidatedConfig, name: &RouteName, route: &RouteConfig, now: Instant) -> Self {
        let callers = config
            .callers()
            .iter()
            .filter(|(_, caller)| caller.routes().contains(name))
            .map(|(caller_name, caller)| (caller_name.clone(), caller.rate_limits().get(name).map(|limit| TokenBucket::new(*limit, now))))
            .collect();
        Self { route: TokenBucket::new(route.rate_limit(), now), callers }
    }

    /// Checks both of `caller`'s buckets on this route (`route` names it for errors), then spends from both or neither.
    fn charge(&mut self, caller: &CallerName, route: &RouteName, now: Instant) -> Result<(), ChargeError> {
        let not_granted = || ChargeError::NotGranted { caller: caller.clone(), route: route.clone() };
        let caller_bucket = self.callers.get_mut(caller).ok_or_else(not_granted)?;
        let route_wait = self.route.refill_and_check(now).err();
        let caller_wait = caller_bucket.as_mut().and_then(|bucket| bucket.refill_and_check(now).err());
        match refusal(route_wait, caller_wait) {
            Some(limited) => Err(limited.into()),
            None => {
                self.route.spend();
                caller_bucket.iter_mut().for_each(TokenBucket::spend);
                Ok(())
            }
        }
    }
}

/// The refusal for the route's and the caller's waits, if either bucket is empty; a client must wait out the longer.
fn refusal(route_wait: Option<RetryAfter>, caller_wait: Option<RetryAfter>) -> Option<RateLimited> {
    let limited = |retry_after, limit| Some(RateLimited { retry_after, limit });
    match (route_wait, caller_wait) {
        (None, None) => None,
        (Some(route), None) => limited(route, ExhaustedLimit::Route),
        (None, Some(caller)) => limited(caller, ExhaustedLimit::Caller),
        (Some(route), Some(caller)) => limited(longer(route, caller), ExhaustedLimit::Both),
    }
}

fn longer(a: RetryAfter, b: RetryAfter) -> RetryAfter {
    match a.as_secs() >= b.as_secs() {
        true => a,
        false => b,
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;
    use std::sync::Barrier;
    use std::time::Duration;

    use super::*;
    use crate::activation::{Capabilities, CatalogEntry, CredentialCatalog, activate};
    use crate::config::ParsedConfig;
    use crate::name::CredentialName;
    use crate::port::Port;
    use crate::rate_limit::RateLimit;
    use crate::spec_example::SPEC_EXAMPLE;

    /// A vault where every §3.3 credential is usable at its route's upstream.
    struct Healthy;

    impl CredentialCatalog for Healthy {
        fn entry(&self, _: &CredentialName) -> CatalogEntry {
            let hosts = ["api.fx.example", "api.venice.ai", "api.search.brave.com"];
            CatalogEntry::Usable { origins: hosts.iter().map(|host| (host.parse().unwrap(), Port::HTTPS)).collect() }
        }
    }

    /// A second `fx` caller, `fx-other`, with no stricter limit, and `fx-mcp` limited to a burst of 3.
    const TWO_FX_CALLERS: &str = r#"
[callers.fx-mcp.rate_limits]
fx = { requests = 1, per_seconds = 60, burst = 3 }

[callers.fx-other]
listener = "local"
token_hash = "blake2b:1111111111111111111111111111111111111111111111111111111111111111"
routes = ["fx"]
"#;

    fn n<T: std::str::FromStr<Err: std::fmt::Debug>>(s: &str) -> T {
        s.parse().unwrap()
    }

    fn limiter(doc: &str, now: Instant) -> RateLimiter {
        let config = ValidatedConfig::try_from(ParsedConfig::from_toml(doc.as_bytes()).unwrap()).unwrap();
        RateLimiter::new(&activate(&config, &Capabilities::default(), &Healthy).unwrap(), now)
    }

    fn two_callers(now: Instant) -> RateLimiter {
        limiter(&format!("{SPEC_EXAMPLE}{TWO_FX_CALLERS}"), now)
    }

    /// Charges `count` times; returns how many passed.
    fn charge_n(limiter: &RateLimiter, caller: &str, route: &str, now: Instant, count: usize) -> usize {
        (0..count).filter(|_| limiter.charge(&n(caller), &n(route), now).is_ok()).count()
    }

    fn route_level(limiter: &RateLimiter, route: &str, now: Instant) -> u64 {
        limiter.routes[&n::<RouteName>(route)].lock().unwrap().route.level_at(now)
    }

    fn limited(result: Result<(), ChargeError>) -> RateLimited {
        match result {
            Err(ChargeError::Limited(limited)) => limited,
            other => panic!("expected a rate-limit refusal, got {other:?}"),
        }
    }

    /// A refusal from a fresh bucket that refills one token per `secs` seconds.
    fn wait_of(secs: u32, now: Instant) -> RetryAfter {
        let limit = RateLimit::new(NonZeroU32::MIN, NonZeroU32::new(secs).unwrap(), NonZeroU32::MIN);
        TokenBucket::new(limit, now).try_take(now).unwrap_err()
    }

    /// 64 threads race 100 charges at one instant; returns how many passed.
    fn race(limiter: &RateLimiter, caller: &CallerName, route: &RouteName, now: Instant) -> usize {
        const THREADS: usize = 64;
        let start = Barrier::new(THREADS);
        std::thread::scope(|scope| {
            let start = &start;
            let handles: Vec<_> = (0..THREADS)
                .map(|thread| {
                    scope.spawn(move || {
                        start.wait();
                        (thread..100).step_by(THREADS).filter(|_| limiter.charge(caller, route, now).is_ok()).count()
                    })
                })
                .collect();
            handles.into_iter().map(|handle| handle.join().unwrap()).sum()
        })
    }

    #[test]
    fn buckets_start_empty() {
        let t0 = Instant::now();
        let limiter = limiter(SPEC_EXAMPLE, t0);
        assert_eq!(limiter.routes.keys().map(RouteName::as_str).collect::<Vec<_>>(), ["brave", "fx", "venice"]);
        let refused = limited(limiter.charge(&n("fx-mcp"), &n("fx"), t0));
        assert_eq!((refused.limit(), refused.retry_after().as_secs()), (ExhaustedLimit::Route, 1));
    }

    #[test]
    fn concurrent_charges_never_exceed_the_burst() {
        let t0 = Instant::now();
        let (caller, route) = (n("fx-mcp"), n("fx"));
        (0..50).for_each(|_| {
            let limiter = limiter(SPEC_EXAMPLE, t0);
            let now = t0 + Duration::from_secs(600);
            assert_eq!(race(&limiter, &caller, &route, now), 10);
            assert_eq!(route_level(&limiter, "fx", now), 0);
        });
    }

    #[test]
    fn caller_limit_refusals_cost_the_route_nothing() {
        let t0 = Instant::now();
        let now = t0 + Duration::from_secs(600);
        let limiter = two_callers(t0);
        assert_eq!(charge_n(&limiter, "fx-mcp", "fx", now, 10), 3);
        assert_eq!(route_level(&limiter, "fx", now), 7);
        let refused = limited(limiter.charge(&n("fx-mcp"), &n("fx"), now));
        assert_eq!((refused.limit(), refused.retry_after().as_secs()), (ExhaustedLimit::Caller, 60));
        assert_eq!(charge_n(&limiter, "fx-other", "fx", now, 10), 7);
        assert_eq!(limited(limiter.charge(&n("fx-other"), &n("fx"), now)).limit(), ExhaustedLimit::Route);
    }

    #[test]
    fn route_limit_refusals_cost_the_caller_nothing() {
        let t0 = Instant::now();
        let now = t0 + Duration::from_secs(600);
        let limiter = two_callers(t0);
        assert_eq!(charge_n(&limiter, "fx-other", "fx", now, 10), 10);
        assert_eq!(limited(limiter.charge(&n("fx-mcp"), &n("fx"), now)).limit(), ExhaustedLimit::Route);
        // One second later the route has one token again, and fx-mcp's own bucket is still full.
        let later = now + Duration::from_secs(1);
        assert_eq!(charge_n(&limiter, "fx-mcp", "fx", later, 1), 1);
        let buckets = limiter.routes[&n::<RouteName>("fx")].lock().unwrap();
        assert_eq!(buckets.callers[&n::<CallerName>("fx-mcp")].as_ref().unwrap().level_at(later), 2);
    }

    #[test]
    fn both_exhausted_waits_for_the_longer() {
        let t0 = Instant::now();
        let refused = limited(two_callers(t0).charge(&n("fx-mcp"), &n("fx"), t0));
        assert_eq!((refused.limit(), refused.retry_after().as_secs()), (ExhaustedLimit::Both, 60));
        let (short, long) = (wait_of(2, t0), wait_of(5, t0));
        assert_eq!(refusal(Some(long), Some(short)).unwrap().retry_after(), long);
        assert_eq!(refusal(Some(short), Some(long)).unwrap().retry_after(), long);
        assert_eq!(refusal(None, None), None);
    }

    #[test]
    fn unknown_route_and_ungranted_caller_are_errors() {
        let t0 = Instant::now();
        let limiter = limiter(SPEC_EXAMPLE, t0);
        let now = t0 + Duration::from_secs(600);
        assert_eq!(limiter.charge(&n("fx-mcp"), &n("missing"), now), Err(ChargeError::UnknownRoute { route: n("missing") }));
        let not_granted = ChargeError::NotGranted { caller: n("naomi-backoffice"), route: n("fx") };
        assert_eq!(limiter.charge(&n("naomi-backoffice"), &n("fx"), now), Err(not_granted));
        assert_eq!(limiter.charge(&n("nobody"), &n("fx"), now), Err(ChargeError::NotGranted { caller: n("nobody"), route: n("fx") }));
        assert_eq!(route_level(&limiter, "fx", now), 10);
    }

    #[test]
    fn charging_survives_a_poisoned_lock() {
        let t0 = Instant::now();
        let limiter = limiter(SPEC_EXAMPLE, t0);
        let fx = &limiter.routes[&n::<RouteName>("fx")];
        let crashed = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    let _held = fx.lock().unwrap();
                    panic!("a request thread crashes while holding the fx lock");
                })
                .join()
        });
        assert!(crashed.is_err() && fx.is_poisoned());
        let now = t0 + Duration::from_secs(600);
        assert_eq!(charge_n(&limiter, "fx-mcp", "fx", now, 20), 10);
    }
}
