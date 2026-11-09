//! Shared setup for the streamed-response release tests: the credentials the tests scrub for, a proxy serving a scripted
//! upstream, and a caller that reads the chunked response body chunk by chunk while the upstream is still sending it.

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use iron_vault::scrub::SCRUB_REPLACEMENT;
use iron_vault_kinds::CredentialMaterial;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::mpsc;

use super::mock_upstream::{MockUpstream, TestCa};
use super::proxy_harness::{CallerRequest, Credential, Proxy, Setup, TOKEN_BYTES, Via, WAIT, token_hash};

/// How long the held-back measurement waits for more bytes before it takes what has arrived as all that will.
pub const QUIET: Duration = Duration::from_millis(150);

/// A credential the vault holds, the route that injects it, and every form of it the service must scrub.
pub struct Cred {
    pub route: &'static str,
    pub name: &'static str,
    pub material: CredentialMaterial,
    /// The slot, as a route's `slot` setting.
    pub slot: &'static str,
    pub forms: Vec<String>,
}

impl Cred {
    pub fn longest(&self) -> &str {
        self.forms.iter().max_by_key(|form| form.len()).unwrap()
    }
}

/// Shaped like the FX service's key (§6): 32 lowercase hex characters, sent in the `access_key` query slot.
pub fn fx() -> Cred {
    static_cred("fx", "fx_key", "3f9a1c07d2b84e65a0c1f7e93b5d8a42", "{ query = \"access_key\" }")
}

/// A generic Basic credential: a username and a password with characters a URL encodes.
pub fn basic() -> Cred {
    let (user, password) = ("fx-agent", "pa/ss+word=9f3e0a71");
    let token = STANDARD.encode(format!("{user}:{password}"));
    let forms = [token.clone(), format!("Basic {token}")]
        .into_iter()
        .chain(url_forms(&format!("{user}:{password}")))
        .chain(url_forms(password));
    Cred {
        route: "basic",
        name: "basic_cred",
        material: CredentialMaterial::Basic {
            username: user.into(),
            password: password.into(),
        },
        slot: "\"basic\"",
        forms: unique(forms),
    }
}

/// Shaped like a Brave Search key: 31 characters, `BSA` first.
pub fn brave() -> Cred {
    static_cred(
        "brave",
        "brave_key",
        "BSAx7Kq9ZpLm2Vt4Rw8Yc1Dn5Hf3Jb0",
        "{ header = \"X-Subscription-Token\" }",
    )
}

/// Shaped like a Venice key: 43 characters of the URL-safe alphabet.
pub fn venice() -> Cred {
    static_cred(
        "venice",
        "venice_key",
        "vK3_xT9-qLm2Zp7Rw4Yc1Dn8Hf5Jb0Ua6Gs-Ei_Onop",
        "{ header = \"Authorization\", format = \"Bearer {}\" }",
    )
}

/// A short static key with the three characters whose URL-encoded forms differ from it.
pub fn edge() -> Cred {
    static_cred("edge", "edge_key", "ed/ge+key=Ab12", "{ header = \"X-Api-Key\" }")
}

pub fn static_cred(route: &'static str, name: &'static str, key: &'static str, slot: &'static str) -> Cred {
    let encodings = [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD].map(|engine| engine.encode(key));
    Cred {
        route,
        name,
        material: CredentialMaterial::Static { key: key.into() },
        slot,
        forms: unique(url_forms(key).into_iter().chain(encodings)),
    }
}

/// `secret` as sent and URL-encoded in both hex cases, the forms scrubbing adds for every secret.
pub fn url_forms(secret: &str) -> [String; 3] {
    let encode = |lower: bool| {
        secret
            .chars()
            .map(|c| match c {
                '/' | '+' | '=' | ':' if lower => format!("%{:02x}", c as u32),
                '/' | '+' | '=' | ':' => format!("%{:02X}", c as u32),
                _ => c.to_string(),
            })
            .collect::<String>()
    };
    [secret.to_owned(), encode(false), encode(true)]
}

pub fn unique(forms: impl IntoIterator<Item = String>) -> Vec<String> {
    forms.into_iter().collect::<BTreeSet<_>>().into_iter().collect()
}

/// The proxy serving every credential's route to `upstream`, for one caller. The rate limit is lifted so a loop of
/// requests is never refused.
pub async fn start(ca: &TestCa, upstream: &MockUpstream, creds: Vec<Cred>) -> Proxy {
    let port = upstream.port();
    let hash = token_hash(TOKEN_BYTES);
    let routes = creds.iter().map(|c| format!("\"{}\"", c.route)).collect::<Vec<_>>().join(", ");
    let sections: String = creds
        .iter()
        .map(|c| {
            let (route, name, slot) = (c.route, c.name, c.slot);
            format!(
                r#"
[routes.{route}]
prefix = "/{route}"
upstream = "https://localhost:{port}/v1"
ca_file = "/etc/iron-vault/ca/test.pem"
credential = "{name}"
slot = {slot}
methods = ["GET"]
paths = ["/v1/**"]
rate_limit = {{ requests = 100000, per_seconds = 1, burst = 100000 }}
"#
            )
        })
        .collect();
    let callers_and_routes = format!("[callers.agent]\nlistener = \"local\"\ntoken_hash = \"{hash}\"\nroutes = [{routes}]\n{sections}");
    Proxy::start(Setup {
        ca,
        callers_and_routes,
        credentials: creds
            .into_iter()
            .map(|c| Credential {
                name: c.name,
                material: c.material,
                port,
            })
            .collect(),
        tcp: false,
        request_timeout_secs: 60,
        limits: "",
    })
    .await
}

/// A response body as the caller receives it: each chunk of the chunked framing with the time it arrived.
pub struct Streamed {
    chunks: mpsc::UnboundedReceiver<(Instant, Vec<u8>)>,
    /// The response headers, names lowercased, in arrival order.
    pub headers: Vec<(String, String)>,
}

impl Streamed {
    /// Sends `GET target` on a fresh Unix connection, checks the `200` head and reads the body chunk by chunk in a task,
    /// so the test can look at the body while the upstream is still sending it.
    pub async fn open(proxy: &Proxy, target: &str) -> Self {
        Self::open_with(proxy, target, &[]).await
    }

    /// [`open`](Self::open) with these extra request headers.
    pub async fn open_with(proxy: &Proxy, target: &str, request_headers: &[(&str, &str)]) -> Self {
        let mut stream = proxy.connect().await;
        let request = request_headers
            .iter()
            .fold(CallerRequest::get(target), |request, (name, value)| request.header(name, value))
            .signed(Via::Unix);
        stream.write_all(&request.to_bytes()).await.unwrap();
        let mut reader = BufReader::new(stream);
        let status = read_line(&mut reader).await.unwrap();
        assert!(status.contains(" 200 "), "{status}");
        let mut headers = Vec::new();
        while let line = read_line(&mut reader).await.unwrap()
            && !line.is_empty()
        {
            let (name, value) = line.split_once(':').unwrap();
            headers.push((name.to_ascii_lowercase(), value.trim().to_owned()));
        }
        let (tx, chunks) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Some(chunk) = next_chunk(&mut reader).await {
                if tx.send((Instant::now(), chunk)).is_err() {
                    break;
                }
            }
        });
        Self { chunks, headers }
    }

    /// The next chunk, or `None` once the body has ended.
    pub async fn next(&mut self) -> Option<(Instant, Vec<u8>)> {
        tokio::time::timeout(WAIT, self.chunks.recv()).await.expect("no chunk within WAIT")
    }

    /// Every chunk to the end of the body.
    pub async fn all(mut self) -> Vec<Vec<u8>> {
        let mut chunks = Vec::new();
        while let Some((_, chunk)) = self.next().await {
            chunks.push(chunk);
        }
        chunks
    }

    /// Reads until `at_least` bytes have arrived in all, then returns what has and when the last chunk arrived.
    pub async fn until_at(&mut self, at_least: usize) -> (Instant, Vec<u8>) {
        let mut body = Vec::new();
        let mut at = Instant::now();
        while body.len() < at_least {
            let (arrived, chunk) = self.next().await.expect("the body ended early");
            at = arrived;
            body.extend(chunk);
        }
        (at, body)
    }

    /// Reads until `at_least` bytes have arrived in all, then returns what has.
    pub async fn until(&mut self, at_least: usize) -> Vec<u8> {
        self.until_at(at_least).await.1
    }

    /// Whatever arrives until no chunk comes for [`QUIET`].
    pub async fn until_quiet(&mut self) -> Vec<u8> {
        let mut body = Vec::new();
        while let Ok(Some((_, chunk))) = tokio::time::timeout(QUIET, self.chunks.recv()).await {
            body.extend(chunk);
        }
        body
    }
}

pub async fn read_line(reader: &mut BufReader<UnixStream>) -> Option<String> {
    let mut line = String::new();
    (reader.read_line(&mut line).await.ok()? > 0).then(|| line.trim_end().to_owned())
}

/// The next chunk of a chunked body; `None` after the last chunk, or if the connection ends first.
pub async fn next_chunk(reader: &mut BufReader<UnixStream>) -> Option<Vec<u8>> {
    let size = usize::from_str_radix(&read_line(reader).await?, 16).ok()?;
    let mut chunk = vec![0; size];
    reader.read_exact(&mut chunk).await.ok()?;
    read_line(reader).await?;
    (size > 0).then_some(chunk)
}

pub fn replacement() -> &'static str {
    std::str::from_utf8(SCRUB_REPLACEMENT).unwrap()
}

/// A body holding every form of the credential between plain words, and the same body scrubbed.
pub fn body_with_every_form(cred: &Cred) -> (String, String) {
    let join = |forms: Vec<&str>| format!("start | {} | end\n", forms.join(" | "));
    let plain = join(cred.forms.iter().map(String::as_str).collect());
    let scrubbed = join(vec![replacement(); cred.forms.len()]);
    (plain, scrubbed)
}
