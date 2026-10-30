//! Generating caller tokens from the operating system's random source (spec §3.4).

use iron_vault_policy::CallerToken;
use rand_core::OsRng;
use thiserror::Error;

/// The operating system's random source failed, so no caller token was made.
///
/// There is no fallback source: a token drawn from anything weaker would be guessable.
#[derive(Debug, Error)]
#[error("the operating system's random source failed: {0}")]
pub struct RandomSourceError(rand_core::Error);

/// A new caller token from the operating system's random source.
pub fn generate_caller_token() -> Result<CallerToken, RandomSourceError> {
    CallerToken::from_random(&mut OsRng).map_err(RandomSourceError)
}

#[cfg(test)]
mod tests {
    use iron_vault_policy::TokenHash;
    use secrecy::ExposeSecret;

    use super::*;

    #[test]
    fn a_generated_token_parses_back() {
        let text = generate_caller_token().unwrap().expose_once();
        assert!(CallerToken::parse(text.expose_secret().as_bytes()).is_ok());
    }

    #[test]
    fn generated_tokens_differ() {
        let [first, second] = [(); 2].map(|()| TokenHash::of(&generate_caller_token().unwrap()));
        assert_ne!(first, second);
    }
}
