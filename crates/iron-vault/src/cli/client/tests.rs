//! The client's exchange end to end over a socket pair, against the admin server in process: the service prompts, the
//! client answers from piped input. Logs from both ends are captured at TRACE.

use std::io::Write;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use iron_vault::admin::dispatch::{AdminHandler, HandlerFuture, Handlers};
use iron_vault::admin::principal::{AdminPrincipal, AdminPrincipals};
use iron_vault::admin::protocol::{AdminCommand, AdminRequest, AdminResponse, MAX_BODY_LEN, Prompt, RevealedSecret};
use iron_vault::admin::server::{AdminServer, Exchange, Limits};
use iron_vault::deployment::DeploymentProfile;
use iron_vault::path_metadata::invoking_user;

use super::*;
use crate::cli::console::{InputError, OwnerConsole, Piped};

/// Distinctive enough that finding it in a log or an error can only be the typed value leaking.
const MARKER: &str = "MARKER-secret-5d1c9e";

/// What the handler got for one prompt: the owner input's bytes, or the `Debug` form of the exchange error.
type Answer = Result<Vec<u8>, String>;

/// The test-only command, registered for `ping`: it prompts in turn for each value, records what it got, and stops at
/// the first prompt that fails, so its command is cancelled.
struct Prompts {
    prompts: Vec<Prompt>,
    answers: Arc<Mutex<Vec<Answer>>>,
}

impl AdminHandler for Prompts {
    fn handle<'a>(&'a self, _principal: AdminPrincipal, _request: AdminRequest, exchange: &'a mut Exchange) -> HandlerFuture<'a> {
        Box::pin(async move {
            for prompt in &self.prompts {
                let answer = exchange.prompt(prompt).await;
                let recorded = answer
                    .as_ref()
                    .map(|input| input.expose_secret().to_vec())
                    .map_err(|e| format!("{e:?}"));
                self.answers.lock().unwrap().push(recorded);
                answer?;
            }
            Ok(AdminResponse::Success)
        })
    }
}

fn secret() -> Prompt {
    Prompt {
        label: "Secret".to_owned(),
        secret: true,
    }
}

fn plain() -> Prompt {
    Prompt {
        label: "Plain".to_owned(),
        secret: false,
    }
}

/// Log output, shared by the subscribers of both ends.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Captured {
    fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

fn capture(logs: &Captured) -> impl tracing::Subscriber + Send + Sync + use<> {
    let logs = logs.clone();
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_ansi(false)
        .with_writer(move || logs.clone())
        .finish()
}

/// Serves one connection on `stream` with `handler` registered for `ping`.
fn serve_one(stream: UnixStream, handler: impl AdminHandler + 'static) {
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    runtime.block_on(async {
        stream.set_nonblocking(true).unwrap();
        let stream = tokio::net::UnixStream::from_std(stream).unwrap();
        let principals = AdminPrincipals::new(DeploymentProfile::Protected, invoking_user().unwrap().uid);
        let handlers = Handlers::default().with(AdminCommand::Ping, handler);
        AdminServer::new(principals, handlers, Limits::default())
            .serve_connection(stream)
            .await;
    });
}

/// How one exchange went: the client's result, what the handler got, and every log line from both ends.
struct Run {
    result: Result<AdminResponse, ClientError>,
    answers: Vec<Answer>,
    logs: String,
}

/// Runs `ping` against a service that asks `prompts`, answering them from `input`.
fn run(prompts: Vec<Prompt>, input: &[u8]) -> Run {
    let logs = Captured::default();
    let answers = Arc::default();
    let handler = Prompts {
        prompts,
        answers: Arc::clone(&answers),
    };
    let (mut client, service) = UnixStream::pair().unwrap();
    let service_logs = capture(&logs);
    let served = std::thread::spawn(move || tracing::subscriber::with_default(service_logs, || serve_one(service, handler)));
    let mut console = Piped::new(input, false);
    let result = tracing::subscriber::with_default(capture(&logs), || converse(&mut client, AdminRequest::Ping, &mut console));
    // A cancelled client closes the connection by dropping it; the service waits for that.
    drop(client);
    served.join().unwrap();
    let answers = std::mem::take(&mut *answers.lock().unwrap());
    Run {
        result,
        answers,
        logs: logs.text(),
    }
}

fn value(bytes: &[u8]) -> Answer {
    Ok(bytes.to_vec())
}

fn closed() -> Answer {
    Err("Closed".to_owned())
}

#[test]
fn one_value_is_read_from_a_line_of_stdin() {
    let run = run(vec![secret()], b"s3cret\n");
    assert!(matches!(run.result.unwrap(), AdminResponse::Success));
    assert_eq!(run.answers, [value(b"s3cret")]);
}

#[test]
fn several_prompts_read_consecutive_lines() {
    let run = run(vec![secret(), plain()], b"first\nsecond\n");
    assert!(matches!(run.result.unwrap(), AdminResponse::Success));
    assert_eq!(run.answers, [value(b"first"), value(b"second")]);
}

#[test]
fn an_empty_line_is_an_empty_value() {
    let run = run(vec![secret()], b"\n");
    assert!(matches!(run.result.unwrap(), AdminResponse::Success));
    assert_eq!(run.answers, [value(b"")]);
}

#[test]
fn crlf_line_endings_are_stripped() {
    let run = run(vec![secret(), plain()], b"first\r\nsecond\r\n");
    assert!(matches!(run.result.unwrap(), AdminResponse::Success));
    assert_eq!(run.answers, [value(b"first"), value(b"second")]);
}

#[test]
fn an_overlong_value_is_refused_unsent_and_cancels_the_command() {
    let over = format!("{}\n", MARKER.repeat(MAX_BODY_LEN / MARKER.len() + 1));
    let run = run(vec![secret()], over.as_bytes());
    let error = run.result.unwrap_err();
    assert!(matches!(error, ClientError::Input(InputError::TooLong)), "{error:?}");
    assert_eq!(run.answers, [closed()]);
    assert!(!error.to_string().contains(MARKER), "{error}");
    assert!(!run.logs.contains(MARKER), "{}", run.logs);
}

#[test]
fn input_that_ends_before_a_value_cancels_the_command() {
    let run = run(vec![secret(), plain()], b"only one\n");
    let error = run.result.unwrap_err();
    assert!(matches!(error, ClientError::Input(InputError::NoInput)), "{error:?}");
    assert_eq!(run.answers, [value(b"only one"), closed()]);
    assert!(run.logs.contains("cancelled"), "{}", run.logs);
}

#[test]
fn typed_values_appear_in_no_log_line_at_trace() {
    let input = format!("{MARKER}\n{MARKER}-plain\n");
    let run = run(vec![secret(), plain()], input.as_bytes());
    assert!(matches!(run.result.unwrap(), AdminResponse::Success));
    assert_eq!(run.answers, [value(MARKER.as_bytes()), value(format!("{MARKER}-plain").as_bytes())]);
    assert!(run.logs.contains("admin command `ping`"), "the capture saw nothing: {}", run.logs);
    assert!(!run.logs.contains(MARKER), "{}", run.logs);
}

#[test]
fn a_service_that_stops_answering_times_out() {
    let (mut client, _silent) = UnixStream::pair().unwrap();
    client.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
    let mut console = Piped::new(&b""[..], false);
    let error = converse(&mut client, AdminRequest::Ping, &mut console).unwrap_err();
    assert!(matches!(error, ClientError::TimedOut), "{error:?}");
}

/// The test-only command, registered for `ping`, that shows a notice, reveals [`MARKER`], then prompts once and records
/// the answer.
struct Shows {
    answers: Arc<Mutex<Vec<Answer>>>,
}

impl AdminHandler for Shows {
    fn handle<'a>(&'a self, _principal: AdminPrincipal, _request: AdminRequest, exchange: &'a mut Exchange) -> HandlerFuture<'a> {
        Box::pin(async move {
            exchange.notice("save this key\n").await?;
            exchange.reveal(MARKER.as_bytes()).await?;
            let answer = exchange.prompt(&plain()).await?;
            self.answers.lock().unwrap().push(value(answer.expose_secret()));
            Ok(AdminResponse::Success)
        })
    }
}

/// What the owner console was asked to do, in order.
#[derive(Debug, PartialEq, Eq)]
enum Shown {
    Notice(String),
    Reveal(Vec<u8>),
    Prompt(String),
}

/// An owner console that records each call and answers every prompt `yes`.
#[derive(Default)]
struct Recording(Vec<Shown>);

impl OwnerConsole for Recording {
    fn collect(&mut self, prompt: &Prompt) -> Result<OwnerInput, InputError> {
        self.0.push(Shown::Prompt(prompt.label.clone()));
        Ok(OwnerInput::new(Zeroizing::new(b"yes".to_vec())))
    }

    fn notice(&mut self, text: &str) -> Result<(), InputError> {
        self.0.push(Shown::Notice(text.to_owned()));
        Ok(())
    }

    fn reveal(&mut self, secret: &RevealedSecret) -> Result<(), InputError> {
        self.0.push(Shown::Reveal(secret.expose_secret().to_vec()));
        Ok(())
    }
}

#[test]
fn notices_reveals_and_prompts_reach_the_console_in_order_and_the_reveal_reaches_no_log() {
    let logs = Captured::default();
    let answers = Arc::default();
    let handler = Shows {
        answers: Arc::clone(&answers),
    };
    let (mut client, service) = UnixStream::pair().unwrap();
    let service_logs = capture(&logs);
    let served = std::thread::spawn(move || tracing::subscriber::with_default(service_logs, || serve_one(service, handler)));
    let mut console = Recording::default();
    let result = tracing::subscriber::with_default(capture(&logs), || converse(&mut client, AdminRequest::Ping, &mut console));
    drop(client);
    served.join().unwrap();
    assert!(matches!(result.unwrap(), AdminResponse::Success));
    assert_eq!(
        console.0,
        [
            Shown::Notice("save this key\n".to_owned()),
            Shown::Reveal(MARKER.as_bytes().to_vec()),
            Shown::Prompt("Plain".to_owned()),
        ]
    );
    assert_eq!(*answers.lock().unwrap(), [value(b"yes")]);
    let logs = logs.text();
    assert!(logs.contains("admin command `ping`"), "the capture saw nothing: {logs}");
    assert!(!logs.contains(MARKER), "{logs}");
}

/// A temporary config file holding the given bytes, removed on drop.
struct ConfigFile(std::path::PathBuf);

impl ConfigFile {
    fn new(name: &str, bytes: &[u8]) -> Self {
        let path = std::env::temp_dir().join(format!("iv-config-{}-{name}.toml", std::process::id()));
        std::fs::write(&path, bytes).unwrap();
        Self(path)
    }
}

impl Drop for ConfigFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[test]
fn a_config_file_is_read_whole_up_to_the_limit_and_refused_past_it_without_quoting_it() {
    let longest = ConfigFile::new("longest", &[b'#'; MAX_CONFIG_LEN]);
    assert_eq!(read_config(&longest.0).unwrap().bytes().len(), MAX_CONFIG_LEN);
    let over = ConfigFile::new("over", &[MARKER.as_bytes(), &[b'#'; MAX_CONFIG_LEN]].concat());
    let message = read_config(&over.0).unwrap_err();
    assert!(message.contains("longer than") && !message.contains(MARKER), "{message}");
    assert_eq!(config_approve(Some(Path::new("/nonexistent/admin.sock")), &over.0), Exit::Usage);
}

#[test]
fn an_approval_prints_the_service_version_digest_and_headline() {
    let result = ApprovalResult {
        version: 3,
        digest: [0xab; 32],
        headline: "callers: none".to_owned(),
    };
    assert_eq!(
        approved(&result),
        format!("approved version 3 (blake2b:{})\ncallers: none\n", "ab".repeat(32))
    );
}
