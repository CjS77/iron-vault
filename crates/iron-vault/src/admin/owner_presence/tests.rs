//! Owner presence's answers that end before the approver key is checked, driven through an exchange whose CLI end the
//! test holds: input that cannot be the passphrase is refused as a wrong one, and a `lock` cancels the change.

use std::future::{self, Future};

use iron_vault_store::{ApproverId, ApproverLabel, SoftwareSigner, UtcSecond};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use zeroize::Zeroizing;

use super::*;
use crate::admin::protocol::{self, Decoded, Frame};
use crate::admin::server::Limits;

/// The prompt the CLI end receives next, read a byte at a time so nothing after it is consumed.
async fn read_prompt(cli: &mut UnixStream) -> Prompt {
    let mut bytes = Vec::new();
    loop {
        match protocol::decode(&bytes).unwrap() {
            Decoded::Frame {
                frame: Frame::Prompt(prompt),
                ..
            } => return prompt,
            Decoded::Frame { frame, .. } => panic!("expected a prompt, got {frame:?}"),
            Decoded::NeedMore(_) => bytes.push(cli.read_u8().await.unwrap()),
        }
    }
}

/// A pinned approver labelled `label`, with a fresh key.
fn approver(label: &str) -> PinnedApprover {
    let (_, key) = SoftwareSigner::generate().unwrap();
    PinnedApprover::software_for_tests(ApproverId::generate(), key, ApproverLabel::new(label).unwrap(), UtcSecond::EPOCH)
}

/// What the CLI end sends for one prompt: owner input, a switch frame, or nothing.
enum Reply {
    Input(&'static [u8]),
    Switch,
    Silence,
}

/// Runs the approver prompt over `approvers` with `lock_requested`; the CLI end answers each prompt it reads with the next of
/// `replies`, and stops answering when they run out. Returns the prompts the CLI saw, then the outcome with the approver's
/// label.
async fn ask_with<L: Future<Output = ()>>(
    approvers: &[PinnedApprover],
    replies: Vec<Reply>,
    lock_requested: impl Fn() -> L,
) -> (Vec<Prompt>, Option<(String, PassphraseAnswer)>) {
    let (service, mut cli) = UnixStream::pair().unwrap();
    let mut exchange = Exchange::new(service, Limits::default());
    let asked = ask_approval_passphrase(&mut exchange, approvers, lock_requested);
    let cli_side = async {
        let mut prompts = Vec::new();
        for reply in replies {
            prompts.push(read_prompt(&mut cli).await);
            let frame = match reply {
                Reply::Input(bytes) => Frame::OwnerInput(OwnerInput::new(Zeroizing::new(bytes.to_vec()))),
                Reply::Switch => Frame::Switch,
                Reply::Silence => continue,
            };
            let mut bytes = Vec::new();
            protocol::encode(&frame, &mut bytes).unwrap();
            cli.write_all(&bytes).await.unwrap();
        }
        prompts
    };
    let (outcome, prompts) = tokio::join!(asked, cli_side);
    (
        prompts,
        outcome
            .unwrap()
            .map(|(approver, answer)| (approver.label().as_str().to_owned(), answer)),
    )
}

/// [`ask_with`] one approver labelled `label`, which the CLI end answers with `answer`, or never answers when `None`.
async fn prompt_for<L: Future<Output = ()>>(
    label: &str,
    answer: Option<&'static [u8]>,
    lock_requested: impl Fn() -> L,
) -> (Prompt, Result<ApprovalPassphrase, NoPresence>) {
    let reply = answer.map_or(Reply::Silence, Reply::Input);
    let (mut prompts, outcome) = ask_with(&[approver(label)], vec![reply], lock_requested).await;
    let prompt = prompts.remove(0);
    let result = match outcome.unwrap().1 {
        PassphraseAnswer::Typed(passphrase) => Ok(passphrase),
        PassphraseAnswer::Unusable => Err(NoPresence::Refused(PresenceRefusal::Denied(DenialKind::WrongPassphrase))),
        PassphraseAnswer::CancelledByLock => Err(NoPresence::CancelledByLock),
    };
    (prompt, result)
}

/// [`prompt_for`] the software signer as `init` pins it.
async fn presence_with<L: Future<Output = ()>>(
    answer: Option<&'static [u8]>,
    lock_requested: impl Fn() -> L,
) -> (Prompt, Result<ApprovalPassphrase, NoPresence>) {
    prompt_for("approval passphrase", answer, lock_requested).await
}

fn passphrase_prompt() -> Prompt {
    Prompt {
        label: "Approval passphrase for \"approval passphrase\"".to_owned(),
        secret: true,
        switchable: false,
    }
}

// The store refuses a label with a control or format character such as U+202E, so a pinned label can only reach the
// prompt with non-ASCII text; the prompt escapes it all the same.
#[tokio::test]
async fn the_prompt_names_the_asked_approver_with_its_label_escaped() {
    let (prompt, _) = prompt_for("Dave's clé", None, || future::ready(())).await;

    assert_eq!(prompt.label, "Approval passphrase for \"Dave's cl\\u{e9}\"");
}

#[tokio::test]
async fn input_that_cannot_be_the_passphrase_is_denied_without_a_key_check() {
    let (prompt, outcome) = presence_with(Some(&[0xff, 0xfe]), future::pending::<()>).await;

    assert_eq!(prompt, passphrase_prompt());
    assert!(matches!(outcome, Err(NoPresence::Refused(PresenceRefusal::Denied(_)))));
}

#[tokio::test]
async fn a_lock_at_the_prompt_cancels_the_change() {
    let (prompt, outcome) = presence_with(None, || future::ready(())).await;

    assert_eq!(prompt, passphrase_prompt());
    assert!(matches!(outcome, Err(NoPresence::CancelledByLock)));
}

#[tokio::test]
async fn a_usable_passphrase_goes_on_to_the_key_check() {
    let (_, outcome) = presence_with(Some(b"APPROVAL-typed-91c2"), future::pending::<()>).await;

    assert!(outcome.is_ok());
}

/// The labels of the prompts the CLI saw, and whether each could switch.
fn shown(prompts: &[Prompt]) -> Vec<(&str, bool)> {
    prompts.iter().map(|prompt| (prompt.label.as_str(), prompt.switchable)).collect()
}

#[tokio::test]
async fn one_pinned_approver_is_not_switchable() {
    let (prompts, _) = ask_with(&[approver("only")], vec![Reply::Input(b"x")], future::pending::<()>).await;

    assert_eq!(shown(&prompts), [("Approval passphrase for \"only\"", false)]);
}

#[tokio::test]
async fn a_switch_asks_the_next_approver_and_wraps_after_the_last() {
    let approvers = [approver("first"), approver("second")];
    let replies = vec![Reply::Switch, Reply::Switch, Reply::Input(b"typed-passphrase")];

    let (prompts, outcome) = ask_with(&approvers, replies, future::pending::<()>).await;

    assert_eq!(
        shown(&prompts),
        [
            ("Approval passphrase for \"first\"", true),
            ("Approval passphrase for \"second\"", true),
            ("Approval passphrase for \"first\"", true),
        ]
    );
    assert!(matches!(outcome, Some((label, PassphraseAnswer::Typed(_))) if label == "first"));
}

#[tokio::test]
async fn the_answer_is_for_the_approver_last_asked() {
    let approvers = [approver("first"), approver("second")];

    let (_, outcome) = ask_with(&approvers, vec![Reply::Switch, Reply::Input(&[0xff])], future::pending::<()>).await;

    assert!(matches!(outcome, Some((label, PassphraseAnswer::Unusable)) if label == "second"));
}

#[tokio::test]
async fn no_pinned_approver_asks_nothing() {
    let (prompts, outcome) = ask_with(&[], vec![], future::pending::<()>).await;

    assert!(prompts.is_empty() && outcome.is_none());
}
