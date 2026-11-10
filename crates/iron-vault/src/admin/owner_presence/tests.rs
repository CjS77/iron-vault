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

/// Runs the presence prompt for `asked` with `lock_requested`; the CLI end answers with `answer`, or never answers when it
/// is `None`.
async fn prompt_for(
    asked: &PinnedApprover,
    answer: Option<&[u8]>,
    lock_requested: impl Future<Output = ()>,
) -> (Prompt, Result<ApprovalPassphrase, NoPresence>) {
    let (service, mut cli) = UnixStream::pair().unwrap();
    let mut exchange = Exchange::new(service, Limits::default());
    let answered = presence_passphrase(&mut exchange, asked, lock_requested);
    let cli_side = async {
        let prompt = read_prompt(&mut cli).await;
        if let Some(answer) = answer {
            let mut bytes = Vec::new();
            protocol::encode(&Frame::OwnerInput(OwnerInput::new(Zeroizing::new(answer.to_vec()))), &mut bytes).unwrap();
            cli.write_all(&bytes).await.unwrap();
        }
        prompt
    };
    let (outcome, prompt) = tokio::join!(answered, cli_side);
    (prompt, outcome.unwrap())
}

/// [`prompt_for`] the software signer as `init` pins it.
async fn presence_with(
    answer: Option<&[u8]>,
    lock_requested: impl Future<Output = ()>,
) -> (Prompt, Result<ApprovalPassphrase, NoPresence>) {
    prompt_for(&approver("approval passphrase"), answer, lock_requested).await
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
    let (prompt, _) = prompt_for(&approver("Dave's clé"), None, future::ready(())).await;

    assert_eq!(prompt.label, "Approval passphrase for \"Dave's cl\\u{e9}\"");
}

#[tokio::test]
async fn input_that_cannot_be_the_passphrase_is_denied_without_a_key_check() {
    let (prompt, outcome) = presence_with(Some(&[0xff, 0xfe]), future::pending()).await;

    assert_eq!(prompt, passphrase_prompt());
    assert!(matches!(outcome, Err(NoPresence::Refused(PresenceRefusal::Denied(_)))));
}

#[tokio::test]
async fn a_lock_at_the_prompt_cancels_the_change() {
    let (prompt, outcome) = presence_with(None, future::ready(())).await;

    assert_eq!(prompt, passphrase_prompt());
    assert!(matches!(outcome, Err(NoPresence::CancelledByLock)));
}

#[tokio::test]
async fn a_usable_passphrase_goes_on_to_the_key_check() {
    let (_, outcome) = presence_with(Some(b"APPROVAL-typed-91c2"), future::pending()).await;

    assert!(outcome.is_ok());
}
