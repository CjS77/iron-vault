//! Owner presence's answers that end before the approver key is checked, driven through an exchange whose CLI end the
//! test holds: input that cannot be the passphrase is refused as a wrong one, and a `lock` cancels the change.

use std::future::{self, Future};

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

/// Runs the presence prompt with `lock_requested`; the CLI end answers with `answer`, or never answers when it is `None`.
async fn presence_with(
    answer: Option<&[u8]>,
    lock_requested: impl Future<Output = ()>,
) -> (Prompt, Result<ApprovalPassphrase, NoPresence>) {
    let (service, mut cli) = UnixStream::pair().unwrap();
    let mut exchange = Exchange::new(service, Limits::default());
    let answered = presence_passphrase(&mut exchange, lock_requested);
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

fn passphrase_prompt() -> Prompt {
    Prompt {
        label: PASSPHRASE_PROMPT.to_owned(),
        secret: true,
    }
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
