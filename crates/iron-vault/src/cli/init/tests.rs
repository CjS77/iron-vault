//! The recovery key watch: which advice the CLI gives when `init` ends without a service answer.

use zeroize::Zeroizing;

use super::*;

/// An owner console that answers each prompt with the next of its answers and shows nothing.
struct Scripted(Vec<&'static [u8]>);

impl OwnerConsole for Scripted {
    fn collect(&mut self, _prompt: &Prompt) -> Result<OwnerInput, InputError> {
        Ok(OwnerInput::new(Zeroizing::new(self.0.remove(0).to_vec())))
    }

    fn notice(&mut self, _text: &str) -> Result<(), InputError> {
        Ok(())
    }

    fn reveal(&mut self, _secret: &RevealedSecret) -> Result<(), InputError> {
        Ok(())
    }
}

fn prompt() -> Prompt {
    Prompt {
        label: "Type yes once you have saved the recovery key".to_owned(),
        secret: false,
        switchable: false,
    }
}

fn reveal() -> RevealedSecret {
    RevealedSecret::new(Zeroizing::new(b"AGE-SECRET-KEY-1".to_vec()))
}

#[test]
fn no_advice_before_the_key_is_shown_even_after_a_yes() {
    let mut watch = RecoveryKeyWatch::new(Scripted(vec![b"yes"]));
    watch.collect(&prompt()).unwrap();
    assert_eq!(watch.advice(), None);
}

/// Holds the signal advice, because it is process-wide and each watch that reaches a stage sets it.
#[test]
fn a_shown_key_is_dead_until_yes_is_sent_and_kept_after_it() {
    let _advice = console::hold_signal_advice();
    let mut watch = RecoveryKeyWatch::new(Scripted(vec![b"no", b"Yes", b"yes"]));
    watch.reveal(&reveal()).unwrap();
    watch.collect(&prompt()).unwrap();
    watch.collect(&prompt()).unwrap();
    let dead = watch.advice().unwrap();
    assert!(dead.ends_with(DEAD_RECOVERY_KEY), "{dead}");
    assert_eq!(console::signal_advice(), Some(dead));

    watch.collect(&prompt()).unwrap();
    let unconfirmed = watch.advice().unwrap();
    assert!(unconfirmed.ends_with(UNCONFIRMED_RECOVERY_KEY), "{unconfirmed}");
    assert_eq!(console::signal_advice(), Some(unconfirmed));
}

/// Holds the signal advice, because it is process-wide and each watch that reaches a stage sets it.
#[test]
fn a_rotation_confirms_at_the_vault_passphrase_and_not_at_yes() {
    let _advice = console::hold_signal_advice();
    let secret_prompt = Prompt {
        label: "Vault passphrase".to_owned(),
        secret: true,
        switchable: false,
    };
    let mut watch = RecoveryKeyWatch::rotation(Scripted(vec![b"yes", b"passphrase"]));
    watch.reveal(&reveal()).unwrap();
    watch.collect(&prompt()).unwrap();
    let dead = watch.advice().unwrap();
    assert!(dead.ends_with(DEAD_RECOVERY_KEY), "{dead}");

    watch.collect(&secret_prompt).unwrap();
    let unconfirmed = watch.advice().unwrap();
    assert!(unconfirmed.ends_with(UNCONFIRMED_ROTATED_KEY), "{unconfirmed}");
}
