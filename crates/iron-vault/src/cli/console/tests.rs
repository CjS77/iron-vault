use std::cell::RefCell;
use std::io::{self, Cursor, Read, Write};
use std::rc::Rc;

use qrcode::render::unicode::Dense1x2;
use qrcode::{EcLevel, QrCode};

use super::*;

fn line(input: &[u8]) -> Result<Vec<u8>, InputError> {
    read_line(&mut Cursor::new(input)).map(|line| line.to_vec())
}

fn prompt(label: &str, secret: bool) -> Prompt {
    Prompt {
        label: label.to_owned(),
        secret,
    }
}

#[test]
fn one_trailing_newline_and_the_carriage_return_before_it_are_stripped() {
    [
        (&b"value\n"[..], &b"value"[..]),
        (b"value\r\n", b"value"),
        (b"value\r\r\n", b"value\r"),
        (b"value\n\n", b"value"),
        (b"\n", b""),
        (b"\r\n", b""),
        (b"value\r", b"value\r"),
        (b"  spaced  \n", b"  spaced  "),
    ]
    .into_iter()
    .for_each(|(input, value)| assert_eq!(line(input).unwrap(), value, "{input:?}"));
}

#[test]
fn a_last_line_without_a_newline_is_a_value() {
    assert_eq!(line(b"value").unwrap(), b"value");
}

#[test]
fn input_that_ends_before_any_byte_is_no_value() {
    assert!(matches!(line(b""), Err(InputError::NoInput)));
}

#[test]
fn consecutive_reads_take_consecutive_lines_and_nothing_more() {
    let mut input = Cursor::new(&b"first\nsecond\r\nthird"[..]);
    assert_eq!(*read_line(&mut input).unwrap(), b"first");
    assert_eq!(*read_line(&mut input).unwrap(), b"second");
    assert_eq!(input.position(), 14, "the third line is left unread");
    assert_eq!(*read_line(&mut input).unwrap(), b"third");
    assert!(matches!(read_line(&mut input), Err(InputError::NoInput)));
}

#[test]
fn the_longest_value_fits_and_one_byte_more_is_refused() {
    let longest = vec![b'a'; MAX_BODY_LEN];
    [&b"\n"[..], b"\r\n", b""].into_iter().for_each(|ending| {
        assert_eq!(line(&[&longest[..], ending].concat()).unwrap().len(), MAX_BODY_LEN, "{ending:?}");
        let over = [&longest[..], b"a", ending].concat();
        assert!(matches!(line(&over), Err(InputError::TooLong)), "{ending:?}");
    });
}

#[test]
fn an_overlong_line_is_refused_without_reading_it_all() {
    let mut input = Cursor::new(vec![b'a'; 3 * MAX_BODY_LEN]);
    assert!(matches!(read_line(&mut input), Err(InputError::TooLong)));
    assert_eq!(input.position(), u64::try_from(LINE_CAPACITY).unwrap());
}

/// A reader that fails every read.
struct Unplugged;

impl Read for Unplugged {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("unplugged"))
    }
}

#[test]
fn a_read_failure_is_reported() {
    assert!(matches!(read_line(&mut Unplugged), Err(InputError::Read(_))));
}

#[test]
fn a_piped_console_reads_one_line_per_prompt() {
    let mut console = Piped::new(&b"s3cret\nplain\n"[..], false);
    let secret = console.collect(&prompt("Secret", true)).unwrap();
    let plain = console.collect(&prompt("Plain", false)).unwrap();
    assert_eq!(secret.expose_secret(), b"s3cret");
    assert_eq!(plain.expose_secret(), b"plain");
    assert!(matches!(console.collect(&prompt("More", false)), Err(InputError::NoInput)));
}

/// What happened to a fake terminal, in order.
type Events = Rc<RefCell<Vec<&'static str>>>;

/// Echo control that records each switch, and fails to turn echo off when told to.
struct FakeEcho {
    events: Events,
    refuse: bool,
}

impl EchoControl for FakeEcho {
    fn echo_off(&self) -> io::Result<()> {
        if self.refuse {
            return Err(io::Error::other("not a terminal"));
        }
        self.events.borrow_mut().push("echo off");
        Ok(())
    }

    fn restore(&self) -> io::Result<()> {
        self.events.borrow_mut().push("restore");
        Ok(())
    }
}

/// A terminal that records reads, collects what is written, and fails reads when it has no input.
struct FakeTty {
    events: Events,
    input: Option<Cursor<Vec<u8>>>,
    shown: Vec<u8>,
}

impl Read for FakeTty {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.events.borrow_mut().push("read");
        match &mut self.input {
            Some(input) => input.read(buf),
            None => Err(io::Error::other("hung up")),
        }
    }
}

impl Write for FakeTty {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.shown.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn terminal(input: Option<&[u8]>, refuse_echo_off: bool) -> (Terminal<FakeTty, FakeEcho>, Events) {
    let events = Events::default();
    let tty = FakeTty {
        events: Rc::clone(&events),
        input: input.map(|bytes| Cursor::new(bytes.to_vec())),
        shown: Vec::new(),
    };
    let echo = FakeEcho {
        events: Rc::clone(&events),
        refuse: refuse_echo_off,
    };
    (Terminal::new(tty, echo), events)
}

/// The events with consecutive reads merged, since a line is read one byte at a time.
fn steps(events: &Events) -> Vec<&'static str> {
    let mut steps = events.borrow().clone();
    steps.dedup();
    steps
}

#[test]
fn a_secret_is_read_with_echo_off_and_the_terminal_restored() {
    let (mut console, events) = terminal(Some(b"s3cret\n"), false);
    let input = console.collect(&prompt("Passphrase", true)).unwrap();
    assert_eq!(input.expose_secret(), b"s3cret");
    assert_eq!(steps(&events), ["echo off", "read", "restore"]);
    assert_eq!(console.tty.shown, b"Passphrase: ");
}

#[test]
fn a_failed_secret_read_still_restores_the_terminal() {
    let (mut console, events) = terminal(None, false);
    assert!(matches!(console.collect(&prompt("Passphrase", true)), Err(InputError::Read(_))));
    assert_eq!(steps(&events), ["echo off", "read", "restore"]);
}

#[test]
fn a_secret_that_ends_early_or_runs_long_still_restores_the_terminal() {
    let too_long = vec![b'a'; LINE_CAPACITY];
    [(&b""[..], "NoInput"), (&too_long[..], "TooLong")]
        .into_iter()
        .for_each(|(input, expected)| {
            let (mut console, events) = terminal(Some(input), false);
            let error = console.collect(&prompt("Passphrase", true)).unwrap_err();
            assert!(format!("{error:?}").starts_with(expected), "{error:?}");
            assert_eq!(steps(&events), ["echo off", "read", "restore"]);
        });
}

#[test]
fn a_terminal_line_just_under_the_terminal_limit_is_a_value() {
    let value = vec![b'a'; TERMINAL_LINE_LIMIT - 2];
    let (mut console, _) = terminal(Some(&[&value[..], b"\n"].concat()), false);
    assert_eq!(console.collect(&prompt("Passphrase", true)).unwrap().expose_secret(), value);
}

#[test]
fn a_terminal_line_that_may_have_been_cut_short_is_refused_and_the_terminal_restored() {
    let marker = b"MARKER-secret-5d1c9e";
    let long = marker.repeat(TERMINAL_LINE_LIMIT / marker.len() + 1);
    // Counted with the line ending: lines of exactly the limit, ended by `\n`, by `\r\n` and by nothing (Ctrl-D), and
    // a line of 4095 bytes and its `\n`, which is what a line Linux cut short arrives as.
    [
        (TERMINAL_LINE_LIMIT - 1, &b"\n"[..]),
        (TERMINAL_LINE_LIMIT - 2, b"\r\n"),
        (TERMINAL_LINE_LIMIT, b""),
        (TERMINAL_LINE_LIMIT, b"\n"),
    ]
    .into_iter()
    .map(|(len, ending)| [&long[..len], ending].concat())
    .for_each(|input| {
        let (mut console, events) = terminal(Some(&input), false);
        let error = console.collect(&prompt("Passphrase", true)).unwrap_err();
        assert!(matches!(error, InputError::TerminalLineTooLong), "{} bytes: {error:?}", input.len());
        assert_eq!(steps(&events), ["echo off", "read", "restore"]);
        let message = error.to_string();
        assert!(message.contains("pipe longer values through stdin"), "{message}");
        assert!(!message.contains("MARKER"), "{message}");
    });
}

#[test]
fn a_secret_is_not_read_when_echo_cannot_be_turned_off() {
    let (mut console, events) = terminal(Some(b"s3cret\n"), true);
    assert!(matches!(console.collect(&prompt("Passphrase", true)), Err(InputError::Terminal(_))));
    assert!(events.borrow().is_empty(), "{:?}", events.borrow());
}

#[test]
fn a_plain_value_is_read_with_echo_on() {
    let (mut console, events) = terminal(Some(b"plain\n"), false);
    assert_eq!(console.collect(&prompt("Name", false)).unwrap().expose_secret(), b"plain");
    assert_eq!(steps(&events), ["read"]);
}

#[test]
fn a_label_cannot_send_control_characters_to_the_terminal() {
    let (mut console, _) = terminal(Some(b"\n"), false);
    console.collect(&prompt("Pass\x1b[2Jphrase\r\n", false)).unwrap();
    assert_eq!(console.tty.shown, b"Pass[2Jphrase: ");
}

#[test]
fn a_notice_keeps_its_newlines_and_loses_every_other_control_character() {
    let (mut console, events) = terminal(None, false);
    console.notice("route \x1b[2Jfx\r\n").unwrap();
    console.notice("ends here\n").unwrap();
    assert_eq!(console.tty.shown, b"route [2Jfx\nends here\n");
    assert!(steps(&events).is_empty(), "a notice reads nothing");
}

#[test]
fn input_errors_name_no_typed_byte() {
    let marker = "MARKER-secret-5d1c9e";
    let over = marker.repeat(MAX_BODY_LEN / marker.len() + 1);
    let error = line(over.as_bytes()).unwrap_err();
    assert!(!error.to_string().contains(marker), "{error}");
    assert!(!format!("{error:?}").contains(marker), "{error:?}");
}

const KEY: &[u8] = b"AGE-SECRET-KEY-1MARKER5D1C9E";

fn revealed(bytes: &[u8]) -> RevealedSecret {
    RevealedSecret::new(Zeroizing::new(bytes.to_vec()))
}

/// Bytes a fake terminal or a fake stderr was given, shared with the test that reads them back.
#[derive(Clone, Default)]
struct Sink(Rc<RefCell<Vec<u8>>>);

impl Write for Sink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Sink {
    fn bytes(&self) -> Vec<u8> {
        self.0.borrow().clone()
    }
}

/// A piped console with fake stderr and terminal: it opens the terminal only for a reveal.
type FakePiped = Piped<&'static [u8], Sink, Box<dyn FnMut() -> io::Result<Sink>>>;

/// A piped console whose notices go to the returned stderr and whose reveals go to the returned terminal, or fail to
/// open one when `has_tty` is false.
fn piped(has_tty: bool) -> (FakePiped, Sink, Sink) {
    let (stderr, tty) = (Sink::default(), Sink::default());
    let tty_handle = tty.clone();
    let console = Piped {
        input: &b""[..],
        show_labels: false,
        notices: stderr.clone(),
        open_tty: Box::new(move || {
            if has_tty {
                Ok(tty_handle.clone())
            } else {
                Err(io::Error::from(io::ErrorKind::NotFound))
            }
        }) as Box<dyn FnMut() -> io::Result<Sink>>,
    };
    (console, stderr, tty)
}

#[test]
fn a_terminal_shows_a_reveal_once_then_a_newline_and_reads_nothing() {
    let (mut console, events) = terminal(None, false);
    console.reveal(&revealed(KEY)).unwrap();
    assert_eq!(console.tty.shown, [KEY, b"\n", &qr_of(KEY)].concat());
    assert!(steps(&events).is_empty(), "a reveal reads nothing");
}

#[test]
fn a_piped_console_shows_a_reveal_on_the_terminal_and_never_on_stderr() {
    let (mut console, stderr, tty) = piped(true);
    console.notice("save this key\n").unwrap();
    console.reveal(&revealed(KEY)).unwrap();
    assert_eq!(
        tty.bytes(),
        [KEY, b"\n", &qr_of(KEY)].concat(),
        "the text, then its QR code, on the terminal"
    );
    assert_eq!(stderr.bytes(), b"save this key\n", "the notice goes to stderr, the value does not");
}

#[test]
fn a_piped_console_without_a_terminal_shows_nothing_and_cancels() {
    let (mut console, stderr, _) = piped(false);
    let error = console.reveal(&revealed(KEY)).unwrap_err();
    assert!(matches!(error, InputError::NoTerminal(_)), "{error:?}");
    assert!(stderr.bytes().is_empty());
    assert!(error.to_string().contains("shown only on a terminal"), "{error}");
}

#[test]
fn a_reveal_with_a_byte_outside_printable_ascii_is_refused_unshown() {
    [
        &b"KEY\x1b[2J"[..],
        b"KEY\n",
        b"KEY\r",
        b"KEY\x7f",
        b"KEY\0",
        "KEYé".as_bytes(),
        b"KEY\x9b",
    ]
    .into_iter()
    .map(|bad| [KEY, bad].concat())
    .for_each(|value| {
        let (mut terminal, _) = terminal(None, false);
        // Without a terminal, so a value checked only after opening one would fail as `NoTerminal` instead.
        let (mut piped, stderr, tty) = piped(false);
        [terminal.reveal(&revealed(&value)), piped.reveal(&revealed(&value))]
            .into_iter()
            .for_each(|result| {
                let error = result.unwrap_err();
                assert!(matches!(error, InputError::UnprintableReveal), "{value:?}: {error:?}");
                assert!(!format!("{error} {error:?}").contains("MARKER"), "{error:?}");
            });
        assert!(terminal.tty.shown.is_empty() && tty.bytes().is_empty() && stderr.bytes().is_empty());
    });
}

#[test]
fn every_printable_ascii_byte_and_the_space_can_be_revealed() {
    let printable: Vec<u8> = (b' '..=b'~').collect();
    let (mut console, _) = terminal(None, false);
    console.reveal(&revealed(&printable)).unwrap();
    assert_eq!(console.tty.shown, [&printable[..], b"\n", &qr_of(&printable)].concat());
}

/// An obviously fake 74-character key of the recovery key's shape.
const SAMPLE: &[u8] = b"AGE-SECRET-KEY-1FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFA";

/// What a reveal draws after the text: the library's own rendering, newline-ended.
fn qr_of(value: &[u8]) -> Vec<u8> {
    let code = QrCode::with_error_correction_level(value, EcLevel::M).unwrap();
    let mut drawing = code.render::<Dense1x2>().quiet_zone(true).build().into_bytes();
    drawing.push(b'\n');
    drawing
}

#[test]
fn the_sample_key_is_74_characters() {
    assert_eq!(SAMPLE.len(), 74);
}

#[test]
fn a_reveal_draws_a_small_square_qr_code_that_does_not_change() {
    let (mut console, _) = terminal(None, false);
    console.reveal(&revealed(SAMPLE)).unwrap();
    let shown = String::from_utf8(console.tty.shown.clone()).unwrap();
    let drawing = shown.strip_prefix(&format!("{}\n", String::from_utf8_lossy(SAMPLE))).unwrap();
    let widths: Vec<usize> = drawing.lines().map(|line| line.chars().count()).collect();
    assert!(
        widths.windows(2).all(|pair| pair[0] == pair[1]),
        "every line is as wide as the first: {widths:?}"
    );
    // Version 5 is 37 modules and a quiet zone of 4 on each side: at most 45 columns.
    assert!(widths.first().is_some_and(|width| *width <= 45), "at most version 5: {widths:?}");
    assert_eq!(drawing, include_str!("recovery_qr.snapshot.txt"));
}

#[test]
fn a_reveal_too_long_for_a_qr_code_still_shows_its_text() {
    let long = vec![b'A'; 4000];
    let (mut console, _) = terminal(None, false);
    console.reveal(&revealed(&long)).unwrap();
    assert_eq!(console.tty.shown, [&long[..], b"\n", b"(too long for a QR code)\n"].concat());
}

#[test]
fn a_piped_reveal_puts_no_qr_code_on_the_notices_sink() {
    let (mut console, stderr, tty) = piped(true);
    console.reveal(&revealed(SAMPLE)).unwrap();
    assert!(stderr.bytes().is_empty(), "nothing but the terminal is written");
    assert!(tty.bytes().len() > SAMPLE.len() + 1, "the QR code follows the text on the terminal");
}
