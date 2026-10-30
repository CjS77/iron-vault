use std::cell::RefCell;
use std::io::{self, Cursor, Read, Write};
use std::rc::Rc;

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
fn input_errors_name_no_typed_byte() {
    let marker = "MARKER-secret-5d1c9e";
    let over = marker.repeat(MAX_BODY_LEN / marker.len() + 1);
    let error = line(over.as_bytes()).unwrap_err();
    assert!(!error.to_string().contains(marker), "{error}");
    assert!(!format!("{error:?}").contains(marker), "{error:?}");
}
