//! `iron-vault import` run as a child process: on a pseudo-terminal that is its controlling terminal, where it shows the
//! recovery key, with the owner's answers typed into its stdin.

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::{Command, Stdio};

/// What `iron-vault import` did when the CLI ran as a child process.
#[derive(Debug)]
pub struct CliRan {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

/// A pseudo-terminal the CLI gets as its controlling terminal, which is where it shows the recovery key. The test keeps
/// the slave open until the CLI is done, and drains the master so a long reveal cannot block the CLI.
struct Terminal {
    slave: fs::File,
    path: String,
}

impl Terminal {
    fn open() -> Self {
        use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
        let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC).unwrap();
        grantpt(&master).unwrap();
        unlockpt(&master).unwrap();
        let path = ptsname(&master, Vec::new()).unwrap().into_string().unwrap();
        let slave = fs::File::options()
            .read(true)
            .write(true)
            .custom_flags(rustix::fs::OFlags::NOCTTY.bits() as i32)
            .open(&path)
            .unwrap();
        let mut master = fs::File::from(master);
        std::thread::spawn(move || while matches!(master.read(&mut [0; 1024]), Ok(1..)) {});
        Self { slave, path }
    }
}

/// A running `iron-vault import <bundle>` whose stdin is a pipe the test types the owner's answers into, in `cwd`.
pub struct CliImport {
    child: std::process::Child,
    _terminal: Terminal,
}

impl CliImport {
    /// `setsid` and a shell make the pseudo-terminal the CLI's controlling terminal, and `exec` puts the CLI in the shell's place.
    pub fn start(socket: &Path, bundle: &Path, cwd: &Path) -> Self {
        let terminal = Terminal::open();
        let child = Command::new("setsid")
            .args(["sh", "-c", r#"exec 9<"$IV_PTS" && exec 9<&- && exec "$@""#, "sh"])
            .arg(env!("CARGO_BIN_EXE_iron-vault"))
            .arg("import")
            .arg(bundle)
            .arg("--admin-socket")
            .arg(socket)
            .env("IV_PTS", &terminal.path)
            .current_dir(cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let _ = &terminal.slave;
        Self {
            child,
            _terminal: terminal,
        }
    }

    /// Types `answers`, one line each, then closes stdin and waits for the CLI to end.
    pub fn finish(mut self, answers: &[&[u8]]) -> CliRan {
        let mut stdin = self.child.stdin.take().unwrap();
        answers.iter().for_each(|answer| {
            let _ = stdin.write_all(answer).and_then(|()| stdin.write_all(b"\n"));
        });
        drop(stdin);
        let output = self.child.wait_with_output().unwrap();
        CliRan {
            code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    }
}
