//! Real PTY checks of stdout selection, progress, and terminal cleanup.
#![cfg(unix)]

mod common;

use common::{
    TempHome, fixture,
    stub::{Reply, StubServer},
};
use std::{
    fs::File,
    io::{Read as _, Write as _},
    os::{
        fd::{AsRawFd as _, FromRawFd as _},
        unix::process::CommandExt as _,
    },
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use unicode_width::UnicodeWidthStr as _;

const RIS: &str = "/ris.ripe.test/dumps/riswhoisdump.IPv4.gz";
const AUTNUM: &str = "/rdap.arin.test/registry/autnum/64498";

struct Session {
    child: Child,
    terminal: File,
    text: String,
    deadline: Instant,
}

impl Session {
    fn start(
        home: &TempHome,
        stub: &StubServer,
        args: &[&str],
        width: u16,
        stdout_tty: bool,
        stderr_tty: bool,
        term: &str,
    ) -> Self {
        let (mut master, mut slave) = (-1, -1);
        let mut size = libc::winsize {
            ws_row: 24,
            ws_col: width,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: openpty initializes both descriptors. The size pointer is valid.
        #[allow(unsafe_code)]
        let result = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &raw mut size,
            )
        };
        assert_eq!(result, 0, "{}", std::io::Error::last_os_error());
        // SAFETY: each newly opened descriptor is transferred to exactly one File.
        #[allow(unsafe_code)]
        let (terminal, slave) = unsafe { (File::from_raw_fd(master), File::from_raw_fd(slave)) };
        let mut command = Command::new(env!("CARGO_BIN_EXE_netf"));
        command
            .args(args)
            .current_dir(home.path())
            .env("HOME", home.path())
            .env("NETF_SOURCE_BASE", stub.base())
            .env("TERM", term)
            .stdin(slave.try_clone().unwrap())
            .stdout(if stdout_tty {
                Stdio::from(slave.try_clone().unwrap())
            } else {
                Stdio::piped()
            })
            .stderr(if stderr_tty {
                Stdio::from(slave.try_clone().unwrap())
            } else {
                Stdio::piped()
            });
        // SAFETY: only async-signal-safe calls run between fork and exec. The
        // child owns a new session, and fd 0 is its PTY slave, already installed.
        #[allow(unsafe_code)]
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() < 0 || libc::ioctl(0, libc::TIOCSCTTY as _, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.spawn().unwrap();
        Self {
            child,
            terminal,
            text: String::new(),
            deadline: Instant::now() + Duration::from_secs(15),
        }
    }

    fn pump(&mut self) -> bool {
        assert!(
            Instant::now() < self.deadline,
            "PTY timed out: {}",
            self.text
        );
        let mut fd = libc::pollfd {
            fd: self.terminal.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: fd points to one valid pollfd for the duration of poll.
        #[allow(unsafe_code)]
        let ready = unsafe { libc::poll(&mut fd, 1, 100) };
        if ready <= 0 {
            return true;
        }
        let mut bytes = [0; 4096];
        match self.terminal.read(&mut bytes) {
            Ok(0) => false,
            Ok(n) => {
                self.text.push_str(&String::from_utf8_lossy(&bytes[..n]));
                true
            }
            // Linux signals the closed slave with EIO. BSD returns EOF.
            Err(error) if error.raw_os_error() == Some(libc::EIO) => false,
            Err(error) => panic!("PTY read: {error}"),
        }
    }

    fn until(&mut self, marker: &str) {
        while !self.text.contains(marker) {
            assert!(self.pump(), "PTY closed before {marker:?}: {}", self.text);
        }
    }

    fn finish(mut self) -> (i32, String, String, String) {
        while self.pump() {}
        let status = self.child.wait().unwrap();
        let mut stdout = String::new();
        let mut stderr = String::new();
        if let Some(mut pipe) = self.child.stdout.take() {
            pipe.read_to_string(&mut stdout).unwrap();
        }
        if let Some(mut pipe) = self.child.stderr.take() {
            pipe.read_to_string(&mut stderr).unwrap();
        }
        (status.code().unwrap(), self.text.clone(), stdout, stderr)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn real_stdout_width_selects_table_or_cards_and_files_keep_plain_output() {
    let (home, stub) = (TempHome::new(), StubServer::start());
    for width in [45, 80, 120, 160] {
        let (code, terminal, _, stderr) = Session::start(
            &home,
            &stub,
            &["as.asn: 64498"],
            width,
            true,
            false,
            "xterm",
        )
        .finish();
        assert_eq!(code, 0, "{stderr}");
        assert!(
            terminal
                .lines()
                .all(|line| line.trim_end_matches('\r').width() <= usize::from(width)),
            "{terminal}"
        );
        assert_eq!(
            terminal.starts_with("BGP route:"),
            width == 45,
            "{terminal}"
        );
        assert!(terminal.contains("Documentation Net Inc"), "{terminal}");
        assert!(stderr.is_empty(), "{stderr}");
    }
    let (code, terminal, _, _) = Session::start(
        &home,
        &stub,
        &["-f", "answer.txt", "as.asn: 64498"],
        45,
        true,
        false,
        "xterm",
    )
    .finish();
    assert_eq!(code, 0);
    assert!(terminal.is_empty());
    let saved = std::fs::read_to_string(home.path().join("answer.txt")).unwrap();
    assert!(saved.contains("AS64498 DOCNET"));
    assert!(!saved.contains("BGP route"));
}

#[test]
fn slow_stages_tick_on_stderr_while_stdout_is_a_pipe() {
    let (home, stub) = (TempHome::new(), StubServer::start());
    stub.on(
        RIS,
        Reply::ok(fixture(&RIS[1..])).delay(Duration::from_millis(750)),
    );
    stub.on(
        AUTNUM,
        Reply::ok(fixture(&AUTNUM[1..])).delay(Duration::from_millis(1200)),
    );
    let mut session = Session::start(&home, &stub, &["as.asn: 64498"], 45, false, true, "xterm");
    session.until("loading network data");
    session.until("registry records");
    let (code, terminal, stdout, _) = session.finish();
    assert_eq!(code, 0, "{terminal}");
    assert!(terminal.contains("0/1 networks"), "{terminal}");
    for line in terminal.split("\r\x1b[K").filter(|line| !line.is_empty()) {
        assert!(line.width() <= 45, "{line}");
    }
    assert!(terminal.ends_with("\r\x1b[K"), "{terminal:?}");
    assert!(stdout.contains("AS64498 DOCNET"));
    assert!(!stdout.contains("elapsed"));
    assert_eq!(stub.count(RIS), 1);
    assert_eq!(stub.count(AUTNUM), 1);
}

#[test]
fn dumb_terminal_and_nonterminal_progress_have_no_redraw_codes() {
    let (home, stub) = (TempHome::new(), StubServer::start());
    stub.always(
        RIS,
        Reply::ok(fixture(&RIS[1..])).delay(Duration::from_millis(1200)),
    );
    let (code, terminal, _, _) = Session::start(
        &home,
        &stub,
        &["--no-cache", "as.asn: 64498"],
        120,
        false,
        true,
        "dumb",
    )
    .finish();
    assert_eq!(code, 0);
    // ONLCR belongs to the PTY, not the program. Only complete lines are sent.
    // Without a cache, datasets stream during the matching stage.
    let normalized = terminal.replace("\r\n", "\n");
    assert!(!normalized.contains(['\r', '\u{1b}']), "{terminal:?}");
    assert_eq!(
        normalized.matches("finding matches").count(),
        1,
        "{normalized}"
    );
    let (code, _, _, stderr) = Session::start(
        &home,
        &stub,
        &["--no-cache", "as.asn: 64498"],
        120,
        true,
        false,
        "xterm",
    )
    .finish();
    assert_eq!(code, 0);
    assert!(stderr.is_empty(), "{stderr}");
}

#[test]
fn failure_and_ctrl_c_clear_progress_and_keep_the_previous_file() {
    let (home, stub) = (TempHome::new(), StubServer::start());
    let path = home.path().join("answer.txt");
    std::fs::write(&path, "previous\n").unwrap();
    stub.on(RIS, Reply::status(404).delay(Duration::from_millis(750)));
    let (code, terminal, stdout, _) = Session::start(
        &home,
        &stub,
        &["-f", "answer.txt", "as.asn: 64498"],
        120,
        false,
        true,
        "xterm",
    )
    .finish();
    assert_eq!(code, 1, "{terminal}");
    assert!(terminal.contains("loading network data"));
    assert!(terminal.contains("\r\x1b[Knetf:"), "{terminal:?}");
    assert!(stdout.is_empty());
    assert_eq!(std::fs::read_to_string(&path).unwrap(), "previous\n");
    stub.on(RIS, Reply::ok(fixture(&RIS[1..])).stall());
    let mut session = Session::start(
        &home,
        &stub,
        &["-f", "answer.txt", "as.asn: 64498"],
        120,
        false,
        true,
        "xterm",
    );
    session.until("loading network data");
    // SAFETY: this PID belongs to the live child created by this test.
    #[allow(unsafe_code)]
    let sent = unsafe { libc::kill(session.child.id() as libc::pid_t, libc::SIGINT) };
    assert_eq!(sent, 0);
    let (code, terminal, stdout, _) = session.finish();
    assert_eq!(code, 130, "{terminal}");
    assert!(
        terminal.contains("\r\x1b[Knetf: interrupted"),
        "{terminal:?}"
    );
    assert!(stdout.is_empty());
    assert_eq!(std::fs::read_to_string(path).unwrap(), "previous\n");
}

#[test]
fn progress_is_cleared_before_the_tree_opens() {
    let (home, stub) = (TempHome::new(), StubServer::start());
    stub.on(
        RIS,
        Reply::ok(fixture(&RIS[1..])).delay(Duration::from_millis(750)),
    );
    let mut session = Session::start(
        &home,
        &stub,
        &["-i", "as.asn: 64498"],
        80,
        true,
        true,
        "xterm",
    );
    session.until("\x1b[?1049h");
    session.terminal.write_all(b"q").unwrap();
    let (code, terminal, _, _) = session.finish();
    assert_eq!(code, 0, "{terminal}");
    let (before, tree) = terminal.split_once("\x1b[?1049h").unwrap();
    assert!(before.contains("loading network data"));
    assert!(before.ends_with("\r\x1b[K"), "{before:?}");
    assert!(!tree.contains("elapsed"), "{tree}");
}

#[test]
fn explicit_formats_and_completion_work_with_separate_terminal_streams() {
    let (home, stub) = (TempHome::new(), StubServer::start());
    let (code, terminal, _, stderr) = Session::start(
        &home,
        &stub,
        &[
            "--columns",
            "route,as.asn",
            "--format",
            "table",
            "as.asn: 64498",
        ],
        45,
        true,
        false,
        "xterm",
    )
    .finish();
    assert_eq!(code, 0, "{stderr}");
    assert!(terminal.contains("BGP route      Origin AS"), "{terminal}");
    assert!(
        terminal.contains("1 record · 1 route · 1 origin AS"),
        "{terminal}"
    );
    assert!(!terminal.contains("Registry network:"), "{terminal}");
    let (code, terminal, stdout, _) = Session::start(
        &home,
        &stub,
        &["--ipset", "-f", "out.txt", "ip: 192.0.2.1"],
        45,
        false,
        true,
        "xterm",
    )
    .finish();
    assert_eq!(code, 0);
    assert!(stdout.is_empty());
    assert!(
        terminal.contains("netf: saved 1 CIDR to out.txt (IPv4)."),
        "{terminal}"
    );
}
