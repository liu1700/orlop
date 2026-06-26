//! Integration tests for orlop mount daemonization. These spawn the real
//! `orlop` binary as a subprocess but skip lease/mount via the
//! `ORLOP_DAEMON_TEST_SKIP_MOUNT` env var, so the tests don't need
//! FUSE/NFS permissions or a control plane.

use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

fn orlop_bin() -> std::path::PathBuf {
    let p = std::path::PathBuf::from(env!("CARGO_BIN_EXE_orlop"));
    assert!(p.exists(), "orlop binary missing at {}", p.display());
    p
}

fn ephemeral_home() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "orlop-daemon-it-{}-{}",
        std::process::id(),
        rand::random::<u32>()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn pid_alive(pid: u32) -> bool {
    orlop::daemon::pid_alive(pid)
}

fn read_pid_file(home: &std::path::Path) -> Option<u32> {
    orlop::daemon::read_pid_file(&home.join(".cache/orlop/mount.pid"))
        .ok()
        .flatten()
}

fn write_minimal_config(home: &std::path::Path) -> std::path::PathBuf {
    let cfg = home.join("config.yaml");
    let body = format!(
        "hosted:\n  control_plane_url: \"http://127.0.0.1:1\"\nmountpoint: {}\n",
        home.join("mnt").display()
    );
    std::fs::write(&cfg, body).unwrap();
    std::fs::create_dir_all(home.join("mnt")).unwrap();
    cfg
}

fn spawn_mount(
    home: &std::path::Path,
    cfg: &std::path::Path,
    mountpoint: &std::path::Path,
) -> std::process::Output {
    Command::new(orlop_bin())
        .env("HOME", home)
        .env("ORLOP_DAEMON_TEST_SKIP_MOUNT", "1")
        .args([
            "--config",
            cfg.to_str().unwrap(),
            "mount",
            "--mountpoint",
            mountpoint.to_str().unwrap(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn orlop mount")
}

#[test]
fn daemon_writes_pid_and_exits_parent_cleanly() {
    let home = ephemeral_home();
    let cfg = write_minimal_config(&home);
    let mp = home.join("mnt");

    let out = spawn_mount(&home, &cfg, &mp);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let pid = read_pid_file(&home).expect("PID file present");
    assert!(pid_alive(pid), "daemon at PID {pid} should be alive");

    // Cleanup
    orlop::daemon::send_signal(pid, libc::SIGTERM);
    thread::sleep(Duration::from_millis(500));
    assert!(
        !pid_alive(pid),
        "daemon should have exited after SIGTERM"
    );

    let _ = std::fs::remove_dir_all(home);
}

#[test]
fn unmount_signals_daemon() {
    let home = ephemeral_home();
    let cfg = write_minimal_config(&home);
    let mp = home.join("mnt");

    let _ = spawn_mount(&home, &cfg, &mp);
    let pid = read_pid_file(&home).expect("daemon PID written");
    assert!(pid_alive(pid));

    let out = Command::new(orlop_bin())
        .env("HOME", &home)
        .env("ORLOP_DAEMON_TEST_SKIP_MOUNT", "1")
        .args([
            "--config",
            cfg.to_str().unwrap(),
            "unmount",
            mp.to_str().unwrap(),
        ])
        .output()
        .expect("spawn orlop unmount");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Daemon should be gone, PID file removed.
    let deadline = Instant::now() + Duration::from_secs(2);
    while pid_alive(pid) && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(50));
    }
    assert!(!pid_alive(pid), "daemon still alive after `orlop unmount`");
    assert!(read_pid_file(&home).is_none(), "PID file not cleaned up");

    let _ = std::fs::remove_dir_all(home);
}
