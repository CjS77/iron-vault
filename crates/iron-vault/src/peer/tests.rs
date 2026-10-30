use super::*;

#[cfg(target_os = "linux")]
#[test]
fn a_socket_pair_reports_this_process() {
    let (ours, _theirs) = std::os::unix::net::UnixStream::pair().unwrap();
    let identity = peer_identity(&ours).unwrap();
    assert_eq!(identity.uid(), rustix::process::getuid().as_raw());
    assert_eq!(identity.gid(), rustix::process::getgid().as_raw());
    assert_eq!(identity.pid(), std::process::id());
}

#[cfg(not(target_os = "linux"))]
#[test]
fn other_platforms_refuse_every_connection() {
    let (ours, _theirs) = std::os::unix::net::UnixStream::pair().unwrap();
    assert_eq!(peer_identity(&ours).unwrap_err().kind(), std::io::ErrorKind::Unsupported);
}
