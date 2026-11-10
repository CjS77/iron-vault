use super::adapter::visible_pid;
use super::*;

#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_socket_pair_reports_this_process() {
    let (ours, _theirs) = tokio::net::UnixStream::pair().unwrap();
    let identity = peer_identity(&ours).unwrap();
    assert_eq!(identity.uid(), rustix::process::getuid().as_raw());
    assert_eq!(identity.gid(), rustix::process::getgid().as_raw());
    assert_eq!(identity.pid(), Some(std::process::id()));
}

#[test]
fn a_pid_from_another_pid_namespace_is_absent_and_a_negative_one_is_an_error() {
    assert_eq!(visible_pid(0).unwrap(), None);
    assert_eq!(visible_pid(4242).unwrap(), Some(4242));
    assert_eq!(visible_pid(-1).unwrap_err().kind(), std::io::ErrorKind::InvalidData);
}

#[cfg(not(target_os = "linux"))]
#[tokio::test]
async fn other_platforms_refuse_every_connection() {
    let (ours, _theirs) = tokio::net::UnixStream::pair().unwrap();
    assert_eq!(peer_identity(&ours).unwrap_err().kind(), std::io::ErrorKind::Unsupported);
}
