use super::*;

const SERVICE: u32 = 997;
const OTHER: u32 = 1000;

fn peer(uid: u32) -> PeerIdentity {
    PeerIdentity { uid, gid: 50, pid: 4242 }
}

fn accepts(profile: DeploymentProfile, service_uid: u32, uid: u32) -> Result<AdminPrincipal, NotAnAdminPrincipal> {
    AdminPrincipals::new(profile, service_uid).accepts(peer(uid))
}

#[test]
fn protected_accepts_root_and_the_service_account() {
    [0, SERVICE].into_iter().for_each(|uid| {
        let principal = accepts(DeploymentProfile::Protected, SERVICE, uid).unwrap();
        assert_eq!(principal.peer(), peer(uid));
    });
}

#[test]
fn protected_refuses_any_other_account_and_points_at_sudo() {
    let refused = accepts(DeploymentProfile::Protected, SERVICE, OTHER).unwrap_err();
    assert_eq!(refused, NotAnAdminPrincipal::Protected { uid: OTHER });
    assert_eq!(refused.uid(), OTHER);
    let message = refused.to_string();
    assert!(message.contains("1000"), "{message}");
    assert!(message.contains("sudo"), "{message}");
}

#[test]
fn development_accepts_only_the_invoking_user() {
    assert_eq!(accepts(DeploymentProfile::Development, OTHER, OTHER).unwrap().peer(), peer(OTHER));
    [0, SERVICE].into_iter().for_each(|uid| {
        assert_eq!(
            accepts(DeploymentProfile::Development, OTHER, uid),
            Err(NotAnAdminPrincipal::Development { uid })
        );
    });
}

#[test]
fn development_refuses_root_even_as_the_service_account() {
    assert_eq!(
        accepts(DeploymentProfile::Development, 0, 0),
        Err(NotAnAdminPrincipal::Development { uid: 0 })
    );
    assert!(accepts(DeploymentProfile::Development, 0, OTHER).is_err());
}

#[test]
fn only_the_uid_decides() {
    let principals = AdminPrincipals::new(DeploymentProfile::Protected, SERVICE);
    let root_gid_peer = PeerIdentity {
        uid: OTHER,
        gid: 0,
        pid: 1,
    };
    assert!(principals.accepts(root_gid_peer).is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn a_socket_pair_reports_this_process() {
    let (ours, _theirs) = std::os::unix::net::UnixStream::pair().unwrap();
    let identity = peer_identity(&ours).unwrap();
    assert_eq!(identity.uid, rustix::process::getuid().as_raw());
    assert_eq!(identity.gid, rustix::process::getgid().as_raw());
    assert_eq!(identity.pid, std::process::id());
}

#[cfg(not(target_os = "linux"))]
#[test]
fn other_platforms_refuse_every_connection() {
    let (ours, _theirs) = std::os::unix::net::UnixStream::pair().unwrap();
    assert_eq!(peer_identity(&ours).unwrap_err().kind(), std::io::ErrorKind::Unsupported);
}
