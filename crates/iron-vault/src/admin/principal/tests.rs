use super::*;
use crate::deployment::DEFAULT_OVERFLOW_UID;

const SERVICE: u32 = 997;
const OTHER: u32 = 1000;

fn peer(uid: u32) -> PeerIdentity {
    PeerIdentity::for_test(uid, 50, 4242)
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
fn container_accepts_only_root() {
    assert_eq!(accepts(DeploymentProfile::Container, SERVICE, 0).unwrap().peer(), peer(0));
}

#[test]
fn container_refuses_the_service_account_a_login_and_the_overflow_uid_and_points_at_host_sudo() {
    [SERVICE, OTHER, DEFAULT_OVERFLOW_UID].into_iter().for_each(|uid| {
        let refused = accepts(DeploymentProfile::Container, SERVICE, uid).unwrap_err();
        assert_eq!(refused, NotAnAdminPrincipal::Container { uid });
        assert_eq!(refused.uid(), uid);
        let message = refused.to_string();
        assert!(message.contains("host") && message.contains("sudo"), "{message}");
    });
}

#[test]
fn only_the_uid_decides() {
    let principals = AdminPrincipals::new(DeploymentProfile::Protected, SERVICE);
    let root_gid_peer = PeerIdentity::for_test(OTHER, 0, 1);
    assert!(principals.accepts(root_gid_peer).is_err());
}
