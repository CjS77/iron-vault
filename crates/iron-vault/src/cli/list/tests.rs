use iron_vault::standing::Standing;
use iron_vault_policy::CredentialKind;
use iron_vault_store::RecordDamage;

use super::*;

fn healthy(name: &str, kind: CredentialKind, origins: &[(&str, u16)]) -> CredentialStanding {
    CredentialStanding {
        name: name.parse().unwrap(),
        standing: Standing::Healthy,
        unavailable_routes: Vec::new(),
        summary: Some(RecordSummary {
            kind,
            origins: origins
                .iter()
                .map(|(host, port)| (host.parse().unwrap(), (*port).try_into().unwrap()))
                .collect(),
        }),
    }
}

fn damaged(name: &str) -> CredentialStanding {
    CredentialStanding {
        name: name.parse().unwrap(),
        standing: Standing::Damaged(RecordDamage::Missing),
        unavailable_routes: Vec::new(),
        summary: None,
    }
}

#[test]
fn each_credential_is_one_line_of_name_kind_origins_and_standing() {
    let credentials = [
        damaged("brave_key"),
        healthy("fx_key", CredentialKind::Static, &[("api.fx.example", 443), ("[::1]", 8443)]),
        healthy("web", CredentialKind::Basic, &[("web.example", 443)]),
    ];

    assert_eq!(
        render(Some(&credentials)),
        "brave_key  unknown  unknown  damaged (missing)\n\
         fx_key  static  api.fx.example:443,[::1]:8443  healthy\n\
         web  basic  web.example:443  healthy\n"
    );
}

#[test]
fn an_open_vault_without_credentials_prints_nothing() {
    assert_eq!(render(Some(&[])), "");
}

#[test]
fn a_locked_vault_prints_the_credentials_as_unknown() {
    assert_eq!(render(None), "credentials: unknown while the vault is locked\n");
}

#[test]
fn the_same_list_prints_the_same_bytes() {
    let credentials = [healthy("fx_key", CredentialKind::Static, &[("api.fx.example", 443)])];
    assert_eq!(render(Some(&credentials)), render(Some(&credentials)));
}
