use super::*;

const SERVICE: u32 = 997;
const USER: u32 = 1000;
const STRANGER: u32 = 1001;
const STAFF: u32 = 50;

const SERVICE_OWNER: ExpectedOwner = ExpectedOwner { uid: SERVICE };
const USER_OWNER: ExpectedOwner = ExpectedOwner { uid: USER };

fn entry(path: &str, uid: u32, mode: u32, kind: ComponentKind) -> PathComponent {
    PathComponent {
        path: PathBuf::from(path),
        uid,
        gid: uid,
        group_name: None,
        mode: Mode::new(mode),
        kind,
    }
}

fn dir(path: &str, uid: u32, mode: u32) -> PathComponent {
    entry(path, uid, mode, ComponentKind::Directory)
}

fn file(path: &str, uid: u32, mode: u32) -> PathComponent {
    entry(path, uid, mode, ComponentKind::RegularFile)
}

fn link(path: &str, uid: u32, target: Vec<PathComponent>) -> PathComponent {
    entry(
        path,
        uid,
        0o777,
        ComponentKind::Symlink {
            target: SymlinkTarget::Resolved(target),
        },
    )
}

fn staff_writable(path: &str) -> PathComponent {
    PathComponent {
        gid: STAFF,
        group_name: Some("staff".to_string()),
        ..dir(path, ROOT_UID, 0o775)
    }
}

fn config_chain(leaf: PathComponent) -> Vec<PathComponent> {
    vec![
        dir("/", ROOT_UID, 0o755),
        dir("/etc", ROOT_UID, 0o755),
        dir("/etc/iron-vault", ROOT_UID, 0o755),
        leaf,
    ]
}

fn config_file() -> PathComponent {
    file("/etc/iron-vault/config.toml", ROOT_UID, 0o644)
}

fn state_chain(leaf: PathComponent) -> Vec<PathComponent> {
    vec![
        dir("/", ROOT_UID, 0o755),
        dir("/var", ROOT_UID, 0o755),
        dir("/var/lib", ROOT_UID, 0o755),
        leaf,
    ]
}

fn state_dir(mode: u32) -> PathComponent {
    dir("/var/lib/iron-vault", SERVICE, mode)
}

fn lock_chain(leaf: PathComponent) -> Vec<PathComponent> {
    let mut chain = state_chain(state_dir(0o700));
    chain.push(leaf);
    chain
}

fn tmp_chain(rule_leaf: PathComponent) -> Vec<PathComponent> {
    vec![dir("/", ROOT_UID, 0o755), dir("/tmp", ROOT_UID, 0o1777), rule_leaf]
}

fn unsafe_at(path: &str, problem: Problem) -> Result<(), UnsafePath> {
    Err(UnsafePath {
        path: PathBuf::from(path),
        problem,
    })
}

fn wrong_owner(found: u32, expected: OwnerRequirement) -> Problem {
    Problem::WrongOwner { found, expected }
}

fn wrong_mode(found: u32, expected: u32) -> Problem {
    Problem::WrongMode {
        found: Mode::new(found),
        expected: Mode::new(expected),
    }
}

fn staff_problem() -> Problem {
    Problem::WritableByGroup {
        gid: STAFF,
        name: Some("staff".to_string()),
    }
}

/// Nests `levels` root-owned symlinks, each resolving to a chain whose leaf is the next, ending at the config file.
fn nested_links(levels: usize) -> Vec<PathComponent> {
    (0..levels).fold(config_chain(config_file()), |target, level| {
        vec![dir("/", ROOT_UID, 0o755), link(&format!("/link{level}"), ROOT_UID, target)]
    })
}

struct Case {
    name: &'static str,
    rule: TrustedPathRule,
    profile: Profile,
    owner: ExpectedOwner,
    chain: Vec<PathComponent>,
    expected: Result<(), UnsafePath>,
}

fn case(name: &'static str, rule: TrustedPathRule, chain: Vec<PathComponent>, expected: Result<(), UnsafePath>) -> Case {
    Case {
        name,
        rule,
        profile: Profile::Protected,
        owner: SERVICE_OWNER,
        chain,
        expected,
    }
}

fn dev_case(name: &'static str, rule: TrustedPathRule, chain: Vec<PathComponent>, expected: Result<(), UnsafePath>) -> Case {
    Case {
        profile: Profile::Development,
        owner: USER_OWNER,
        ..case(name, rule, chain, expected)
    }
}

fn binary_and_config_cases() -> Vec<Case> {
    use TrustedPathRule::{Binary, Config};
    let bin = |uid, mode| {
        vec![
            dir("/", ROOT_UID, 0o755),
            dir("/usr", ROOT_UID, 0o755),
            file("/usr/bin/iron-vault", uid, mode),
        ]
    };
    let user_config = |uid| config_chain(file("/etc/iron-vault/config.toml", uid, 0o600));
    vec![
        case("root-owned binary", Binary, bin(ROOT_UID, 0o755), Ok(())),
        case(
            "service-owned binary when protected",
            Binary,
            bin(SERVICE, 0o755),
            unsafe_at("/usr/bin/iron-vault", wrong_owner(SERVICE, OwnerRequirement::Root)),
        ),
        case(
            "group-writable binary",
            Binary,
            bin(ROOT_UID, 0o775),
            unsafe_at("/usr/bin/iron-vault", Problem::WritableByGroup { gid: 0, name: None }),
        ),
        case(
            "world-writable binary",
            Binary,
            bin(ROOT_UID, 0o757),
            unsafe_at("/usr/bin/iron-vault", Problem::WritableByOthers),
        ),
        dev_case("user-owned binary in development", Binary, bin(USER, 0o755), Ok(())),
        dev_case("root-owned binary in development", Binary, bin(ROOT_UID, 0o755), Ok(())),
        dev_case(
            "stranger's binary in development",
            Binary,
            bin(STRANGER, 0o755),
            unsafe_at("/usr/bin/iron-vault", wrong_owner(STRANGER, OwnerRequirement::RootOr(USER))),
        ),
        case("root-owned config", Config, config_chain(config_file()), Ok(())),
        case(
            "user-owned config when protected",
            Config,
            user_config(USER),
            unsafe_at("/etc/iron-vault/config.toml", wrong_owner(USER, OwnerRequirement::Root)),
        ),
        dev_case("user-owned config in development", Config, user_config(USER), Ok(())),
        case(
            "config that is a directory",
            Config,
            config_chain(dir("/etc/iron-vault/config.toml", ROOT_UID, 0o755)),
            unsafe_at("/etc/iron-vault/config.toml", Problem::NotARegularFile),
        ),
        case(
            "config that is a device",
            Config,
            config_chain(entry("/etc/iron-vault/config.toml", ROOT_UID, 0o644, ComponentKind::Other)),
            unsafe_at("/etc/iron-vault/config.toml", Problem::NotARegularFile),
        ),
    ]
}

fn ancestor_cases() -> Vec<Case> {
    use TrustedPathRule::{Config, RuntimeDir, StateDir};
    let config_under = |parent: PathComponent| vec![dir("/", ROOT_UID, 0o755), dir("/etc", ROOT_UID, 0o755), parent, config_file()];
    vec![
        case(
            "group-writable ancestor",
            Config,
            config_under(staff_writable("/etc/iron-vault")),
            unsafe_at("/etc/iron-vault", staff_problem()),
        ),
        case(
            "world-writable ancestor",
            Config,
            config_under(dir("/etc/iron-vault", ROOT_UID, 0o757)),
            unsafe_at("/etc/iron-vault", Problem::WritableByOthers),
        ),
        case(
            "service-owned ancestor",
            Config,
            config_under(dir("/etc/iron-vault", SERVICE, 0o755)),
            Ok(()),
        ),
        case(
            "stranger-owned ancestor",
            Config,
            config_under(dir("/etc/iron-vault", STRANGER, 0o755)),
            unsafe_at("/etc/iron-vault", wrong_owner(STRANGER, OwnerRequirement::RootOr(SERVICE))),
        ),
        case(
            "ancestor that is a file",
            Config,
            config_under(file("/etc/iron-vault", ROOT_UID, 0o755)),
            unsafe_at("/etc/iron-vault", Problem::NotADirectory),
        ),
        case(
            "sticky /tmp ancestor of a state dir",
            StateDir,
            tmp_chain(dir("/tmp/iron-vault", SERVICE, 0o700)),
            unsafe_at("/tmp", Problem::SharedStickyAncestor),
        ),
        case(
            "sticky /tmp ancestor of a config",
            Config,
            tmp_chain(file("/tmp/config.toml", ROOT_UID, 0o644)),
            unsafe_at("/tmp", Problem::SharedStickyAncestor),
        ),
        case(
            "sticky /tmp ancestor of a runtime dir",
            RuntimeDir,
            tmp_chain(dir("/tmp/iron-vault", SERVICE, 0o755)),
            Ok(()),
        ),
        case(
            "sticky ancestor not owned by root",
            RuntimeDir,
            vec![
                dir("/", ROOT_UID, 0o755),
                dir("/tmp", SERVICE, 0o1777),
                dir("/tmp/iron-vault", SERVICE, 0o755),
            ],
            unsafe_at("/tmp", Problem::WritableByGroup { gid: SERVICE, name: None }),
        ),
    ]
}

fn state_and_runtime_cases() -> Vec<Case> {
    use TrustedPathRule::{RuntimeDir, StateDir, StateFile};
    let run = |uid, mode| {
        vec![
            dir("/", ROOT_UID, 0o755),
            dir("/run", ROOT_UID, 0o755),
            dir("/run/iron-vault", uid, mode),
        ]
    };
    let lock = |uid, mode| lock_chain(file("/var/lib/iron-vault/lock", uid, mode));
    let lock_link = link(
        "/var/lib/iron-vault/lock",
        ROOT_UID,
        lock_chain(file("/var/lib/iron-vault/real-lock", SERVICE, 0o600)),
    );
    vec![
        case("state dir at 0700", StateDir, state_chain(state_dir(0o700)), Ok(())),
        case(
            "state dir at 0750",
            StateDir,
            state_chain(state_dir(0o750)),
            unsafe_at("/var/lib/iron-vault", wrong_mode(0o750, 0o700)),
        ),
        case(
            "state dir at 0770",
            StateDir,
            state_chain(state_dir(0o770)),
            unsafe_at("/var/lib/iron-vault", wrong_mode(0o770, 0o700)),
        ),
        case(
            "root-owned state dir",
            StateDir,
            state_chain(dir("/var/lib/iron-vault", ROOT_UID, 0o700)),
            unsafe_at("/var/lib/iron-vault", wrong_owner(ROOT_UID, OwnerRequirement::Uid(SERVICE))),
        ),
        case(
            "state dir that is a file",
            StateDir,
            state_chain(file("/var/lib/iron-vault", SERVICE, 0o700)),
            unsafe_at("/var/lib/iron-vault", Problem::NotADirectory),
        ),
        case("runtime dir at 0755", RuntimeDir, run(SERVICE, 0o755), Ok(())),
        case(
            "group-writable runtime dir",
            RuntimeDir,
            run(SERVICE, 0o775),
            unsafe_at("/run/iron-vault", Problem::WritableByGroup { gid: SERVICE, name: None }),
        ),
        case(
            "world-writable runtime dir",
            RuntimeDir,
            run(SERVICE, 0o757),
            unsafe_at("/run/iron-vault", Problem::WritableByOthers),
        ),
        case(
            "root-owned runtime dir",
            RuntimeDir,
            run(ROOT_UID, 0o755),
            unsafe_at("/run/iron-vault", wrong_owner(ROOT_UID, OwnerRequirement::Uid(SERVICE))),
        ),
        case(
            "runtime dir that is a file",
            RuntimeDir,
            run(SERVICE, 0o755)
                .into_iter()
                .take(2)
                .chain([file("/run/iron-vault", SERVICE, 0o755)])
                .collect(),
            unsafe_at("/run/iron-vault", Problem::NotADirectory),
        ),
        case("lock file at 0600", StateFile, lock(SERVICE, 0o600), Ok(())),
        case(
            "lock file at 0644",
            StateFile,
            lock(SERVICE, 0o644),
            unsafe_at("/var/lib/iron-vault/lock", wrong_mode(0o644, 0o600)),
        ),
        case(
            "lock file owned by a stranger",
            StateFile,
            lock(STRANGER, 0o600),
            unsafe_at("/var/lib/iron-vault/lock", wrong_owner(STRANGER, OwnerRequirement::Uid(SERVICE))),
        ),
        case(
            "lock file that is a symlink",
            StateFile,
            lock_chain(lock_link),
            unsafe_at("/var/lib/iron-vault/lock", Problem::NotARegularFile),
        ),
        case(
            "lock file that is a directory",
            StateFile,
            lock_chain(dir("/var/lib/iron-vault/lock", SERVICE, 0o600)),
            unsafe_at("/var/lib/iron-vault/lock", Problem::NotARegularFile),
        ),
    ]
}

fn symlink_cases() -> Vec<Case> {
    use TrustedPathRule::{Config, StateDir};
    let to_config = |target: Vec<PathComponent>| {
        vec![
            dir("/", ROOT_UID, 0o755),
            dir("/etc", ROOT_UID, 0o755),
            link("/etc/iron-vault", ROOT_UID, target),
        ]
    };
    let real_dir = |leaf: PathComponent| vec![dir("/", ROOT_UID, 0o755), dir("/opt", ROOT_UID, 0o755), leaf];
    let mut via_dir_link = to_config(real_dir(dir("/opt/iron-vault", ROOT_UID, 0o755)));
    via_dir_link.push(config_file());
    let mut via_file_target = to_config(real_dir(file("/opt/iron-vault", ROOT_UID, 0o755)));
    via_file_target.push(config_file());
    let user_dir_link = |link_uid, parent_uid| {
        vec![
            dir("/", ROOT_UID, 0o755),
            dir("/etc", ROOT_UID, 0o755),
            dir("/etc/iron-vault", parent_uid, 0o755),
            link("/etc/iron-vault/config.toml", link_uid, config_chain(config_file())),
        ]
    };
    let leaf_link = |target| vec![dir("/", ROOT_UID, 0o755), link("/config.toml", ROOT_UID, target)];
    let looped = vec![
        dir("/", ROOT_UID, 0o755),
        entry(
            "/loop",
            ROOT_UID,
            0o777,
            ComponentKind::Symlink {
                target: SymlinkTarget::Loop,
            },
        ),
    ];
    let state_link = vec![dir("/", ROOT_UID, 0o755), link("/state", ROOT_UID, state_chain(state_dir(0o750)))];
    let link_in_linked_dir = |real_uid| {
        let mut chain = to_config(real_dir(dir("/opt/iron-vault", real_uid, 0o755)));
        chain.push(link("/etc/iron-vault/config.toml", ROOT_UID, config_chain(config_file())));
        chain
    };
    vec![
        case(
            "symlink in a root-owned directory reached through a link",
            Config,
            link_in_linked_dir(ROOT_UID),
            Ok(()),
        ),
        case(
            "symlink in a service-owned directory reached through a root link",
            Config,
            link_in_linked_dir(SERVICE),
            unsafe_at("/etc/iron-vault/config.toml", Problem::UntrustedSymlink),
        ),
        case(
            "root-controlled leaf symlink",
            Config,
            leaf_link(config_chain(config_file())),
            Ok(()),
        ),
        case(
            "leaf symlink to an unsafe file",
            Config,
            leaf_link(config_chain(file("/etc/iron-vault/config.toml", ROOT_UID, 0o666))),
            unsafe_at("/etc/iron-vault/config.toml", Problem::WritableByGroup { gid: 0, name: None }),
        ),
        case("root-controlled ancestor symlink", Config, via_dir_link, Ok(())),
        case(
            "ancestor symlink to a file",
            Config,
            via_file_target,
            unsafe_at("/opt/iron-vault", Problem::NotADirectory),
        ),
        case(
            "symlink with a non-root parent",
            Config,
            user_dir_link(ROOT_UID, SERVICE),
            unsafe_at("/etc/iron-vault/config.toml", Problem::UntrustedSymlink),
        ),
        case(
            "symlink not owned by root",
            Config,
            user_dir_link(SERVICE, ROOT_UID),
            unsafe_at("/etc/iron-vault/config.toml", Problem::UntrustedSymlink),
        ),
        case(
            "symlink without a parent",
            Config,
            vec![link("/", ROOT_UID, config_chain(config_file()))],
            unsafe_at("/", Problem::UntrustedSymlink),
        ),
        case("symlink loop", Config, looped, unsafe_at("/loop", Problem::SymlinkLoop)),
        case(
            "symlink with no resolved components",
            Config,
            leaf_link(vec![]),
            unsafe_at("/config.toml", Problem::NoComponents),
        ),
        case(
            "leaf symlink keeps the state-dir rule",
            StateDir,
            state_link,
            unsafe_at("/var/lib/iron-vault", wrong_mode(0o750, 0o700)),
        ),
        case("forty nested symlinks", Config, nested_links(MAX_SYMLINK_DEPTH), Ok(())),
        case(
            "forty-one nested symlinks",
            Config,
            nested_links(MAX_SYMLINK_DEPTH + 1),
            unsafe_at("/link0", Problem::SymlinkLoop),
        ),
        case("empty path", Config, vec![], unsafe_at("", Problem::NoComponents)),
        case(
            "path not from the root",
            Config,
            vec![dir("/etc", ROOT_UID, 0o755), config_file()],
            unsafe_at("/etc", Problem::NotFromRoot),
        ),
        case(
            "symlink target not from the root",
            Config,
            leaf_link(vec![config_file()]),
            unsafe_at("/etc/iron-vault/config.toml", Problem::NotFromRoot),
        ),
    ]
}

fn ordering_cases() -> Vec<Case> {
    let both_bad = vec![
        dir("/", ROOT_UID, 0o755),
        staff_writable("/etc"),
        dir("/etc/iron-vault", STRANGER, 0o777),
        file("/etc/iron-vault/config.toml", STRANGER, 0o666),
    ];
    vec![case(
        "first unsafe component from the root wins",
        TrustedPathRule::Config,
        both_bad,
        unsafe_at("/etc", staff_problem()),
    )]
}

#[test]
fn every_rule_and_problem() {
    [
        binary_and_config_cases(),
        ancestor_cases(),
        state_and_runtime_cases(),
        symlink_cases(),
        ordering_cases(),
    ]
    .into_iter()
    .flatten()
    .for_each(|case| {
        assert_eq!(
            check(case.rule, case.profile, case.owner, &case.chain),
            case.expected,
            "{}",
            case.name
        )
    });
}

#[test]
fn mode_drops_file_type_bits_and_displays_as_octal() {
    let mode = Mode::new(0o40755);
    assert_eq!(mode.bits(), 0o755);
    assert_eq!(mode.to_string(), "0755");
    assert_eq!(Mode::new(0o1777).to_string(), "1777");
}

#[test]
fn messages_name_the_path_and_the_fix() {
    let at = |problem| {
        UnsafePath {
            path: PathBuf::from("/etc/iron-vault"),
            problem,
        }
        .to_string()
    };
    let expected = [
        (
            staff_problem(),
            "/etc/iron-vault is writable by group 'staff'; run `chmod g-w /etc/iron-vault`",
        ),
        (
            Problem::WritableByGroup { gid: 50, name: None },
            "/etc/iron-vault is writable by group 50; run `chmod g-w /etc/iron-vault`",
        ),
        (
            Problem::WritableByOthers,
            "/etc/iron-vault is writable by all users; run `chmod o-w /etc/iron-vault`",
        ),
        (
            wrong_mode(0o750, 0o700),
            "/etc/iron-vault has mode 0750 but must have mode 0700; run `chmod 0700 /etc/iron-vault`",
        ),
        (
            wrong_owner(USER, OwnerRequirement::Root),
            "/etc/iron-vault is owned by uid 1000 but must be owned by root; run `chown root /etc/iron-vault`",
        ),
        (
            wrong_owner(STRANGER, OwnerRequirement::RootOr(SERVICE)),
            "/etc/iron-vault is owned by uid 1001 but must be owned by root or uid 997; run `chown root /etc/iron-vault`",
        ),
        (
            wrong_owner(ROOT_UID, OwnerRequirement::Uid(SERVICE)),
            "/etc/iron-vault is owned by uid 0 but must be owned by uid 997; run `chown 997 /etc/iron-vault`",
        ),
        (
            Problem::NotADirectory,
            "/etc/iron-vault is not a directory; replace it with a directory",
        ),
        (
            Problem::SharedStickyAncestor,
            "/etc/iron-vault is a shared directory other users can write; move the state directory or config out of \
             /etc/iron-vault rather than changing its permissions",
        ),
    ];
    expected.into_iter().for_each(|(problem, message)| assert_eq!(at(problem), message));
}

#[test]
fn messages_cover_every_problem() {
    let problems = [
        Problem::NoComponents,
        Problem::NotFromRoot,
        Problem::NotARegularFile,
        Problem::UntrustedSymlink,
        Problem::SymlinkLoop,
    ];
    problems.into_iter().for_each(|problem| {
        let message = UnsafePath {
            path: PathBuf::from("/x"),
            problem,
        }
        .to_string();
        assert!(message.contains("/x") && message.contains("; "), "{message}");
    });
}

#[test]
fn root_as_expected_owner_is_named_once() {
    let chain = vec![
        dir("/", ROOT_UID, 0o755),
        dir("/srv", STRANGER, 0o755),
        dir("/srv/run", ROOT_UID, 0o755),
    ];
    let result = check(
        TrustedPathRule::RuntimeDir,
        Profile::Protected,
        ExpectedOwner { uid: ROOT_UID },
        &chain,
    );
    assert_eq!(result, unsafe_at("/srv", wrong_owner(STRANGER, OwnerRequirement::Root)));
}

/// Words that name an I/O module in a `use` declaration, grouped or not.
const IO_MODULES: [&str; 5] = ["fs", "io", "net", "process", "env"];

/// Path and std calls that touch the filesystem or the environment.
const IO_CALLS: [&str; 15] = [
    "std::fs",
    "std::io",
    "std::net",
    "std::process",
    "std::env",
    "fs::",
    ".exists(",
    ".try_exists(",
    ".metadata(",
    ".symlink_metadata(",
    ".canonicalize(",
    ".read_dir(",
    ".read_link(",
    ".is_dir(",
    ".is_file(",
];

/// The module must stay pure: the platform adapter reads metadata, and these rules only judge it.
#[test]
fn module_performs_no_io() {
    let source = include_str!("../trusted_path.rs");
    IO_CALLS
        .into_iter()
        .for_each(|forbidden| assert!(!source.contains(forbidden), "trusted_path.rs calls {forbidden}"));
    source
        .lines()
        .filter(|line| line.trim_start().starts_with("use "))
        .for_each(|line| {
            let named = line
                .split(|c: char| !(c.is_alphanumeric() || c == '_'))
                .find(|word| IO_MODULES.contains(word));
            assert!(named.is_none(), "trusted_path.rs imports an I/O module: {line}");
        });
}
