//! Trusted-path checks on real files, as the unprivileged test user.
//!
//! The trees live under the system temp directory, normally `/tmp`: root-owned, sticky and world-writable. The
//! runtime-directory and state-file rules accept such an ancestor, so they are checked end to end. The state-directory
//! and config rules rightly refuse one, so for those the collected chain has only that shared ancestor's mode replaced
//! with `0755` before it is checked, as if the tree lived under a private directory such as `/var/lib`; every
//! component the test creates is checked exactly as collected. Cases that need root-owned files are covered by the
//! pure rule tests.

#![cfg(target_os = "linux")]
// Test helpers outside `#[test]` functions: a failed setup step should stop the test where it happened.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use iron_vault::path_metadata::{self, MAX_SYMLINK_HOPS, invoking_user};
use iron_vault::trusted_path::{
    self, ComponentKind, ExpectedOwner, Mode, PathComponent, Problem, Profile, SymlinkTarget, TrustedPathRule, UnsafePath,
};
use iron_vault::trusted_path_report::{PathFailure, ServicePaths, TrustedPathReport, check_path};

static NEXT: AtomicU32 = AtomicU32::new(0);

/// A fresh directory with mode `0755` under the system temp directory, removed on drop.
struct Tree(PathBuf);

impl Tree {
    fn new(name: &str) -> Self {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!("iv-trusted-{name}-{}-{n}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        dir(&root, 0o755);
        Self(root)
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.0.join(relative)
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Creates a directory with exactly `mode`, whatever the umask.
fn dir(path: &Path, mode: u32) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

/// Creates a file with exactly `mode`, whatever the umask.
fn file(path: &Path, mode: u32) {
    fs::write(path, b"").unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn me() -> ExpectedOwner {
    invoking_user().unwrap()
}

fn check_real(rule: TrustedPathRule, path: &Path) -> Result<(), PathFailure> {
    check_path(rule, Profile::Development, me(), path)
}

/// Checks `path` as if the shared sticky directory above `tree` were a private `0755` directory.
fn check_beside_tmp(tree: &Tree, rule: TrustedPathRule, path: &Path) -> Result<(), UnsafePath> {
    let chain = privatize_shared_ancestors(&tree.0, path_metadata::collect(path).unwrap());
    trusted_path::check(rule, Profile::Development, me(), &chain)
}

fn privatize_shared_ancestors(root: &Path, chain: Vec<PathComponent>) -> Vec<PathComponent> {
    chain
        .into_iter()
        .map(|component| match component.kind {
            ComponentKind::Symlink { target: SymlinkTarget::Resolved(target) } => PathComponent {
                kind: ComponentKind::Symlink { target: SymlinkTarget::Resolved(privatize_shared_ancestors(root, target)) },
                ..component
            },
            _ if is_shared_ancestor(root, &component) => PathComponent { mode: Mode::new(0o755), ..component },
            _ => component,
        })
        .collect()
}

fn is_shared_ancestor(root: &Path, component: &PathComponent) -> bool {
    root.starts_with(&component.path) && root != component.path && component.uid == 0 && component.mode.bits() & 0o1000 != 0
}

fn unsafe_at(path: PathBuf, problem: Problem) -> Result<(), UnsafePath> {
    Err(UnsafePath { path, problem })
}

/// A state directory at `state` holding a lock file with `lock_mode`.
fn state_tree(state: &Path, lock_mode: u32) {
    dir(state, 0o700);
    file(&state.join("lock"), lock_mode);
}

#[test]
fn a_safe_tree_passes() {
    let tree = Tree::new("safe");
    dir(&tree.path("etc"), 0o755);
    file(&tree.path("etc/config.toml"), 0o644);
    state_tree(&tree.path("state"), 0o600);
    dir(&tree.path("run"), 0o755);

    assert_eq!(check_real(TrustedPathRule::RuntimeDir, &tree.path("run")), Ok(()));
    assert_eq!(check_real(TrustedPathRule::StateFile, &tree.path("state/lock")), Ok(()));
    assert_eq!(check_beside_tmp(&tree, TrustedPathRule::StateDir, &tree.path("state")), Ok(()));
    assert_eq!(check_beside_tmp(&tree, TrustedPathRule::Config, &tree.path("etc/config.toml")), Ok(()));
}

#[test]
fn a_state_dir_under_the_shared_temp_dir_is_refused_there() {
    let tree = Tree::new("under-tmp");
    state_tree(&tree.path("state"), 0o600);
    let Err(PathFailure::Unsafe(found)) = check_real(TrustedPathRule::StateDir, &tree.path("state")) else {
        panic!("a state directory under a shared sticky directory passed");
    };
    assert_eq!(found.problem, Problem::SharedStickyAncestor);
    assert!(tree.0.starts_with(&found.path), "{found}");
}

#[test]
fn a_group_writable_ancestor_fails_naming_it() {
    let tree = Tree::new("group-writable");
    dir(&tree.path("shared"), 0o775);
    state_tree(&tree.path("shared/state"), 0o600);
    let gid = fs::metadata(tree.path("shared")).map(|m| std::os::unix::fs::MetadataExt::gid(&m)).unwrap();
    let expected = unsafe_at(tree.path("shared"), Problem::WritableByGroup { gid, name: None });
    assert_eq!(check_real(TrustedPathRule::StateFile, &tree.path("shared/state/lock")), expected.clone().map_err(PathFailure::from));
    assert_eq!(check_beside_tmp(&tree, TrustedPathRule::StateDir, &tree.path("shared/state")), expected);
}

#[test]
fn a_user_owned_symlink_to_the_state_dir_is_untrusted() {
    let tree = Tree::new("state-link");
    state_tree(&tree.path("real-state"), 0o600);
    symlink("real-state", tree.path("state")).unwrap();
    let expected = unsafe_at(tree.path("state"), Problem::UntrustedSymlink);
    assert_eq!(check_beside_tmp(&tree, TrustedPathRule::StateDir, &tree.path("state")), expected);
    assert_eq!(check_real(TrustedPathRule::StateFile, &tree.path("state/lock")), expected.map_err(PathFailure::from));
}

#[test]
fn a_lock_file_replaced_by_a_symlink_fails() {
    let tree = Tree::new("lock-link");
    dir(&tree.path("state"), 0o700);
    file(&tree.path("state/real-lock"), 0o600);
    symlink("real-lock", tree.path("state/lock")).unwrap();
    let expected = unsafe_at(tree.path("state/lock"), Problem::NotARegularFile).map_err(PathFailure::from);
    assert_eq!(check_real(TrustedPathRule::StateFile, &tree.path("state/lock")), expected);
}

#[test]
fn a_lock_file_readable_by_others_fails() {
    let tree = Tree::new("lock-mode");
    state_tree(&tree.path("state"), 0o644);
    let problem = Problem::WrongMode { found: Mode::new(0o644), expected: Mode::new(0o600) };
    let expected = unsafe_at(tree.path("state/lock"), problem).map_err(PathFailure::from);
    assert_eq!(check_real(TrustedPathRule::StateFile, &tree.path("state/lock")), expected);
}

#[test]
fn components_below_a_symlink_are_named_under_the_link() {
    let tree = Tree::new("naming");
    dir(&tree.path("real"), 0o755);
    file(&tree.path("real/config.toml"), 0o644);
    symlink("real", tree.path("link")).unwrap();
    let chain = path_metadata::collect(&tree.path("link/config.toml")).unwrap();

    let names: Vec<&Path> = chain.iter().map(|c| c.path.as_path()).collect();
    assert_eq!(names.first(), Some(&Path::new("/")));
    assert_eq!(names[names.len() - 2..], [tree.path("link").as_path(), tree.path("link/config.toml").as_path()]);
    let ComponentKind::Symlink { target: SymlinkTarget::Resolved(target) } = &chain[chain.len() - 2].kind else {
        panic!("the link was not collected as a symlink: {:?}", chain[chain.len() - 2]);
    };
    assert_eq!(target.first().map(|c| c.path.as_path()), Some(Path::new("/")));
    assert_eq!(target.last().map(|c| (c.path.clone(), c.kind.clone())), Some((tree.path("real"), ComponentKind::Directory)));
    assert_eq!(chain.last().map(|c| (c.kind.clone(), c.mode)), Some((ComponentKind::RegularFile, Mode::new(0o644))));
}

#[test]
fn a_symlink_loop_is_reported_after_the_hop_limit() {
    let tree = Tree::new("loop");
    symlink("b", tree.path("a")).unwrap();
    symlink("a", tree.path("b")).unwrap();
    let chain = path_metadata::collect(&tree.path("a")).unwrap();
    let (links, innermost) = follow_links(chain.last().unwrap());
    assert_eq!((links, innermost), (MAX_SYMLINK_HOPS + 1, &SymlinkTarget::Loop));
}

/// Follows a symlink component through each resolved chain's last component, counting the links passed.
fn follow_links(component: &PathComponent) -> (usize, &SymlinkTarget) {
    match &component.kind {
        ComponentKind::Symlink { target: SymlinkTarget::Resolved(chain) } => {
            let (links, innermost) = follow_links(chain.last().unwrap());
            (links + 1, innermost)
        }
        ComponentKind::Symlink { target } => (1, target),
        other => panic!("{} is {other:?}, not a symlink", component.path.display()),
    }
}

#[test]
fn the_report_lists_every_path_in_a_fixed_order() {
    let tree = Tree::new("report");
    dir(&tree.path("etc"), 0o755);
    file(&tree.path("etc/config.toml"), 0o644);
    state_tree(&tree.path("state"), 0o600);
    dir(&tree.path("run"), 0o755);
    let paths = ServicePaths {
        profile: Profile::Development,
        owner: me(),
        config: tree.path("etc/config.toml"),
        state_dir: tree.path("state"),
        runtime_dir: Some(tree.path("run")),
    };
    let report = TrustedPathReport::check(&paths);

    let listed: Vec<(TrustedPathRule, PathBuf)> = report.entries.iter().map(|e| (e.rule, e.path.clone())).collect();
    let expected = [
        (TrustedPathRule::Binary, std::env::current_exe().unwrap()),
        (TrustedPathRule::Config, tree.path("etc/config.toml")),
        (TrustedPathRule::StateDir, tree.path("state")),
        (TrustedPathRule::StateFile, tree.path("state/lock")),
        (TrustedPathRule::RuntimeDir, tree.path("run")),
    ];
    assert_eq!(listed, expected);
    assert_eq!(report.entries[3].outcome, Ok(()));
    assert_eq!(report.entries[4].outcome, Ok(()));
}

#[test]
fn a_report_without_a_runtime_dir_omits_it() {
    let paths = ServicePaths {
        profile: Profile::Protected,
        owner: me(),
        config: PathBuf::from("/nonexistent/config.toml"),
        state_dir: PathBuf::from("/nonexistent/state"),
        runtime_dir: None,
    };
    let rules: Vec<TrustedPathRule> = TrustedPathReport::check(&paths).entries.iter().map(|e| e.rule).collect();
    assert_eq!(rules, [TrustedPathRule::Binary, TrustedPathRule::Config, TrustedPathRule::StateDir, TrustedPathRule::StateFile]);
}
