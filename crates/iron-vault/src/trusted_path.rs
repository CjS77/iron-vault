//! Trusted-path rules: whether the service may rely on its binary, config, state and runtime paths.
//!
//! Encryption cannot protect a vault whose binary, config or state directory a caller can replace, so before it
//! unlocks anything the service walks each trusted path from `/` down and refuses to start on the first unsafe
//! component (specification §3.1).
//!
//! The rules are pure functions over metadata the platform adapter reads, so every case is testable without a
//! filesystem. This module performs no I/O and names users and groups only by the ids and names it is given.

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};

/// The uid of root, which is trusted for every ancestor directory and owns protected binaries and config.
const ROOT_UID: u32 = 0;

/// How deeply symlink resolutions may nest: a link whose target chain holds a link, and so on.
///
/// This bounds nesting depth, not the total number of links on a path; the kernel's total limit of 40 links is
/// enforced by the adapter, which reports a path past it as [`SymlinkTarget::Loop`].
pub const MAX_SYMLINK_DEPTH: usize = 40;

/// Permission bits of a path component: the low twelve bits of `st_mode`, without the file-type bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mode(u32);

impl Mode {
    /// Keeps only the permission, set-id and sticky bits, so modes compare and display the same whatever the
    /// adapter passed in the file-type bits.
    pub const fn new(bits: u32) -> Self {
        Self(bits & 0o7777)
    }

    /// The permission, set-id and sticky bits.
    pub const fn bits(self) -> u32 {
        self.0
    }

    const fn group_writable(self) -> bool {
        self.0 & 0o020 != 0
    }

    const fn others_writable(self) -> bool {
        self.0 & 0o002 != 0
    }

    const fn sticky(self) -> bool {
        self.0 & 0o1000 != 0
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04o}", self.0)
    }
}

/// One component of a trusted path, from `/` down to the leaf, as the platform adapter reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
///
/// Components are named by the path as the service will open it, not by where symlinks lead. Below an ancestor
/// symlink, the adapter names each component under the link's path: with `/etc/iron-vault -> /opt/iron-vault`,
/// the config is `/etc/iron-vault/config.toml`, and its metadata is that of the file the link leads to. The
/// directory holding such a component is the last component of the link's resolved chain, `/opt/iron-vault`.
pub struct PathComponent {
    /// The component's absolute path, as the service names it; the first component of a chain is `/`.
    pub path: PathBuf,
    /// The owning uid.
    pub uid: u32,
    /// The owning user's name, when the adapter resolved one; messages fall back to the uid.
    pub owner_name: Option<String>,
    /// The owning gid.
    pub gid: u32,
    /// The owning group's name, when the adapter resolved one; messages fall back to the gid.
    pub group_name: Option<String>,
    /// The permission bits.
    pub mode: Mode,
    /// What kind of filesystem entry it is.
    pub kind: ComponentKind,
}

/// The kind of filesystem entry a path component is, without following a symlink.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComponentKind {
    /// A directory.
    Directory,
    /// A regular file.
    RegularFile,
    /// A symlink, with the resolution the adapter followed.
    Symlink {
        /// Where the link leads.
        target: SymlinkTarget,
    },
    /// A device, socket, FIFO or anything else.
    Other,
}

/// The resolution of a symlink, supplied by the adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SymlinkTarget {
    /// The full component chain of the target, from `/` down.
    Resolved(Vec<PathComponent>),
    /// The adapter stopped following links: they loop, or the path passes through more links than the kernel's
    /// limit of 40 allows.
    Loop,
}

/// The uid that owns the service's own files: the service account when protected, the invoking user in development.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpectedOwner {
    /// The expected uid.
    pub uid: u32,
}

/// The deployment profile, which decides only who may own the binary and config.
///
/// EP-14 owns the full deployment profile and replaces this enum with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// A supported protected installation: root owns the binary and config.
    Protected,
    /// A user-level installation with no isolation from that user's malware: the invoking user may own them.
    Development,
}

/// Which trusted path is being checked; each kind has its own rule for the leaf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustedPathRule {
    /// The service executable.
    Binary,
    /// The configuration file.
    Config,
    /// The state directory, which must be the expected owner's alone.
    StateDir,
    /// The runtime directory holding the service's sockets.
    RuntimeDir,
    /// A file inside the state directory, such as its lock file.
    StateFile,
}

impl TrustedPathRule {
    /// Whether a root-owned sticky ancestor such as `/tmp` may be group- or world-writable on this path.
    const fn allows_sticky_ancestor(self) -> bool {
        !matches!(self, Self::StateDir | Self::Config)
    }
}

/// Who may own a path component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerRequirement {
    /// Only root.
    Root,
    /// Only the given uid.
    Uid(u32),
    /// Root or the given uid.
    RootOr(u32),
}

impl OwnerRequirement {
    /// Root or `uid`, collapsed to [`OwnerRequirement::Root`] when `uid` is root, so messages do not repeat it.
    const fn root_or(uid: u32) -> Self {
        match uid {
            ROOT_UID => Self::Root,
            _ => Self::RootOr(uid),
        }
    }

    const fn allows(self, uid: u32) -> bool {
        match self {
            Self::Root => uid == ROOT_UID,
            Self::Uid(expected) => uid == expected,
            Self::RootOr(expected) => uid == ROOT_UID || uid == expected,
        }
    }

    /// The owner `chown` should set: root whenever root is acceptable, since root is the stricter choice.
    fn chown_target(self) -> String {
        match self {
            Self::Root | Self::RootOr(_) => "root".to_string(),
            Self::Uid(uid) => uid.to_string(),
        }
    }
}

impl fmt::Display for OwnerRequirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Root => write!(f, "root"),
            Self::Uid(uid) => write!(f, "uid {uid}"),
            Self::RootOr(uid) => write!(f, "root or uid {uid}"),
        }
    }
}

/// Why a path component is unsafe to trust.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Problem {
    /// The adapter supplied no components for a path or a symlink target.
    NoComponents,
    /// The adapter supplied a chain that does not start at `/`, so the directories above it went unchecked.
    NotFromRoot,
    /// Someone other than the allowed owners owns the component.
    WrongOwner {
        /// The owning uid.
        found: u32,
        /// Who may own it.
        expected: OwnerRequirement,
    },
    /// Members of the owning group can write the component.
    WritableByGroup {
        /// The owning gid.
        gid: u32,
        /// The owning group's name, when known.
        name: Option<String>,
    },
    /// Any user can write the component.
    WritableByOthers,
    /// A root-owned, sticky directory that other users can write, such as `/tmp`, above a state directory or config;
    /// other users can create entries there, so neither may live under it.
    SharedStickyAncestor,
    /// The component's mode is not the exact mode its rule requires.
    WrongMode {
        /// The mode found.
        found: Mode,
        /// The mode required.
        expected: Mode,
    },
    /// The component must be a directory.
    NotADirectory,
    /// The component must be a regular file, not a symlink or special file.
    NotARegularFile,
    /// A symlink that root does not control: the link or the directory holding it is not root-owned.
    UntrustedSymlink,
    /// The path passes through a symlink loop, more links than the kernel allows, or symlink resolutions nested
    /// deeper than [`MAX_SYMLINK_DEPTH`].
    SymlinkLoop,
}

/// The first unsafe component of a trusted path, walking from `/` down, and what is wrong with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsafePath {
    /// The unsafe component.
    pub path: PathBuf,
    /// What is wrong with it.
    pub problem: Problem,
}

impl fmt::Display for UnsafePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let path = self.path.display();
        match &self.problem {
            Problem::NoComponents => write!(f, "{path}: no path components were supplied to check; this is a bug in Iron Vault"),
            Problem::NotFromRoot => write!(
                f,
                "{path}: the path components supplied do not start at `/`; this is a bug in Iron Vault"
            ),
            Problem::WrongOwner { found, expected } => {
                let target = expected.chown_target();
                write!(
                    f,
                    "{path} is owned by uid {found} but must be owned by {expected}; run `chown {target} {path}`"
                )
            }
            Problem::WritableByGroup { gid, name } => {
                let group = name.as_ref().map_or_else(|| gid.to_string(), |name| format!("'{name}'"));
                write!(f, "{path} is writable by group {group}; run `chmod g-w {path}`")
            }
            Problem::WritableByOthers => write!(f, "{path} is writable by all users; run `chmod o-w {path}`"),
            Problem::SharedStickyAncestor => write!(
                f,
                "{path} is a shared directory other users can write; move the state directory or config out of {path} \
                 rather than changing its permissions"
            ),
            Problem::WrongMode { found, expected } => {
                write!(
                    f,
                    "{path} has mode {found} but must have mode {expected}; run `chmod {expected} {path}`"
                )
            }
            Problem::NotADirectory => write!(f, "{path} is not a directory; replace it with a directory"),
            Problem::NotARegularFile => {
                write!(
                    f,
                    "{path} is not a regular file; replace it with a regular file, not a symlink or special file"
                )
            }
            Problem::UntrustedSymlink => write!(
                f,
                "{path} is a symlink not controlled by root; the link and its directory must be owned by root, \
                 or replace the link with the real path"
            ),
            Problem::SymlinkLoop => write!(
                f,
                "{path} passes through a symlink loop or more than {MAX_SYMLINK_DEPTH} symlinks; replace the link with the real path"
            ),
        }
    }
}

impl std::error::Error for UnsafePath {}

/// Checks a trusted path's components, ordered from `/` down to the leaf, against `rule`.
///
/// Returns the first unsafe component in that order, so the same metadata always gives the same report. A symlink's
/// resolved target is checked as a trusted path of its own, playing the symlink's part: the leaf rule when the
/// symlink is the leaf, the ancestor rule otherwise.
pub fn check(rule: TrustedPathRule, profile: Profile, owner: ExpectedOwner, components: &[PathComponent]) -> Result<(), UnsafePath> {
    Walk {
        rule,
        profile,
        owner,
        depth: 0,
    }
    .chain(components, Role::Leaf, Path::new(""))
}

/// Whether a component is the end of the path being checked or a directory above it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Leaf,
    Ancestor,
}

/// The fixed inputs of one check, plus how many symlinks it has followed so far.
#[derive(Debug, Clone, Copy)]
struct Walk {
    rule: TrustedPathRule,
    profile: Profile,
    owner: ExpectedOwner,
    depth: usize,
}

impl Walk {
    /// Checks a chain whose last component plays `role`; `origin` names the chain when it is empty.
    fn chain(self, components: &[PathComponent], role: Role, origin: &Path) -> Result<(), UnsafePath> {
        if components.is_empty() {
            return Err(UnsafePath {
                path: origin.to_path_buf(),
                problem: Problem::NoComponents,
            });
        }
        if let Some(first) = components.first().filter(|first| first.path != Path::new("/")) {
            return Err(UnsafePath {
                path: first.path.clone(),
                problem: Problem::NotFromRoot,
            });
        }
        let last = components.len() - 1;
        components.iter().enumerate().try_for_each(|(index, component)| {
            let parent = index.checked_sub(1).and_then(|before| components.get(before)).and_then(resolved);
            let role = if index == last { role } else { Role::Ancestor };
            self.component(component, parent, role)
        })
    }

    fn component(self, component: &PathComponent, parent: Option<&PathComponent>, role: Role) -> Result<(), UnsafePath> {
        let checked = match (&component.kind, role) {
            (ComponentKind::Symlink { target }, _) => return self.symlink(component, parent, target, role),
            (_, Role::Leaf) => self.leaf(component),
            (_, Role::Ancestor) => self.ancestor(component),
        };
        checked.map_err(|problem| UnsafePath {
            path: component.path.clone(),
            problem,
        })
    }

    fn symlink(self, link: &PathComponent, parent: Option<&PathComponent>, target: &SymlinkTarget, role: Role) -> Result<(), UnsafePath> {
        let unsafe_link = |problem| {
            Err(UnsafePath {
                path: link.path.clone(),
                problem,
            })
        };
        if role == Role::Leaf && self.rule == TrustedPathRule::StateFile {
            return unsafe_link(Problem::NotARegularFile);
        }
        if link.uid != ROOT_UID || parent.is_none_or(|parent| parent.uid != ROOT_UID) {
            return unsafe_link(Problem::UntrustedSymlink);
        }
        match target {
            SymlinkTarget::Resolved(chain) if self.depth < MAX_SYMLINK_DEPTH => Walk {
                depth: self.depth + 1,
                ..self
            }
            .chain(chain, role, &link.path),
            SymlinkTarget::Resolved(_) | SymlinkTarget::Loop => unsafe_link(Problem::SymlinkLoop),
        }
    }

    fn leaf(self, component: &PathComponent) -> Result<(), Problem> {
        let service = OwnerRequirement::Uid(self.owner.uid);
        match self.rule {
            TrustedPathRule::Binary | TrustedPathRule::Config => {
                require_regular_file(component)?;
                require_owner(component, self.installed_owner())?;
                require_not_writable(component)
            }
            TrustedPathRule::StateDir => {
                require_directory(component)?;
                require_owner(component, service)?;
                require_mode(component, Mode::new(0o700))
            }
            TrustedPathRule::RuntimeDir => {
                require_directory(component)?;
                require_owner(component, service)?;
                require_not_writable(component)
            }
            TrustedPathRule::StateFile => {
                require_regular_file(component)?;
                require_owner(component, service)?;
                require_mode(component, Mode::new(0o600))
            }
        }
    }

    fn ancestor(self, component: &PathComponent) -> Result<(), Problem> {
        require_directory(component)?;
        require_owner(component, OwnerRequirement::root_or(self.owner.uid))?;
        match is_shared_sticky(component) {
            true if self.rule.allows_sticky_ancestor() => Ok(()),
            true => Err(Problem::SharedStickyAncestor),
            false => require_not_writable(component),
        }
    }

    /// Who may own the binary and config. Development also accepts root: a root-owned file is beyond the invoking
    /// user's reach, so it is never less safe than one the user owns.
    const fn installed_owner(self) -> OwnerRequirement {
        match self.profile {
            Profile::Protected => OwnerRequirement::Root,
            Profile::Development => OwnerRequirement::root_or(self.owner.uid),
        }
    }
}

fn require_directory(component: &PathComponent) -> Result<(), Problem> {
    match component.kind {
        ComponentKind::Directory => Ok(()),
        _ => Err(Problem::NotADirectory),
    }
}

fn require_regular_file(component: &PathComponent) -> Result<(), Problem> {
    match component.kind {
        ComponentKind::RegularFile => Ok(()),
        _ => Err(Problem::NotARegularFile),
    }
}

fn require_owner(component: &PathComponent, expected: OwnerRequirement) -> Result<(), Problem> {
    match expected.allows(component.uid) {
        true => Ok(()),
        false => Err(Problem::WrongOwner {
            found: component.uid,
            expected,
        }),
    }
}

fn require_mode(component: &PathComponent, expected: Mode) -> Result<(), Problem> {
    match component.mode == expected {
        true => Ok(()),
        false => Err(Problem::WrongMode {
            found: component.mode,
            expected,
        }),
    }
}

/// The real entry a component stands for: itself, or for a symlink the last component of its resolved chain,
/// followed through nested links. A loop or an empty resolution stands for nothing.
fn resolved(component: &PathComponent) -> Option<&PathComponent> {
    match &component.kind {
        ComponentKind::Symlink {
            target: SymlinkTarget::Resolved(chain),
        } => chain.last().and_then(resolved),
        ComponentKind::Symlink {
            target: SymlinkTarget::Loop,
        } => None,
        _ => Some(component),
    }
}

/// Whether a directory is shared like `/tmp`: root-owned, sticky and writable by other users. The sticky bit stops
/// those users renaming or removing the entries that lead to a trusted path, but not creating new ones.
const fn is_shared_sticky(component: &PathComponent) -> bool {
    let mode = component.mode;
    component.uid == ROOT_UID && mode.sticky() && (mode.group_writable() || mode.others_writable())
}

fn require_not_writable(component: &PathComponent) -> Result<(), Problem> {
    let mode = component.mode;
    if mode.group_writable() {
        return Err(Problem::WritableByGroup {
            gid: component.gid,
            name: component.group_name.clone(),
        });
    }
    match mode.others_writable() {
        true => Err(Problem::WritableByOthers),
        false => Ok(()),
    }
}

/// A directory above the binary or config that passes its rule but is not owned by root.
///
/// Anything running as the owning account can rename the trusted file out of the way and put its own in its place,
/// and the next service start would run or load it with the vault unlocked. That is safe enough to start on, so it
/// is a warning, never a refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathCaution {
    /// The rule of the trusted path the directory sits above.
    pub rule: TrustedPathRule,
    /// The directory, as the service names it; for a symlinked path, a directory on the resolved side.
    pub path: PathBuf,
    /// The owning uid.
    pub uid: u32,
    /// The owning user's name, when the adapter resolved one.
    pub owner_name: Option<String>,
}

/// Checks a trusted path as [`check`] does and, when it passes, returns its path cautions from `/` down.
///
/// Only the protected profile's binary and config have cautions: development already reports that it gives no
/// isolation, and the other rules expect the service account to own their directories. A refused path has its
/// refusal only.
pub fn check_with_cautions(
    rule: TrustedPathRule,
    profile: Profile,
    owner: ExpectedOwner,
    components: &[PathComponent],
) -> Result<Vec<PathCaution>, UnsafePath> {
    check(rule, profile, owner, components)?;
    let cautioned = profile == Profile::Protected && matches!(rule, TrustedPathRule::Binary | TrustedPathRule::Config);
    let mut seen = BTreeSet::new();
    Ok(match cautioned {
        true => chain_cautions(rule, components, Role::Leaf)
            .into_iter()
            .filter(|caution| seen.insert(caution.path.clone()))
            .collect(),
        false => Vec::new(),
    })
}

/// The non-root ancestors of a chain whose last component plays `role`, following resolved symlinks the way
/// [`check`] does. Only call it on a chain `check` accepted, which bounds the symlink nesting.
fn chain_cautions(rule: TrustedPathRule, components: &[PathComponent], role: Role) -> Vec<PathCaution> {
    let last = components.len().saturating_sub(1);
    components
        .iter()
        .enumerate()
        .flat_map(|(index, component)| {
            let role = if index == last { role } else { Role::Ancestor };
            component_cautions(rule, component, role)
        })
        .collect()
}

fn component_cautions(rule: TrustedPathRule, component: &PathComponent, role: Role) -> Vec<PathCaution> {
    match (&component.kind, role) {
        (
            ComponentKind::Symlink {
                target: SymlinkTarget::Resolved(chain),
            },
            _,
        ) => chain_cautions(rule, chain, role),
        (ComponentKind::Directory, Role::Ancestor) if component.uid != ROOT_UID => vec![PathCaution {
            rule,
            path: component.path.clone(),
            uid: component.uid,
            owner_name: component.owner_name.clone(),
        }],
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests;
