//! Trusted-path rules: whether the service may rely on its binary, config, state and runtime paths.
//!
//! Encryption cannot protect a vault whose binary, config or state directory a caller can replace, so before it
//! unlocks anything the service walks each trusted path from `/` down and refuses to start on the first unsafe
//! component (specification §3.1).
//!
//! The rules are pure functions over metadata the platform adapter reads, so every case is testable without a
//! filesystem. This module performs no I/O and names users and groups only by the ids and names it is given.

use std::fmt;
use std::path::{Path, PathBuf};

/// The uid of root, which is trusted for every ancestor directory and owns protected binaries and config.
const ROOT_UID: u32 = 0;

/// How many symlinks one trusted path may pass through, matching the Linux kernel's `ELOOP` limit.
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
pub struct PathComponent {
    /// The component's absolute path.
    pub path: PathBuf,
    /// The owning uid.
    pub uid: u32,
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
    /// The adapter stopped following links: the chain loops or is longer than [`MAX_SYMLINK_DEPTH`].
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
    /// The path passes through a symlink loop or more than [`MAX_SYMLINK_DEPTH`] symlinks.
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
            Problem::WrongOwner { found, expected } => {
                let target = expected.chown_target();
                write!(f, "{path} is owned by uid {found} but must be owned by {expected}; run `chown {target} {path}`")
            }
            Problem::WritableByGroup { gid, name } => {
                let group = name.as_ref().map_or_else(|| gid.to_string(), |name| format!("'{name}'"));
                write!(f, "{path} is writable by group {group}; run `chmod g-w {path}`")
            }
            Problem::WritableByOthers => write!(f, "{path} is writable by all users; run `chmod o-w {path}`"),
            Problem::WrongMode { found, expected } => {
                write!(f, "{path} has mode {found} but must have mode {expected}; run `chmod {expected} {path}`")
            }
            Problem::NotADirectory => write!(f, "{path} is not a directory; replace it with a directory"),
            Problem::NotARegularFile => {
                write!(f, "{path} is not a regular file; replace it with a regular file, not a symlink or special file")
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
    Walk { rule, profile, owner, depth: 0 }.chain(components, Role::Leaf, Path::new(""))
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
            return Err(UnsafePath { path: origin.to_path_buf(), problem: Problem::NoComponents });
        }
        let last = components.len() - 1;
        components.iter().enumerate().try_for_each(|(index, component)| {
            let parent = index.checked_sub(1).and_then(|before| components.get(before));
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
        checked.map_err(|problem| UnsafePath { path: component.path.clone(), problem })
    }

    fn symlink(self, link: &PathComponent, parent: Option<&PathComponent>, target: &SymlinkTarget, role: Role) -> Result<(), UnsafePath> {
        let unsafe_link = |problem| Err(UnsafePath { path: link.path.clone(), problem });
        if role == Role::Leaf && self.rule == TrustedPathRule::StateFile {
            return unsafe_link(Problem::NotARegularFile);
        }
        if link.uid != ROOT_UID || parent.is_none_or(|parent| parent.uid != ROOT_UID) {
            return unsafe_link(Problem::UntrustedSymlink);
        }
        match target {
            SymlinkTarget::Resolved(chain) if self.depth < MAX_SYMLINK_DEPTH => {
                Walk { depth: self.depth + 1, ..self }.chain(chain, role, &link.path)
            }
            SymlinkTarget::Resolved(_) | SymlinkTarget::Loop => unsafe_link(Problem::SymlinkLoop),
        }
    }

    fn leaf(self, component: &PathComponent) -> Result<(), Problem> {
        let service = OwnerRequirement::Uid(self.owner.uid);
        match self.rule {
            TrustedPathRule::Binary | TrustedPathRule::Config => {
                require_regular_file(component)?;
                require_owner(component, self.installed_owner())?;
                require_not_writable(component, false)
            }
            TrustedPathRule::StateDir => {
                require_directory(component)?;
                require_owner(component, service)?;
                require_mode(component, Mode::new(0o700))
            }
            TrustedPathRule::RuntimeDir => {
                require_directory(component)?;
                require_owner(component, service)?;
                require_not_writable(component, false)
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
        require_not_writable(component, self.rule.allows_sticky_ancestor())
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
        false => Err(Problem::WrongOwner { found: component.uid, expected }),
    }
}

fn require_mode(component: &PathComponent, expected: Mode) -> Result<(), Problem> {
    match component.mode == expected {
        true => Ok(()),
        false => Err(Problem::WrongMode { found: component.mode, expected }),
    }
}

/// Rejects group and world write access, except on a root-owned sticky directory when `sticky_exempt` is set: there
/// other users can add entries but cannot rename or remove the ones that lead to the trusted path.
fn require_not_writable(component: &PathComponent, sticky_exempt: bool) -> Result<(), Problem> {
    let mode = component.mode;
    if sticky_exempt && mode.sticky() && component.uid == ROOT_UID {
        return Ok(());
    }
    if mode.group_writable() {
        return Err(Problem::WritableByGroup { gid: component.gid, name: component.group_name.clone() });
    }
    match mode.others_writable() {
        true => Err(Problem::WritableByOthers),
        false => Ok(()),
    }
}

#[cfg(test)]
mod tests;
