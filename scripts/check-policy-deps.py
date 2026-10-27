#!/usr/bin/env python3
"""Fail if `iron-vault-policy` gains a dependency that could bring I/O into the pure policy crate.

Specification §7 requires `iron-vault-policy` to perform no I/O. This guard reads `cargo metadata` and checks:

1. Every normal (non-dev, non-build) direct dependency is on ALLOWED_DIRECT.
2. No crate in the normal transitive dependency tree is on DENIED_TRANSITIVE (I/O runtimes).

Dev-dependencies are ignored: they only build tests and never ship in the library.

To extend ALLOWED_DIRECT, add the crate name with a comment citing the ticket that approved it. A new entry needs
a reason the crate does no I/O.
"""

import json
import subprocess
import sys

POLICY_CRATE = "iron-vault-policy"

ALLOWED_DIRECT = {
    "thiserror",  # K-3: typed errors
    "serde",  # K-3, K-5, K-6: configuration and policy model deserialization
    "url",  # K-4: destination URL parsing
    "idna",  # K-4: host name normalization
    "toml",  # K-10: configuration parsing from an in-memory string
}

DENIED_TRANSITIVE = {"tokio", "mio", "socket2", "hyper", "reqwest", "async-std"}


def load_metadata():
    out = subprocess.run(["cargo", "metadata", "--format-version", "1", "--locked"], check=True, capture_output=True, text=True)
    return json.loads(out.stdout)


def is_normal(dep):
    return any(kind["kind"] is None for kind in dep["dep_kinds"])


def policy_package(meta):
    return next(p for p in meta["packages"] if p["name"] == POLICY_CRATE)


def normal_closure(meta, root_id):
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
    seen, stack = set(), [root_id]
    while stack:
        node = nodes[stack.pop()]
        children = [d["pkg"] for d in node["deps"] if is_normal(d) and d["pkg"] not in seen]
        seen.update(children)
        stack.extend(children)
    return seen


def main():
    meta = load_metadata()
    pkg = policy_package(meta)
    names = {p["id"]: p["name"] for p in meta["packages"]}
    direct = sorted({d["name"] for d in pkg["dependencies"] if d["kind"] is None})
    unapproved = [d for d in direct if d not in ALLOWED_DIRECT]
    denied = sorted({names[i] for i in normal_closure(meta, pkg["id"])} & DENIED_TRANSITIVE)
    for d in unapproved:
        print(f"error: {POLICY_CRATE} depends on '{d}', which is not in ALLOWED_DIRECT", file=sys.stderr)
    for d in denied:
        print(f"error: {POLICY_CRATE} pulls in I/O runtime '{d}'", file=sys.stderr)
    if unapproved or denied:
        return 1
    print(f"{POLICY_CRATE} dependencies OK: {', '.join(direct) or '(none)'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
