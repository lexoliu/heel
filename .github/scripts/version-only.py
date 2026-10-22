#!/usr/bin/env python3
"""Print whether a diff only bumps this workspace's own versions.

Usage: version-only.py BASE HEAD

Prints `true` when every file that differs between the two commits is
Markdown (a changelog), or a Cargo.toml or Cargo.lock whose only change is
the version of a workspace member — `package.version`,
`workspace.package.version`, the `version` of a path dependency, a lock
entry without a `source` and its references. That is the whole of a
release-plz bump, and it cannot change what a compiler or a test observes
beyond the version string itself. Anything else prints `false`.

Exits non-zero only on a failure of its own, so a caller never reads a
crash as either answer.
"""

import subprocess
import sys
import tomllib

DEPENDENCY_TABLES = ("dependencies", "dev-dependencies", "build-dependencies")


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], check=True, capture_output=True, text=True
    ).stdout


def changed_files(base: str, head: str) -> list[str]:
    out = git("diff", "--no-renames", "--name-only", "-z", base, head)
    return [p for p in out.split("\0") if p]


def load(rev: str, file: str) -> dict | None:
    """The file's TOML at `rev`, or None when it does not exist there."""
    result = subprocess.run(
        ["git", "show", f"{rev}:{file}"], capture_output=True, text=True
    )
    if result.returncode != 0:
        exists = git("ls-tree", "--name-only", rev, "--", file).strip()
        if exists:
            sys.exit(f"git show {rev}:{file} failed: {result.stderr.strip()}")
        return None
    return tomllib.loads(result.stdout)


def strip_dependency_versions(tables: dict) -> None:
    for kind in DEPENDENCY_TABLES:
        for spec in tables.get(kind, {}).values():
            if isinstance(spec, dict) and "path" in spec:
                spec.pop("version", None)


def normalize_manifest(manifest: dict) -> dict:
    package = manifest.get("package", {})
    if isinstance(package.get("version"), str):
        del package["version"]
    workspace = manifest.get("workspace", {})
    workspace.get("package", {}).pop("version", None)
    strip_dependency_versions(manifest)
    strip_dependency_versions(workspace)
    for target in manifest.get("target", {}).values():
        strip_dependency_versions(target)
    return manifest


def normalize_lock(lock: dict) -> dict:
    members = {p["name"] for p in lock.get("package", []) if "source" not in p}
    for package in lock.get("package", []):
        if "source" not in package:
            del package["version"]
        package["dependencies"] = [
            strip_member_reference(dep, members)
            for dep in package.get("dependencies", [])
        ]
    return lock


def strip_member_reference(dep: str, members: set[str]) -> str:
    """`name version` of a member becomes `name`; a reference that names a
    source is a registry or git package, whatever its name."""
    name, *rest = dep.split(" ")
    if name in members and len(rest) <= 1:
        return name
    return dep


def version_only(base: str, head: str) -> bool:
    for file in changed_files(base, head):
        name = file.rsplit("/", 1)[-1]
        if name.endswith(".md"):
            continue
        if name == "Cargo.toml":
            normalize = normalize_manifest
        elif name == "Cargo.lock":
            normalize = normalize_lock
        else:
            print(f"{file}: not a manifest, lockfile or Markdown", file=sys.stderr)
            return False
        before, after = load(base, file), load(head, file)
        if before is None or after is None:
            print(f"{file}: added or removed", file=sys.stderr)
            return False
        if normalize(before) != normalize(after):
            print(f"{file}: changes more than workspace versions", file=sys.stderr)
            return False
    return True


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    print("true" if version_only(sys.argv[1], sys.argv[2]) else "false")


if __name__ == "__main__":
    main()
