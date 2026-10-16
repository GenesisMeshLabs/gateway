"""Operation IDs are append-only against the latest release.

An operation ID is the public URL /v1/networks/{network}/services/{id}. A pull
request may add operations; it may not remove one released in the latest
release tag (vX.Y.Z), or change it so that a request that worked fails: a new
method or service group, a move to the operator tier, a parameter it no longer
accepts, or a new path parameter it requires. Such a change needs the
Maintainer's `breaking` label and an `### Upgrading` section in the pull
request description.

Only changes made by the pull request count (head against its base), so a
breaking change accepted earlier does not fail later pull requests.

Usage: operation_ids.py BASE_REV HEAD_REV
Environment: LABELS (comma-separated label names), BODY (the description).
"""

import json
import os
import re
import subprocess
import sys

CATALOG = "ui/services.json"
RELEASE = re.compile(r"^v(\d+)\.(\d+)\.(\d+)$")
UPGRADING = re.compile(r"^###\s+Upgrading\s*$", re.MULTILINE)


def git(*args):
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout


def latest_release():
    tags = [t for t in git("tag", "--list", "v*").split() if RELEASE.match(t)]
    return max(tags, key=lambda t: tuple(int(n) for n in RELEASE.match(t).groups()), default=None)


def catalog_at(rev):
    try:
        text = git("show", f"{rev}:{CATALOG}")
    except subprocess.CalledProcessError:
        return {}
    return {op["id"]: op for op in json.loads(text)}


def breaks(released, current):
    """How `current` breaks a request that worked against `released`."""
    if current is None:
        return {"removed"}
    found = set()
    if current["method"] != released["method"]:
        found.add(f"method {released['method']} -> {current['method']}")
    if current["group"] != released["group"]:
        found.add(f"service group {released['group']} -> {current['group']}")
    if current["admin"] and not released["admin"]:
        found.add("now an operator (admin) operation")
    accepted = set(released["parameters"]) | set(released["query"])
    for name in sorted(accepted - set(current["parameters"]) - set(current["query"])):
        found.add(f"no longer accepts {name}")
    for name in sorted(set(current["parameters"]) - set(released["parameters"])):
        found.add(f"now requires {name}")
    return found


def incompatibilities(released, base, head):
    """Breaks of released operations that this change introduces."""
    problems = []
    for op_id, old in sorted(released.items()):
        if op_id not in base:
            continue
        new = breaks(old, head.get(op_id)) - breaks(old, base[op_id])
        problems += [f"{op_id}: {what}" for what in sorted(new)]
    return problems


def allowed(labels, body):
    return "breaking" in labels and bool(UPGRADING.search(body or ""))


def main():
    base_rev, head_rev = sys.argv[1:3]
    tag = latest_release()
    if tag is None:
        sys.exit("::error::No release tag (vX.Y.Z) found; fetch tags (fetch-depth: 0).")
    released = catalog_at(tag)
    if not released:
        sys.exit(f"::error::{tag} has no {CATALOG}.")
    problems = incompatibilities(released, catalog_at(base_rev), catalog_at(head_rev))
    head_count = len(catalog_at(head_rev))
    if not problems:
        print(f"Operation IDs compatible with {tag}: {len(released)} released, {head_count} now.")
        return
    for problem in problems:
        print(f"::warning::{problem}")
    labels = {label.strip() for label in os.environ.get("LABELS", "").split(",") if label.strip()}
    if allowed(labels, os.environ.get("BODY", "")):
        print(f"{len(problems)} incompatible change(s) to operations released in {tag}, "
              "accepted: labelled breaking, with an ### Upgrading section.")
        return
    sys.exit(f"::error::{len(problems)} incompatible change(s) to operations released in {tag}. "
             "Keep the released operation, or have the Maintainer label the pull request "
             "`breaking` and add an `### Upgrading` section to its description.")


if __name__ == "__main__":
    main()
