"""Reconcile source workflows and optional read-only GitHub registration evidence."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
REPOSITORY = "Mikeyphw/BakaSU"
REPOSITORY_ID = 1462243855
ROLES = {"required", "supplemental", "diagnostic", "protected", "inherited-review"}


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key: " + key)
        result[key] = value
    return result


def read_json(path):
    with Path(path).open(encoding="utf-8") as stream:
        return json.load(stream, object_pairs_hook=unique_object)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def valid_id(value):
    return type(value) is int and value > 0


def source_inventory(root=ROOT):
    inventory = read_json(root / "config/fork-ci-workflows.json")
    policy = read_json(root / "config/delivery-required-ci.json")
    require(inventory["schema_version"] == 1 and inventory["repository"] == REPOSITORY
            and inventory["repository_id"] == REPOSITORY_ID, "wrong inventory identity")
    require(policy["schema_version"] == 1 and policy["repository"] == REPOSITORY
            and policy["base_branch"] == "main" and policy["event"] == "pull_request"
            and policy["release_qualification"] == "separate", "wrong CI policy identity")
    required = policy["required_workflows"]
    require(len(required) == 2 and all(valid_id(x["workflow_id"]) for x in required),
            "invalid required workflow policy")
    required_by_name = {x["name"]: x["workflow_id"] for x in required}
    require(len(required_by_name) == len(set(required_by_name.values())) == 2,
            "duplicate required workflow identity")
    require(set(required_by_name) == {"Fork Manager Baseline Qualification", "Lints Check"},
            "required workflow name changed")
    expected = {}
    for entry in inventory["workflows"]:
        path, name, role = entry["path"], entry["name"], entry["role"]
        require(re.fullmatch(r"\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml", path)
                and path not in expected and role in ROLES, "invalid workflow roster entry")
        candidate = root / path
        require(candidate.is_file() and not candidate.is_symlink(), "missing workflow: " + path)
        match = re.search(r"^name:\s*(.+)$", candidate.read_text(encoding="utf-8"), re.M)
        require(match is not None and match.group(1).strip().strip('\"\'') == name,
                "workflow name changed: " + path)
        row = dict(entry)
        if role == "required":
            require(name in required_by_name, "unexpected required workflow: " + path)
            row["workflow_id"] = required_by_name[name]
        elif "observed_workflow_id" in row:
            require(valid_id(row["observed_workflow_id"]), "invalid historical workflow ID")
        expected[path] = row
    actual = {p.relative_to(root).as_posix() for p in (root / ".github/workflows").iterdir()
              if p.suffix in (".yml", ".yaml")}
    require(actual == set(expected), "source workflow inventory drift")
    require({x["name"] for x in expected.values() if x["role"] == "required"} == set(required_by_name),
            "required workflow roster mismatch")
    ids = [x.get("workflow_id", x.get("observed_workflow_id")) for x in expected.values()]
    present = [x for x in ids if x is not None]
    require(len(present) == len(set(present)), "duplicate provider workflow ID")
    return expected


def reconcile(expected, repo, pages):
    require(repo.get("id") == REPOSITORY_ID and repo.get("full_name") == REPOSITORY
            and repo.get("default_branch") == "main", "wrong GitHub repository identity")
    require(isinstance(pages, list) and pages, "complete paginated workflow response required")
    totals = {page["total_count"] for page in pages}
    require(len(totals) == 1 and all(type(n) is int and n >= 0 for n in totals),
            "inconsistent registration totals")
    actual = {}
    ids = set()
    for page in pages:
        for row in page["workflows"]:
            path, provider_id = row["path"], row["id"]
            require(valid_id(provider_id) and path not in actual and provider_id not in ids,
                    "duplicate or invalid registered workflow")
            actual[path] = row
            ids.add(provider_id)
    require(len(actual) == next(iter(totals)), "incomplete workflow pagination")
    result = []
    failures = []
    for path, entry in sorted(expected.items()):
        row = actual.get(path)
        status = "MISSING" if row is None else "ACTIVE" if row.get("state") == "active" else "INACTIVE"
        pin = entry.get("workflow_id", entry.get("observed_workflow_id"))
        if row is not None and (row.get("name") != entry["name"] or (pin is not None and row["id"] != pin)):
            status = "IDENTITY_MISMATCH"
        if entry["role"] == "required" and status != "ACTIVE":
            failures.append(path)
        result.append({"path": path, "role": entry["role"], "status": status,
                       "id": row["id"] if row is not None else None})
    unexpected = sorted(set(actual) - set(expected))
    return {"repository_id": REPOSITORY_ID, "required_status": "FAIL" if failures else "PASS",
            "inventory_status": "REVIEW_REQUIRED" if unexpected or any(x["status"] != "ACTIVE" for x in result) else "PASS",
            "failed_required_paths": failures, "unexpected_registrations": unexpected, "workflows": result}



def read_provider():
    """Use only GitHub GET operations; keep token and error bodies out of reports."""
    def get(*args):
        result = subprocess.run(["gh", "api", *args], cwd=ROOT, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=60, check=False)
        if result.returncode != 0:
            raise ValueError("GitHub read-only registration request failed, rc=" + str(result.returncode))
        return json.loads(result.stdout, object_pairs_hook=unique_object)
    return (get("repos/" + REPOSITORY),
            get("--paginate", "--slurp", "repos/" + REPOSITORY + "/actions/workflows"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-json", type=Path)
    parser.add_argument("--registrations-json", type=Path,
                        help="complete gh api --paginate --slurp Actions workflow response")
    parser.add_argument("--github-api", action="store_true", help="read current registrations via authenticated gh GET")
    args = parser.parse_args()
    try:
        expected = source_inventory()
        if args.github_api:
            require(not (args.repository_json or args.registrations_json), "choose provider GET or supplied evidence, not both")
            report = reconcile(expected, *read_provider())
        elif args.repository_json or args.registrations_json:
            require(args.repository_json and args.registrations_json, "both registration evidence files required")
            report = reconcile(expected, read_json(args.repository_json), read_json(args.registrations_json))
        else:
            report = {"repository_id": REPOSITORY_ID, "source_status": "PASS",
                      "registration_status": "NOT_CHECKED", "workflow_count": len(expected)}
        print(json.dumps(report, indent=2))
        return 1 if report.get("required_status") == "FAIL" else 0
    except (ValueError, KeyError, TypeError, OSError, subprocess.TimeoutExpired) as exc:
        print(f"BK_GAP01_INVENTORY_REFUSED {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
