import os
import subprocess
import textwrap
from pathlib import Path

import pytest

from mock_snyk import (
    ADMIN_ROLE_ID,
    DEVELOPER_ROLE_ID,
    GROUP_ID,
    ORG_ID,
    OTHER_ORG_ID,
    TOKEN,
    MockSnyk,
)

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "snyk-access-sync.sh"
EXAMPLE = ROOT / "examples" / ".github" / "snyk-access.yaml"
REPO_URL = "https://github.com/example-org/payments-api"


@pytest.fixture
def snyk():
    with MockSnyk() as mock:
        yield mock


def write_access_file(tmp_path, content):
    path = tmp_path / "snyk-access.yaml"
    path.write_text(textwrap.dedent(content))
    return path


def run(access_file, tmp_path, mode="apply", snyk=None, **env):
    summary = tmp_path / "summary.md"
    output = tmp_path / "output.txt"
    summary.write_text("")
    output.write_text("")
    full_env = {
        "PATH": os.environ["PATH"],
        "ACCESS_FILE": str(access_file),
        "MODE": mode,
        "GITHUB_STEP_SUMMARY": str(summary),
        "GITHUB_OUTPUT": str(output),
        "SNYK_RETRY_DELAY": "0",
        "REPO_URL": REPO_URL,
    }
    if snyk:
        full_env.update(
            {
                "SNYK_API_URL": snyk.url,
                "SNYK_TOKEN": TOKEN,
                "SNYK_GROUP_ID": GROUP_ID,
                "SNYK_ORG_ADMIN_ROLE_ID": ADMIN_ROLE_ID,
                "SNYK_DEVELOPER_ROLE_ID": DEVELOPER_ROLE_ID,
            }
        )
    full_env.update(env)
    result = subprocess.run(["bash", str(SCRIPT)], env=full_env, capture_output=True, text=True, timeout=60)
    result.summary = summary.read_text()
    result.outputs = dict(line.split("=", 1) for line in output.read_text().splitlines() if "=" in line)
    return result


VALID_WITH_ORG = f"""\
    version: 1
    organization:
      id: {ORG_ID}
    org_admins:
      - email: admin@example.com
    users:
      - email: dev.one@example.com
      - email: dev.two@example.com
"""


# --- validate mode ----------------------------------------------------------


def test_example_file_is_valid(tmp_path):
    result = run(EXAMPLE, tmp_path, mode="validate")
    assert result.returncode == 0, result.stderr
    assert "validation passed" in result.summary


@pytest.mark.parametrize(
    "content, message",
    [
        ("org_admins:\n  - email: a@example.com\n", "version is required"),
        ("version: 2\norg_admins:\n  - email: a@example.com\n", "Unsupported version 2"),
        ("version: 1\n", "org_admins must be a list with at least one entry"),
        ("version: 1\norg_admins: []\n", "org_admins must be a list with at least one entry"),
        ("version: 1\norg_admins:\n  - email: not-an-email\n", "org_admins[0].email must be an email address"),
        (
            "version: 1\norg_admins:\n  - email: a@example.com\nusers:\n  - email: b@example.com\n    role: admin\n",
            'users[0] has unsupported key "role"',
        ),
        (
            "version: 1\norg_admins:\n  - email: A@example.com\nusers:\n  - email: a@example.com\n",
            "a@example.com appears more than once",
        ),
        (
            "version: 1\norganization:\n  id: payments\norg_admins:\n  - email: a@example.com\n",
            "organization.id must be a Snyk Organization ID",
        ),
        ("version: 1\nadmins:\n  - email: a@example.com\norg_admins:\n  - email: a@example.com\n", 'Unknown top-level key "admins"'),
        ("version: 1\nusers: someone\norg_admins:\n  - email: a@example.com\n", "users must be a list"),
        ("- just\n- a\n- list\n", "The file must be a YAML mapping"),
    ],
)
def test_invalid_files_fail_validation(tmp_path, content, message):
    path = write_access_file(tmp_path, content)
    result = run(path, tmp_path, mode="validate")
    assert result.returncode == 1
    assert message in result.stderr
    assert message in result.summary


def test_invalid_yaml_fails(tmp_path):
    path = write_access_file(tmp_path, "version: 1\norg_admins: [\n")
    result = run(path, tmp_path, mode="validate")
    assert result.returncode == 1
    assert "is not valid YAML" in result.stderr


def test_multiple_documents_fail(tmp_path):
    path = write_access_file(tmp_path, "version: 1\n---\nversion: 1\n")
    result = run(path, tmp_path, mode="validate")
    assert result.returncode == 1
    assert "exactly one YAML document" in result.stderr


def test_missing_file_fails(tmp_path):
    result = run(tmp_path / "missing.yaml", tmp_path, mode="validate")
    assert result.returncode == 1
    assert "Access file not found" in result.stderr


def test_validation_failure_makes_no_api_calls(tmp_path, snyk):
    path = write_access_file(tmp_path, "version: 9\norg_admins:\n  - email: a@example.com\n")
    result = run(path, tmp_path, mode="apply", snyk=snyk)
    assert result.returncode == 1
    assert snyk.state.requests == []


# --- apply mode -------------------------------------------------------------


def test_apply_adds_missing_members_with_fixed_roles(tmp_path, snyk):
    snyk.state.group_users = {"admin@example.com": "u-admin", "dev.one@example.com": "u-dev1", "dev.two@example.com": "u-dev2"}
    path = write_access_file(tmp_path, VALID_WITH_ORG)

    result = run(path, tmp_path, snyk=snyk)

    assert result.returncode == 0, result.stderr
    assert snyk.state.org_memberships == {
        (ORG_ID, "u-admin"): ADMIN_ROLE_ID,
        (ORG_ID, "u-dev1"): DEVELOPER_ROLE_ID,
        (ORG_ID, "u-dev2"): DEVELOPER_ROLE_ID,
    }
    post = snyk.state.posts("/memberships")[0]
    assert post["content_type"] == "application/vnd.api+json"
    assert post["body"]["data"]["type"] == "org_membership"
    assert all(r["auth"] == f"token {TOKEN}" for r in snyk.state.requests)
    assert result.outputs == {"org-id": ORG_ID, "added-count": "3", "failed-count": "0", "unresolved-count": "0"}
    assert "**Added:** 3" in result.summary


def test_apply_is_idempotent_and_never_changes_existing_roles(tmp_path, snyk):
    snyk.state.group_users = {"admin@example.com": "u-admin", "dev.one@example.com": "u-dev1", "dev.two@example.com": "u-dev2"}
    snyk.state.org_memberships = {(ORG_ID, "u-admin"): ADMIN_ROLE_ID, (ORG_ID, "u-dev1"): ADMIN_ROLE_ID}
    path = write_access_file(tmp_path, VALID_WITH_ORG)

    result = run(path, tmp_path, snyk=snyk)

    assert result.returncode == 0, result.stderr
    assert len(snyk.state.posts("/memberships")) == 1
    assert snyk.state.org_memberships[(ORG_ID, "u-dev1")] == ADMIN_ROLE_ID
    assert "Skipped: already has this role" in result.summary
    assert "Skipped: has a different role | Holds the Org Admin role. Not changed." in result.summary


def test_unresolved_emails_are_skipped_and_reported(tmp_path, snyk):
    snyk.state.group_users = {"admin@example.com": "u-admin"}
    path = write_access_file(tmp_path, VALID_WITH_ORG)

    result = run(path, tmp_path, snyk=snyk)

    assert result.returncode == 0, result.stderr
    assert list(snyk.state.org_memberships) == [(ORG_ID, "u-admin")]
    assert result.outputs["unresolved-count"] == "2"
    assert "- dev.one@example.com" in result.summary
    assert "::warning::dev.two@example.com was not found" in result.stderr


def test_partial_email_matches_are_not_used(tmp_path, snyk):
    snyk.state.group_users = {"admin@example.com": "u-admin", "old.dev.one@example.com": "u-wrong"}
    path = write_access_file(tmp_path, VALID_WITH_ORG)

    result = run(path, tmp_path, snyk=snyk)

    assert result.returncode == 0, result.stderr
    assert (ORG_ID, "u-wrong") not in snyk.state.org_memberships


def test_fail_on_unresolved(tmp_path, snyk):
    snyk.state.group_users = {"admin@example.com": "u-admin"}
    path = write_access_file(tmp_path, VALID_WITH_ORG)
    result = run(path, tmp_path, snyk=snyk, FAIL_ON_UNRESOLVED="true")
    assert result.returncode == 1


def test_dry_run_makes_no_changes(tmp_path, snyk):
    snyk.state.group_users = {"admin@example.com": "u-admin", "dev.one@example.com": "u-dev1"}
    path = write_access_file(tmp_path, VALID_WITH_ORG)

    result = run(path, tmp_path, mode="dry-run", snyk=snyk)

    assert result.returncode == 0, result.stderr
    assert snyk.state.posts("/memberships") == []
    assert "Would add (dry run)" in result.summary
    assert "**Would add:** 2" in result.summary


def test_apply_refuses_non_default_branch(tmp_path, snyk):
    path = write_access_file(tmp_path, VALID_WITH_ORG)
    result = run(path, tmp_path, snyk=snyk, GIT_REF="refs/heads/feature", DEFAULT_BRANCH="main")
    assert result.returncode == 1
    assert "only runs from the default branch" in result.stderr
    assert snyk.state.requests == []


def test_missing_credentials_fail(tmp_path):
    path = write_access_file(tmp_path, VALID_WITH_ORG)
    result = run(path, tmp_path, mode="dry-run")
    assert result.returncode == 1
    assert "SNYK_TOKEN is required" in result.stderr


# --- Snyk Organization resolution --------------------------------------------

NO_ORG = """\
    version: 1
    org_admins:
      - email: admin@example.com
"""


def test_org_resolved_from_repository_url(tmp_path, snyk):
    snyk.state.group_users = {"admin@example.com": "u-admin"}
    snyk.state.assets = {REPO_URL: [ORG_ID]}
    path = write_access_file(tmp_path, NO_ORG)

    result = run(path, tmp_path, snyk=snyk, REPO_URL=REPO_URL.replace("example-org", "Example-Org") + ".git/")

    assert result.returncode == 0, result.stderr
    search = snyk.state.posts("/assets/search")[0]
    assert search["body"]["query"]["attributes"] == {
        "attribute": "repository_url",
        "operator": "equal",
        "values": [REPO_URL.replace("example-org", "Example-Org")],
    }
    assert list(snyk.state.org_memberships) == [(ORG_ID, "u-admin")]
    assert "Asset Search" in result.summary


def test_repository_in_several_orgs_fails(tmp_path, snyk):
    snyk.state.group_users = {"admin@example.com": "u-admin"}
    snyk.state.assets = {REPO_URL: [ORG_ID, OTHER_ORG_ID]}
    path = write_access_file(tmp_path, NO_ORG)

    result = run(path, tmp_path, snyk=snyk)

    assert result.returncode == 1
    assert "linked to several Snyk Organizations" in result.stderr
    assert snyk.state.posts("/memberships") == []


def test_repository_not_in_snyk_fails(tmp_path, snyk):
    path = write_access_file(tmp_path, NO_ORG)
    result = run(path, tmp_path, snyk=snyk)
    assert result.returncode == 1
    assert "No Snyk Organization is linked" in result.stderr
    assert snyk.state.posts("/memberships") == []


def test_org_outside_group_fails(tmp_path, snyk):
    snyk.state.orgs[ORG_ID]["group_id"] = "99999999-9999-9999-9999-999999999999"
    snyk.state.group_users = {"admin@example.com": "u-admin"}
    path = write_access_file(tmp_path, VALID_WITH_ORG)

    result = run(path, tmp_path, snyk=snyk)

    assert result.returncode == 1
    assert "does not belong to Snyk Group" in result.stderr
    assert snyk.state.posts("/memberships") == []


def test_missing_developer_role_fails(tmp_path, snyk):
    snyk.state.roles = [r for r in snyk.state.roles if r["publicId"] != DEVELOPER_ROLE_ID]
    path = write_access_file(tmp_path, VALID_WITH_ORG)

    result = run(path, tmp_path, snyk=snyk)

    assert result.returncode == 1
    assert "developer role" in result.stderr and "does not exist" in result.stderr
    assert snyk.state.posts("/memberships") == []


# --- API failures -------------------------------------------------------------


def test_group_lookup_failure_aborts_before_changes(tmp_path, snyk):
    snyk.state.group_users = {"admin@example.com": "u-admin"}
    snyk.state.failures = {r"GET /rest/groups/.*/memberships": 403}
    path = write_access_file(tmp_path, VALID_WITH_ORG)

    result = run(path, tmp_path, snyk=snyk)

    assert result.returncode == 1
    assert "No membership changes were made" in result.stderr
    assert snyk.state.posts("/memberships") == []


def test_create_failure_is_retried_then_reported(tmp_path, snyk):
    snyk.state.group_users = {"admin@example.com": "u-admin"}
    snyk.state.failures = {r"POST /rest/orgs/.*/memberships": 500}
    path = write_access_file(tmp_path, VALID_WITH_ORG)

    result = run(path, tmp_path, snyk=snyk)

    assert result.returncode == 1
    assert len(snyk.state.posts("/rest/orgs/")) == 4
    assert result.outputs["failed-count"] == "1"
    assert "Could not add admin@example.com: HTTP 500. forced failure" in result.stderr
