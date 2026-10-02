#!/usr/bin/env python3
"""Verify that the immutable version-tag ruleset is active and narrowly bypassed.

Ported from the SDK's ``.github/scripts/tag-ruleset-state.mjs`` in
``agent-passport-system/agent-passport-system``.

In an organization repository only roles, teams and GitHub Apps can be ruleset
bypass actors; individual users cannot, and GitHub drops any individual user from
a ruleset's bypass list when the repository is transferred into an organization.
This repository's live ruleset today has the single bypass ``User:171286556:always``,
so the transfer empties that list and nobody can create a ``v*`` tag until the
organization admin role is added in its place. The release bypass is therefore
expected to be the organization admin role rather than a named person.

GitHub does report an ``actor_id`` alongside ``OrganizationAdmin``, but it is not
pinned here: GitHub ignores it for a role bypass, so requiring a particular value
would reject the real ruleset. The release principal is narrowed by the actor
guard in ``release_actor_state.py``, not by this check.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.request
from typing import Any

EXPECTED_NAME = "immutable-version-tags"
EXPECTED_REPOSITORY = "agent-passport-system/agent-passport-python"
EXPECTED_RELEASE_BYPASS_ACTOR_TYPE = "OrganizationAdmin"
EXPECTED_RELEASE_BYPASS_MODE = "always"
EXPECTED_REF_INCLUDE = "refs/tags/v*"
REQUIRED_RULES = frozenset({"creation", "update", "deletion", "non_fast_forward"})

_TIMEOUT_SECONDS = 15


class TagRulesetError(Exception):
    """A refusal. The ruleset state could not be established as expected."""


def validate_immutable_version_tag_ruleset(
    document: Any,
    *,
    expected_repository: str = EXPECTED_REPOSITORY,
    expected_release_bypass_actor_type: str = EXPECTED_RELEASE_BYPASS_ACTOR_TYPE,
) -> dict[str, str]:
    if not isinstance(document, dict):
        raise TagRulesetError("immutable version-tag ruleset is not an object")
    if document.get("name") != EXPECTED_NAME:
        raise TagRulesetError(f"expected ruleset {EXPECTED_NAME}")
    if document.get("target") != "tag" or document.get("enforcement") != "active":
        raise TagRulesetError(
            "immutable version-tag ruleset must target tags with active enforcement"
        )
    source = document.get("source")
    if source and source != expected_repository:
        raise TagRulesetError(
            f"immutable version-tag ruleset has unexpected source {source}"
        )

    conditions = document.get("conditions")
    ref_name = conditions.get("ref_name") if isinstance(conditions, dict) else None
    include = ref_name.get("include") if isinstance(ref_name, dict) else None
    exclude = ref_name.get("exclude") if isinstance(ref_name, dict) else None
    if not isinstance(include, list) or sorted(include) != [EXPECTED_REF_INCLUDE]:
        raise TagRulesetError(
            f"immutable version-tag ruleset must include only {EXPECTED_REF_INCLUDE}"
        )
    if not isinstance(exclude, list) or len(exclude) != 0:
        raise TagRulesetError(
            "immutable version-tag ruleset must not exclude release tags"
        )

    rules = document.get("rules")
    if not isinstance(rules, list):
        raise TagRulesetError("immutable version-tag ruleset has no rules array")
    rule_types = {rule.get("type") for rule in rules if isinstance(rule, dict)}
    for required in sorted(REQUIRED_RULES):
        if required not in rule_types:
            raise TagRulesetError(
                f"immutable version-tag ruleset is missing {required}"
            )

    # GitHub hides bypass_actors from a token without admin rights. Absent is
    # therefore "not visible", which is reported rather than treated as empty;
    # present must be exactly the one role bypass.
    bypass_visibility = "not-visible"
    if "bypass_actors" in document:
        bypass_actors = document.get("bypass_actors")
        if not isinstance(bypass_actors, list) or len(bypass_actors) != 1:
            raise TagRulesetError(
                "immutable version-tag ruleset must have exactly one visible bypass actor"
            )
        actor = bypass_actors[0]
        if (
            not isinstance(actor, dict)
            or actor.get("actor_type") != expected_release_bypass_actor_type
            or actor.get("bypass_mode") != EXPECTED_RELEASE_BYPASS_MODE
        ):
            raise TagRulesetError(
                "immutable version-tag ruleset bypass must be the release bypass role only"
            )
        bypass_visibility = "visible"

    return {"state": "active", "bypassVisibility": bypass_visibility}


def _fetch_json(path: str, token: str) -> Any:
    request = urllib.request.Request(
        f"https://api.github.com{path}",
        headers={
            "accept": "application/vnd.github+json",
            "authorization": f"Bearer {token}",
            "user-agent": "agent-passport-python-release-guard",
            "x-github-api-version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(request, timeout=_TIMEOUT_SECONDS) as response:
        if response.status != 200:
            raise TagRulesetError(
                f"GitHub ruleset lookup returned HTTP {response.status}"
            )
        body = response.read().decode("utf-8")
    try:
        return json.loads(body)
    except ValueError as error:
        raise TagRulesetError(
            f"GitHub ruleset lookup returned invalid JSON: {error}"
        ) from error


def main() -> int:
    repository = os.environ.get("GITHUB_REPOSITORY")
    token = os.environ.get("GH_TOKEN")
    try:
        if repository != EXPECTED_REPOSITORY:
            raise TagRulesetError(
                f"unexpected GITHUB_REPOSITORY: {repository or '<missing>'}"
            )
        if not token:
            raise TagRulesetError("GH_TOKEN is required")

        summaries = _fetch_json(
            f"/repos/{repository}/rulesets?includes_parents=true", token
        )
        if not isinstance(summaries, list):
            raise TagRulesetError("GitHub ruleset list is not an array")
        matches = [
            item
            for item in summaries
            if isinstance(item, dict) and item.get("name") == EXPECTED_NAME
        ]
        if len(matches) != 1 or not isinstance(matches[0].get("id"), int):
            raise TagRulesetError(
                f"expected exactly one {EXPECTED_NAME} ruleset, found {len(matches)}"
            )

        document = _fetch_json(
            f"/repos/{repository}/rulesets/{matches[0]['id']}?includes_parents=true",
            token,
        )
        result = validate_immutable_version_tag_ruleset(
            document, expected_repository=repository
        )
    except TagRulesetError as error:
        print(f"::error::{error}", file=sys.stderr)
        return 1

    if result["bypassVisibility"] == "not-visible":
        print(
            f"::notice::{EXPECTED_NAME}: structural restrictions are active; GitHub hides "
            "bypass actors from the workflow token, so the principal gate must verify the "
            "release-bypass-role-only bypass"
        )
    else:
        print(
            f"{EXPECTED_NAME}: active with the release bypass role as the sole bypass actor"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
