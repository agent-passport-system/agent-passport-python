"""Behavioural tests for the release principal guard and the tag ruleset check.

The publish workflow had no actor check. Ownership of the repository was the only
thing standing between a write-capable account and a PyPI release, and moving the
repository into an organization turns that single account into an
organization-level grant. On top of that, the live ``immutable-version-tags``
ruleset bypass is the individual user ``171286556``, which GitHub removes when the
repository is transferred into an organization.

These tests pin what both guards refuse. A guard that fails open is worse than no
guard: it reads as protection in the workflow log while authorizing everyone. Each
case drives the validators directly, so the refusals are asserted here rather than
discovered on a release.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

_SCRIPTS = Path(__file__).resolve().parents[1] / ".github" / "scripts"


def _load(module_name: str, filename: str):
    spec = importlib.util.spec_from_file_location(module_name, _SCRIPTS / filename)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


actor_state = _load("release_actor_state", "release_actor_state.py")
ruleset_state = _load("tag_ruleset_state", "tag_ruleset_state.py")

ReleaseActorError = actor_state.ReleaseActorError
TagRulesetError = ruleset_state.TagRulesetError

REPOSITORY = "agent-passport-system/agent-passport-python"
RUN_ID = 36966151267
RUN_ATTEMPT = 1


def _context(**overrides):
    return {
        "repository": REPOSITORY,
        "repository_id": actor_state.PYTHON_REPOSITORY_ID,
        "run_id": RUN_ID,
        "run_attempt": RUN_ATTEMPT,
        **overrides,
    }


def _attempt_document(**overrides):
    return {
        "id": RUN_ID,
        "run_attempt": RUN_ATTEMPT,
        "repository": {
            "full_name": REPOSITORY,
            "id": actor_state.PYTHON_REPOSITORY_ID,
        },
        "triggering_actor": {"id": actor_state.AUTHORIZED_RELEASE_ACTOR_ID},
        **overrides,
    }


def _ok(document=None):
    return {"status": 200, "document": _attempt_document() if document is None else document}


def _env(**overrides):
    return {
        "GITHUB_ACTOR_ID": str(actor_state.AUTHORIZED_RELEASE_ACTOR_ID),
        "GITHUB_REPOSITORY": REPOSITORY,
        "GITHUB_REPOSITORY_ID": str(actor_state.PYTHON_REPOSITORY_ID),
        "GITHUB_RUN_ID": str(RUN_ID),
        "GITHUB_RUN_ATTEMPT": str(RUN_ATTEMPT),
        "GH_TOKEN": "test-token",
        **overrides,
    }


def _unreachable(url, token):  # noqa: ANN001, ARG001
    raise AssertionError("the guard must not reach the network on this path")


# ── the pinned identities ────────────────────────────────────────────────────


def test_the_guard_pins_the_release_actor_and_the_repository_it_releases_from():
    assert actor_state.AUTHORIZED_RELEASE_ACTOR_ID == 171286556
    assert actor_state.PYTHON_REPOSITORY_ID == 1174743930


# ── the original actor ───────────────────────────────────────────────────────


def test_the_authorized_actor_id_passes_the_original_actor_check():
    assert (
        actor_state.validate_original_release_actor(
            str(actor_state.AUTHORIZED_RELEASE_ACTOR_ID)
        )
        == actor_state.AUTHORIZED_RELEASE_ACTOR_ID
    )


def test_another_actor_id_is_refused_even_with_identical_write_access():
    # Moving into an organization is exactly the case that makes this bite:
    # every other member is a different actor id with the same write access.
    with pytest.raises(ReleaseActorError, match="authorized release actor"):
        actor_state.validate_original_release_actor("1")


@pytest.mark.parametrize(
    "value",
    [None, "", " ", "0", "171286556x", "aeoess", "+171286556", 171286556, True],
)
def test_a_missing_or_non_numeric_actor_id_is_refused_rather_than_skipped(value):
    with pytest.raises(ReleaseActorError, match="authorized release actor"):
        actor_state.validate_original_release_actor(value)


# ── the run attempt document ─────────────────────────────────────────────────


def test_a_complete_matching_run_attempt_document_is_accepted():
    principal = actor_state.validate_release_run_attempt(_context(), _ok())
    assert principal.repository == REPOSITORY
    assert principal.repository_id == actor_state.PYTHON_REPOSITORY_ID
    assert principal.run_id == RUN_ID
    assert principal.run_attempt == RUN_ATTEMPT
    assert principal.triggering_actor_id == actor_state.AUTHORIZED_RELEASE_ACTOR_ID


def test_a_rerun_requested_by_another_actor_is_refused():
    # The case the guard exists for: attempt 1 was authorized, someone else asks
    # for attempt 2. GITHUB_ACTOR_ID still names the original actor, so only the
    # triggering actor of this attempt can catch it.
    with pytest.raises(ReleaseActorError, match="must be requested by the authorized"):
        actor_state.validate_release_run_attempt(
            _context(run_attempt=2),
            _ok(_attempt_document(run_attempt=2, triggering_actor={"id": 1})),
        )


@pytest.mark.parametrize("status", [301, 401, 403, 404, 422, 500, None])
def test_a_lookup_that_did_not_return_200_fails_closed(status):
    with pytest.raises(ReleaseActorError, match="is not established"):
        actor_state.validate_release_run_attempt(
            _context(), {"status": status, "document": _attempt_document()}
        )


@pytest.mark.parametrize("document", [None, "ok", 42, [], [{"id": RUN_ID}]])
def test_a_non_object_document_is_refused_rather_than_read_as_empty(document):
    with pytest.raises(ReleaseActorError, match="non-object document"):
        actor_state.validate_release_run_attempt(
            _context(), {"status": 200, "document": document}
        )


def test_a_document_naming_a_different_repository_is_refused():
    with pytest.raises(ReleaseActorError, match="does not name this repository"):
        actor_state.validate_release_run_attempt(
            _context(),
            _ok(
                _attempt_document(
                    repository={
                        "full_name": "aeoess/agent-passport-python",
                        "id": actor_state.PYTHON_REPOSITORY_ID,
                    }
                )
            ),
        )


def test_a_document_whose_repository_id_is_not_the_pinned_id_is_refused():
    # The repository id is the part a transfer cannot change, so a document whose
    # full name matches but whose id does not is the impersonation case.
    with pytest.raises(ReleaseActorError, match="does not name this repository id"):
        actor_state.validate_release_run_attempt(
            _context(),
            _ok(_attempt_document(repository={"full_name": REPOSITORY, "id": 1161268529})),
        )


@pytest.mark.parametrize("repository_id", [None, "1174743930", 1174743930.5, True])
def test_a_document_with_no_repository_id_is_refused(repository_id):
    with pytest.raises(ReleaseActorError, match="has no repository id"):
        actor_state.validate_release_run_attempt(
            _context(),
            _ok(
                _attempt_document(
                    repository={"full_name": REPOSITORY, "id": repository_id}
                )
            ),
        )


def test_a_document_naming_a_different_run_or_attempt_is_refused():
    with pytest.raises(ReleaseActorError, match="does not name this run"):
        actor_state.validate_release_run_attempt(
            _context(), _ok(_attempt_document(id=RUN_ID + 1))
        )
    with pytest.raises(ReleaseActorError, match="does not name this attempt"):
        actor_state.validate_release_run_attempt(
            _context(), _ok(_attempt_document(run_attempt=2))
        )


@pytest.mark.parametrize(
    "triggering_actor", [None, {}, {"id": None}, {"id": "171286556"}, {"id": True}, "aeoess"]
)
def test_a_document_with_no_triggering_actor_id_is_refused(triggering_actor):
    with pytest.raises(ReleaseActorError, match="has no triggering actor id"):
        actor_state.validate_release_run_attempt(
            _context(), _ok(_attempt_document(triggering_actor=triggering_actor))
        )


# ── ordering: nothing reaches the network before the actor is established ─────


def test_an_unauthorized_original_actor_is_refused_before_any_request_is_made():
    with pytest.raises(ReleaseActorError, match="authorized release actor"):
        actor_state.authorize_release_actor(
            env=_env(GITHUB_ACTOR_ID="1"), fetch=_unreachable
        )


def test_a_repository_id_that_is_not_the_pin_is_refused_before_any_request():
    with pytest.raises(ReleaseActorError, match="not the pinned release repository id"):
        actor_state.authorize_release_actor(
            env=_env(GITHUB_REPOSITORY_ID="1161268529"), fetch=_unreachable
        )


def test_a_missing_token_is_refused_before_any_request():
    with pytest.raises(ReleaseActorError, match="GH_TOKEN is required"):
        actor_state.authorize_release_actor(env=_env(GH_TOKEN=""), fetch=_unreachable)


@pytest.mark.parametrize(
    "repository", ["", "agent-passport-python", "a/b/c", "a b/c", "/x"]
)
def test_a_malformed_repository_is_refused(repository):
    with pytest.raises(ReleaseActorError, match="invalid GITHUB_REPOSITORY"):
        actor_state.authorize_release_actor(
            env=_env(GITHUB_REPOSITORY=repository), fetch=_unreachable
        )


def test_a_lookup_that_raises_fails_closed_with_a_bounded_cause():
    # A redirect is how the old address answers after the transfer; the default
    # fetch refuses to follow one, and the failure must surface as a refusal.
    def _raises(url, token):  # noqa: ANN001, ARG001
        raise OSError("refusing to follow redirect to https://example.invalid")

    with pytest.raises(ReleaseActorError) as caught:
        actor_state.authorize_release_actor(env=_env(), fetch=_raises)
    assert "release run attempt lookup failed (OSError: refusing to follow redirect" in str(
        caught.value
    )


def test_a_bounded_cause_does_not_echo_an_unbounded_message():
    def _raises(url, token):  # noqa: ANN001, ARG001
        raise OSError("x" * 500)

    with pytest.raises(ReleaseActorError) as caught:
        actor_state.authorize_release_actor(env=_env(), fetch=_raises)
    assert len(str(caught.value)) < 200


def test_invalid_json_is_refused_rather_than_parsed_as_empty():
    with pytest.raises(ReleaseActorError, match="invalid JSON"):
        actor_state.authorize_release_actor(
            env=_env(), fetch=lambda url, token: (200, "not json")
        )


def test_the_happy_path_asks_for_this_run_attempt_and_accepts_the_requester():
    seen = []

    def _fetch(url, token):  # noqa: ANN001, ARG001
        seen.append(url)
        return 200, json.dumps(_attempt_document())

    principal = actor_state.authorize_release_actor(env=_env(), fetch=_fetch)
    assert principal.triggering_actor_id == actor_state.AUTHORIZED_RELEASE_ACTOR_ID
    assert seen == [
        f"https://api.github.com/repos/agent-passport-system/agent-passport-python"
        f"/actions/runs/{RUN_ID}/attempts/{RUN_ATTEMPT}"
    ]


# ── the tag ruleset ──────────────────────────────────────────────────────────


def _ruleset(**overrides):
    return {
        "name": "immutable-version-tags",
        "target": "tag",
        "enforcement": "active",
        "source": REPOSITORY,
        "conditions": {"ref_name": {"include": ["refs/tags/v*"], "exclude": []}},
        "rules": [
            {"type": "creation"},
            {"type": "update"},
            {"type": "deletion"},
            {"type": "non_fast_forward"},
        ],
        "bypass_actors": [
            {"actor_type": "OrganizationAdmin", "actor_id": None, "bypass_mode": "always"}
        ],
        **overrides,
    }


def test_the_expected_post_transfer_ruleset_is_accepted():
    assert ruleset_state.validate_immutable_version_tag_ruleset(_ruleset()) == {
        "state": "active",
        "bypassVisibility": "visible",
    }


def test_the_current_pre_transfer_user_bypass_is_refused():
    # This is the live ruleset today. GitHub removes an individual user from the
    # bypass list on transfer into an organization, so a release that still saw
    # this shape would mean the transfer had not taken effect.
    with pytest.raises(TagRulesetError, match="release bypass role only"):
        ruleset_state.validate_immutable_version_tag_ruleset(
            _ruleset(
                bypass_actors=[
                    {"actor_id": 171286556, "actor_type": "User", "bypass_mode": "always"}
                ]
            )
        )


def test_an_empty_bypass_list_is_refused():
    # The state the SDK transfer actually produced: the user bypass gone and the
    # organization admin role not yet added, so nobody could create a v* tag.
    with pytest.raises(TagRulesetError, match="exactly one visible bypass actor"):
        ruleset_state.validate_immutable_version_tag_ruleset(_ruleset(bypass_actors=[]))


def test_a_second_bypass_actor_is_refused():
    with pytest.raises(TagRulesetError, match="exactly one visible bypass actor"):
        ruleset_state.validate_immutable_version_tag_ruleset(
            _ruleset(
                bypass_actors=[
                    {"actor_type": "OrganizationAdmin", "bypass_mode": "always"},
                    {"actor_type": "RepositoryRole", "actor_id": 5, "bypass_mode": "always"},
                ]
            )
        )


@pytest.mark.parametrize("mode", ["pull_request", "", None])
def test_a_bypass_mode_other_than_always_is_refused(mode):
    with pytest.raises(TagRulesetError, match="release bypass role only"):
        ruleset_state.validate_immutable_version_tag_ruleset(
            _ruleset(
                bypass_actors=[{"actor_type": "OrganizationAdmin", "bypass_mode": mode}]
            )
        )


def test_the_role_bypass_is_accepted_whatever_actor_id_github_reports():
    # GitHub ignores actor_id for a role bypass, so pinning a value would reject
    # the real ruleset. Any reported value must still be accepted.
    for actor_id in (None, 0, 1, 171286556):
        assert (
            ruleset_state.validate_immutable_version_tag_ruleset(
                _ruleset(
                    bypass_actors=[
                        {
                            "actor_type": "OrganizationAdmin",
                            "actor_id": actor_id,
                            "bypass_mode": "always",
                        }
                    ]
                )
            )["bypassVisibility"]
            == "visible"
        )


def test_a_hidden_bypass_list_is_reported_rather_than_treated_as_empty():
    document = _ruleset()
    del document["bypass_actors"]
    assert ruleset_state.validate_immutable_version_tag_ruleset(document) == {
        "state": "active",
        "bypassVisibility": "not-visible",
    }


def test_an_inactive_or_mistargeted_ruleset_is_refused():
    with pytest.raises(TagRulesetError, match="active enforcement"):
        ruleset_state.validate_immutable_version_tag_ruleset(
            _ruleset(enforcement="disabled")
        )
    with pytest.raises(TagRulesetError, match="active enforcement"):
        ruleset_state.validate_immutable_version_tag_ruleset(_ruleset(target="branch"))


def test_a_ruleset_from_another_repository_is_refused():
    with pytest.raises(TagRulesetError, match="unexpected source"):
        ruleset_state.validate_immutable_version_tag_ruleset(
            _ruleset(source="aeoess/agent-passport-python")
        )


@pytest.mark.parametrize("missing", ["creation", "update", "deletion", "non_fast_forward"])
def test_a_ruleset_missing_any_required_rule_is_refused(missing):
    rules = [r for r in _ruleset()["rules"] if r["type"] != missing]
    with pytest.raises(TagRulesetError, match=f"missing {missing}"):
        ruleset_state.validate_immutable_version_tag_ruleset(_ruleset(rules=rules))


def test_a_ruleset_that_does_not_cover_release_tags_is_refused():
    with pytest.raises(TagRulesetError, match="must include only"):
        ruleset_state.validate_immutable_version_tag_ruleset(
            _ruleset(conditions={"ref_name": {"include": ["refs/tags/*"], "exclude": []}})
        )
    with pytest.raises(TagRulesetError, match="must not exclude release tags"):
        ruleset_state.validate_immutable_version_tag_ruleset(
            _ruleset(
                conditions={
                    "ref_name": {"include": ["refs/tags/v*"], "exclude": ["refs/tags/v9*"]}
                }
            )
        )


@pytest.mark.parametrize("document", [None, "ok", 42, []])
def test_a_non_object_ruleset_is_refused(document):
    with pytest.raises(TagRulesetError, match="is not an object"):
        ruleset_state.validate_immutable_version_tag_ruleset(document)


def test_the_expected_repository_is_the_organization_path():
    assert ruleset_state.EXPECTED_REPOSITORY == "agent-passport-system/agent-passport-python"
