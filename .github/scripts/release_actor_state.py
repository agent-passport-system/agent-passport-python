#!/usr/bin/env python3
"""The release principal guard for the PyPI publish pipeline.

Ported from the SDK's ``.github/scripts/release-actor-state.mjs`` in
``agent-passport-system/agent-passport-system``, which is the reference
implementation for this pipeline. The checks are the same; only the language and
the pinned repository id differ.

Repository ownership is not the release credential, so every privileged job
checks the actor instead of the owner. Two actors matter. ``GITHUB_ACTOR_ID`` is
the actor who started the run, and GitHub keeps it pointing at that original
actor on a rerun. The run attempt's ``triggering_actor`` is whoever asked for
this attempt. Checking only the first would let a rerun of a failed publish job
reuse an earlier attempt's authorization, so both must be the authorized release
actor. Anything that cannot be established is a refusal, never a pass.

This guard carries more weight in the organization than it did under a personal
account. An organization repository cannot name an individual user as a ruleset
bypass actor, so the ``immutable-version-tags`` bypass becomes the organization
admin role and every organization owner can push a release tag past the ruleset.
The ruleset no longer narrows the push to one person. This actor check is what
limits who can run a release, so it must not be loosened to an owner, a role or
a set of ids.
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
from typing import Any, Mapping, NamedTuple

# The actor id rather than the login: a login can be changed or reused, the
# numeric id cannot.
AUTHORIZED_RELEASE_ACTOR_ID = 171286556

# The repository id survives a transfer between owners, so it is the one piece
# of repository identity that a rename or a move cannot change. Pinning it means
# a run against some other repository that happens to carry the expected full
# name cannot satisfy this guard. ``GITHUB_REPOSITORY_ID`` is a documented
# default workflow variable, and the document's ``repository.id`` must agree
# with it and with this pin.
PYTHON_REPOSITORY_ID = 1174743930

_REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_POSITIVE_INTEGER = re.compile(r"^[1-9][0-9]*$")
_BOUNDED_ERROR_LENGTH = 120
_TIMEOUT_SECONDS = 15


class ReleaseActorError(Exception):
    """A refusal. Every path that cannot establish the principal raises this."""


class ReleasePrincipal(NamedTuple):
    repository: str
    repository_id: int
    run_id: int
    run_attempt: int
    triggering_actor_id: int


def _bounded_cause(error: BaseException) -> str:
    message = str(error)
    name = type(error).__name__
    return f"{name}: {message[:_BOUNDED_ERROR_LENGTH]}" if message else name


def _read_run_number(value: object, label: str) -> int:
    if not isinstance(value, str) or not _POSITIVE_INTEGER.match(value):
        raise ReleaseActorError(f"invalid {label}")
    return int(value)


def _is_int(value: object) -> bool:
    # bool is an int subclass in Python and True would otherwise compare equal
    # to 1, so it is excluded explicitly rather than left to coercion.
    return isinstance(value, int) and not isinstance(value, bool)


def validate_original_release_actor(
    actor_id: object,
    *,
    expected_actor_id: int = AUTHORIZED_RELEASE_ACTOR_ID,
) -> int:
    """Refuse unless the actor who started the run is the authorized actor."""
    if (
        not isinstance(actor_id, str)
        or not _POSITIVE_INTEGER.match(actor_id)
        or int(actor_id) != expected_actor_id
    ):
        raise ReleaseActorError(
            "release tags must be pushed by the authorized release actor"
        )
    return expected_actor_id


def validate_release_run_attempt(
    context: Mapping[str, Any],
    response: Mapping[str, Any],
    *,
    expected_actor_id: int = AUTHORIZED_RELEASE_ACTOR_ID,
    expected_repository_id: int = PYTHON_REPOSITORY_ID,
) -> ReleasePrincipal:
    """Refuse unless the run attempt document names this run and its requester."""
    repository = context["repository"]
    repository_id = context["repository_id"]
    run_id = context["run_id"]
    run_attempt = context["run_attempt"]

    status = response.get("status")
    document = response.get("document")

    if status != 200:
        raise ReleaseActorError(
            f"release run attempt lookup returned HTTP {status}; "
            "the requesting release actor is not established"
        )
    if not isinstance(document, dict):
        raise ReleaseActorError(
            "release run attempt lookup returned a non-object document"
        )

    document_repository = document.get("repository")
    if not isinstance(document_repository, dict):
        raise ReleaseActorError(
            "release run attempt document does not name this repository"
        )
    if document_repository.get("full_name") != repository:
        raise ReleaseActorError(
            "release run attempt document does not name this repository"
        )

    document_repository_id = document_repository.get("id")
    if not _is_int(document_repository_id):
        raise ReleaseActorError("release run attempt document has no repository id")
    if document_repository_id != repository_id:
        raise ReleaseActorError(
            "release run attempt document does not name this repository id"
        )
    if document_repository_id != expected_repository_id:
        raise ReleaseActorError(
            "release run attempt document does not name the pinned release repository id"
        )
    if document.get("id") != run_id:
        raise ReleaseActorError("release run attempt document does not name this run")
    if document.get("run_attempt") != run_attempt:
        raise ReleaseActorError(
            "release run attempt document does not name this attempt"
        )

    triggering_actor = document.get("triggering_actor")
    triggering_actor_id = (
        triggering_actor.get("id") if isinstance(triggering_actor, dict) else None
    )
    if not _is_int(triggering_actor_id):
        raise ReleaseActorError(
            "release run attempt document has no triggering actor id"
        )
    if triggering_actor_id != expected_actor_id:
        raise ReleaseActorError(
            "this release attempt must be requested by the authorized release actor"
        )

    return ReleasePrincipal(
        repository=repository,
        repository_id=repository_id,
        run_id=run_id,
        run_attempt=run_attempt,
        triggering_actor_id=triggering_actor_id,
    )


def _default_fetch(url: str, token: str) -> tuple[int | None, str | None]:
    request = urllib.request.Request(
        url,
        headers={
            "accept": "application/vnd.github+json",
            "authorization": f"Bearer {token}",
            "user-agent": "agent-passport-python-release-guard",
            "x-github-api-version": "2022-11-28",
        },
    )

    # A redirect is how the old address answers after a transfer. Following it
    # would authorize a run against whatever it points at, so redirects are
    # refused rather than followed.
    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
            raise urllib.error.HTTPError(
                req.full_url, code, f"refusing to follow redirect to {newurl}", headers, fp
            )

    opener = urllib.request.build_opener(_NoRedirect)
    with opener.open(request, timeout=_TIMEOUT_SECONDS) as response:
        return response.status, response.read().decode("utf-8")


def authorize_release_actor(
    *,
    env: Mapping[str, str] | None = None,
    fetch: Any = None,
    expected_actor_id: int = AUTHORIZED_RELEASE_ACTOR_ID,
    expected_repository_id: int = PYTHON_REPOSITORY_ID,
) -> ReleasePrincipal:
    """Establish the release principal or raise.

    The original-actor check runs first and before any network call, so an
    unauthorized actor never causes a lookup.
    """
    environ = os.environ if env is None else env
    fetch_impl = _default_fetch if fetch is None else fetch

    validate_original_release_actor(
        environ.get("GITHUB_ACTOR_ID"), expected_actor_id=expected_actor_id
    )

    repository = environ.get("GITHUB_REPOSITORY") or ""
    if not _REPOSITORY_PATTERN.match(repository):
        raise ReleaseActorError("invalid GITHUB_REPOSITORY")

    repository_id = _read_run_number(
        environ.get("GITHUB_REPOSITORY_ID"), "GITHUB_REPOSITORY_ID"
    )
    if repository_id != expected_repository_id:
        raise ReleaseActorError(
            "GITHUB_REPOSITORY_ID is not the pinned release repository id"
        )
    run_id = _read_run_number(environ.get("GITHUB_RUN_ID"), "GITHUB_RUN_ID")
    run_attempt = _read_run_number(
        environ.get("GITHUB_RUN_ATTEMPT"), "GITHUB_RUN_ATTEMPT"
    )
    token = environ.get("GH_TOKEN")
    if not token:
        raise ReleaseActorError("GH_TOKEN is required")

    owner, repo = repository.split("/")
    url = (
        f"https://api.github.com/repos/{owner}/{repo}"
        f"/actions/runs/{run_id}/attempts/{run_attempt}"
    )

    try:
        status, body = fetch_impl(url, token)
    except Exception as error:  # noqa: BLE001 - every failure is a refusal
        raise ReleaseActorError(
            f"release run attempt lookup failed ({_bounded_cause(error)})"
        ) from error

    document = None
    if status == 200:
        try:
            document = json.loads(body)
        except (TypeError, ValueError) as error:
            raise ReleaseActorError(
                "release run attempt lookup returned invalid JSON"
            ) from error

    return validate_release_run_attempt(
        {
            "repository": repository,
            "repository_id": repository_id,
            "run_id": run_id,
            "run_attempt": run_attempt,
        },
        {"status": status, "document": document},
        expected_actor_id=expected_actor_id,
        expected_repository_id=expected_repository_id,
    )


def main() -> int:
    try:
        principal = authorize_release_actor()
    except ReleaseActorError as error:
        print(f"::error::{error}", file=sys.stderr)
        return 1
    print(
        f"release principal: the run actor and the actor requesting attempt "
        f"{principal.run_attempt} of run {principal.run_id} in {principal.repository} "
        f"(repository id {principal.repository_id}) are both the authorized release "
        f"actor {principal.triggering_actor_id}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
