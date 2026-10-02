"""Placement tests for the release guards in publish.yml.

``test_release_actor_state.py`` proves the guards refuse the right things. It
does not prove the guards run. Deleting both "Require the authorized release
actor" steps from ``publish.yml`` leaves all 72 of those cases passing, because
none of them reads a workflow. A guard nobody calls is the same as no guard,
and it is worse at the audit, because the script is still in the tree and still
reviewed.

So these tests assert placement instead of logic. The rule they enforce: every
job that has a protected effect must run the release actor guard, and must run
it before its first protected effect. Protected means an effect that leaves
this repository and cannot be taken back. Publishing to PyPI, uploading with
twine, creating a GitHub release, signing a provenance attestation.

The rule is applied to every workflow file, not to a list of known ones, so a
new workflow that publishes is covered the day it is added.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _workflow_steps import (  # noqa: E402
    Job,
    Workflow,
    parse_workflow,
    read_workflows,
    step_matches,
)

_WORKFLOW_DIR = Path(__file__).resolve().parents[1] / ".github" / "workflows"

# The release workflow is the one every protected effect is expected to live
# in. Named explicitly so that deleting the publish step cannot make the
# placement rule pass by having nothing left to guard.
PUBLISH_WORKFLOW = "publish.yml"

GUARD = re.compile(r"release_actor_state\.py(?![\w.-])")
RULESET_CHECK = re.compile(r"tag_ruleset_state\.py(?![\w.-])")

# Each pattern is matched against the step's whole text with comment lines
# removed, not just against ``run``. A protected effect moved into an action
# input or a different key is still a protected effect.
PROTECTED_EFFECTS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("PyPI publish", re.compile(r"uses:\s*pypa/gh-action-pypi-publish@")),
    ("twine upload", re.compile(r"(?:^|[\s;&|(./])twine\s+upload(?![\w-])", re.M)),
    ("GitHub release creation", re.compile(r"(?:^|[\s;&|(])gh\s+release\s+create(?![\w-])", re.M)),
    ("build provenance attestation", re.compile(r"uses:\s*actions/attest-[\w-]+@")),
)

ACTIONS_READ = re.compile(r"^\s+actions:\s*read\b", re.M)


def _protected_effects_in(step) -> list[str]:
    return [name for name, pattern in PROTECTED_EFFECTS if step_matches(step.text, pattern)]


def _first_step_matching(job: Job, pattern: re.Pattern[str]):
    return next((step for step in job.steps if step_matches(step.text, pattern)), None)


def guard_placement_violations(workflows: list[Workflow]) -> list[str]:
    """The rule, as a function, so the same code runs against the real files and
    against deliberately broken ones."""
    violations: list[str] = []

    for workflow in workflows:
        for job in workflow.jobs:
            protected = [
                (step, effects)
                for step in job.steps
                if (effects := _protected_effects_in(step))
            ]
            if not protected:
                continue

            where = f"{workflow.path} job {job.name}"
            first_step, first_effects = protected[0]
            effect_names = ", ".join(first_effects)
            guard = _first_step_matching(job, GUARD)

            if guard is None:
                violations.append(
                    f"{where} performs {effect_names} at step {first_step.index + 1} "
                    f"(line {first_step.start_line}) and never runs the release actor guard"
                )
                continue

            if guard.index > first_step.index:
                violations.append(
                    f"{where} runs the release actor guard at step {guard.index + 1} "
                    f"(line {guard.start_line}), after {effect_names} at step "
                    f"{first_step.index + 1} (line {first_step.start_line})"
                )

            # The guard reads this run's attempt through the Actions API, so a
            # job that calls it without ``actions: read`` fails closed at
            # release time rather than at review time. Catch it here instead.
            if not ACTIONS_READ.search(job.text):
                violations.append(
                    f"{where} runs the release actor guard without declaring actions: read"
                )

    return violations


def _read() -> list[Workflow]:
    return read_workflows(_WORKFLOW_DIR)


def _publish_workflow() -> Workflow:
    workflow = next((w for w in _read() if w.path == PUBLISH_WORKFLOW), None)
    assert workflow is not None, f"{PUBLISH_WORKFLOW} is missing"
    return workflow


# --- the real files ---------------------------------------------------------


def test_every_publishing_job_guards_before_its_first_protected_effect():
    assert guard_placement_violations(_read()) == []


def test_publish_workflow_still_performs_the_effect_this_rule_covers():
    found = {
        name
        for job in _publish_workflow().jobs
        for step in job.steps
        for name in _protected_effects_in(step)
    }
    assert "PyPI publish" in found, f"{PUBLISH_WORKFLOW} no longer publishes to PyPI"


def test_every_job_in_the_publish_workflow_runs_the_guard():
    """Including ``verify``, which has no protected step of its own.

    ``verify`` is the gate: the tag-to-version check, the ancestry check and the
    full test suite. Running those for an actor who may not release is the wrong
    shape, and leaving the job unguarded means a mutation that removes only this
    guard goes unnoticed.
    """
    workflow = _publish_workflow()
    assert workflow.jobs, f"{PUBLISH_WORKFLOW} declares no jobs"
    for job in workflow.jobs:
        assert _first_step_matching(job, GUARD) is not None, (
            f"{PUBLISH_WORKFLOW} job {job.name} does not run the release actor guard"
        )


def test_the_guard_is_the_first_step_that_is_not_setup():
    """Checkout and language setup may precede it. Nothing else may."""
    setup = re.compile(r"uses:\s*actions/(checkout|setup-python|setup-node)@")
    for job in _publish_workflow().jobs:
        guard = _first_step_matching(job, GUARD)
        assert guard is not None
        for step in job.steps[: guard.index]:
            assert step_matches(step.text, setup), (
                f"{PUBLISH_WORKFLOW} job {job.name} runs step {step.index + 1} "
                f"(line {step.start_line}) before the release actor guard"
            )


def test_the_tag_ruleset_check_gates_the_publishing_job():
    """The publishing job either runs the ruleset check or needs a job that does."""
    workflow = _publish_workflow()
    by_name = {job.name: job for job in workflow.jobs}

    def reaches_check(job: Job, seen: set[str]) -> bool:
        if job.name in seen:
            return False
        seen.add(job.name)
        if _first_step_matching(job, RULESET_CHECK) is not None:
            return True
        return any(
            name in by_name and reaches_check(by_name[name], seen) for name in job.needs
        )

    for job in workflow.jobs:
        if not any(_protected_effects_in(step) for step in job.steps):
            continue
        assert reaches_check(job, set()), (
            f"{PUBLISH_WORKFLOW} job {job.name} publishes without the version-tag "
            "ruleset check running anywhere upstream of it"
        )


def test_the_reader_finds_the_jobs_and_steps_the_real_workflows_declare():
    """A reader that quietly finds no steps would make every rule above pass
    vacuously, so what it reads out of the real files is pinned."""
    by_path = {workflow.path: workflow for workflow in _read()}
    assert sorted(by_path) == [
        "check-drift.yml",
        "cross-impl-jcs.yml",
        "publish.yml",
        "tests.yml",
    ]
    publish = by_path["publish.yml"]
    assert [job.name for job in publish.jobs] == ["verify", "publish"]
    assert len(publish.job("verify").steps) >= 6
    assert len(publish.job("publish").steps) >= 4
    assert publish.job("publish").needs == ("verify",)


# --- the rule biting --------------------------------------------------------
#
# Synthetic rather than mutations of the real file, so the proof lives in the
# suite and does not depend on anyone remembering to run a mutation by hand.

_PUBLISHING_JOB = """
name: Example
on:
  push:
    tags: ["v*"]
jobs:
  publish:
    runs-on: ubuntu-latest
    environment: pypi
    permissions:
      id-token: write
      contents: read
      actions: read
    steps:
      - uses: actions/checkout@v7
      - name: Require the authorized release actor
        run: python .github/scripts/release_actor_state.py
      - name: Publish to PyPI
        uses: pypa/gh-action-pypi-publish@dc37677b2e1c63e2034f94d8a5b11f265b73ba33
        with:
          attestations: true
"""

_GUARD_STEP = """      - name: Require the authorized release actor
        run: python .github/scripts/release_actor_state.py
"""


def test_the_rule_passes_a_job_that_guards_before_publishing():
    assert guard_placement_violations([parse_workflow(_PUBLISHING_JOB, "synthetic.yml")]) == []


def test_the_rule_fails_when_the_guard_step_is_removed():
    mutated = _PUBLISHING_JOB.replace(_GUARD_STEP, "")
    assert mutated != _PUBLISHING_JOB, "mutation did not apply"
    violations = guard_placement_violations([parse_workflow(mutated, "synthetic.yml")])
    assert len(violations) == 1
    assert "never runs the release actor guard" in violations[0]


def test_the_rule_fails_when_the_guard_runs_after_the_publish_step():
    mutated = """
name: Example
on:
  push:
    tags: ["v*"]
jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      actions: read
    steps:
      - uses: actions/checkout@v7
      - name: Publish to PyPI
        uses: pypa/gh-action-pypi-publish@dc37677b2e1c63e2034f94d8a5b11f265b73ba33
      - name: Require the authorized release actor
        run: python .github/scripts/release_actor_state.py
"""
    violations = guard_placement_violations([parse_workflow(mutated, "synthetic.yml")])
    assert len(violations) == 1
    assert "after PyPI publish at step 2" in violations[0]


def test_the_rule_fails_when_the_guarded_job_cannot_read_the_run_attempt():
    mutated = _PUBLISHING_JOB.replace("      actions: read\n", "")
    assert mutated != _PUBLISHING_JOB, "mutation did not apply"
    violations = guard_placement_violations([parse_workflow(mutated, "synthetic.yml")])
    assert len(violations) == 1
    assert "without declaring actions: read" in violations[0]


def test_the_rule_catches_a_twine_upload_added_to_an_unguarded_job():
    mutated = """
name: Example
on:
  workflow_dispatch:
jobs:
  ship:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - name: Upload
        run: twine upload dist/*
"""
    violations = guard_placement_violations([parse_workflow(mutated, "synthetic.yml")])
    assert len(violations) == 1
    assert "twine upload" in violations[0]


def test_a_job_with_no_protected_effect_is_not_required_to_carry_the_guard():
    benign = """
name: Tests
on:
  pull_request:
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - name: Run test suite
        run: python -m pytest -q
"""
    assert guard_placement_violations([parse_workflow(benign, "synthetic.yml")]) == []


def test_a_comment_naming_a_protected_effect_does_not_make_a_step_protected():
    commented = """
name: Example
on:
  push:
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Build distributions
        # Deliberately not a twine upload: the publish job uses the
        # trusted-publishing action so no token is ever materialised.
        run: python -m build
"""
    assert guard_placement_violations([parse_workflow(commented, "synthetic.yml")]) == []


@pytest.mark.parametrize(
    "tricky",
    [
        # A heredoc whose body contains sequence-looking lines must not split
        # the step.
        """
name: Example
on:
  push:
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Scan
        run: |
          cat <<'LIST'
          - not a step
          - also not a step
          LIST
      - name: Second
        run: echo done
""",
    ],
)
def test_the_reader_does_not_split_a_step_on_sequence_lines_inside_a_run_block(tricky):
    job = parse_workflow(tricky, "synthetic.yml").jobs[0]
    assert len(job.steps) == 2
    assert "name: Second" in job.steps[1].text
