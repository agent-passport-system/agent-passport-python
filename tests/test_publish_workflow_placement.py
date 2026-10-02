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

Placement alone was not enough either. The first version of this file looked for
the guard script's filename in the step's text and compared step indices, and a
step can keep the filename while enforcing nothing: ``if: false``,
``continue-on-error: true``, ``run: echo python .github/scripts/...``,
``|| true``. All four passed. So each gate -- both actor guards and the
version-tag ruleset check -- now has to run its actual command, with nothing that
can skip it and nothing that can discard its exit status.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _workflow_steps import (  # noqa: E402
    Job,
    Step,
    Workflow,
    commands_in,
    parse_workflow,
    read_workflows,
    run_command_of,
    step_fields,
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

# --- the gates, and what makes one enforced ---------------------------------
#
# Finding the script's filename in a step proves the filename is there. It does
# not prove the step runs the script, or that the job stops when the script
# refuses. Four ways to keep the filename and lose the gate, all of which the
# first version of this suite accepted: ``if: false`` skips the step,
# ``continue-on-error: true`` lets the job continue past it, replacing the
# command with ``echo`` runs nothing, and ``|| true`` discards the exit status.
# So each gate carries the command it must actually run, and that command is
# required exactly.
#
# ``if:`` is rejected outright rather than analysed. A condition that only
# repeats the job's own trigger would be harmless, but telling that apart from
# one that can be false at release time means evaluating GitHub expressions,
# which is a much larger thing than this reader is. Neither gate step has an
# ``if:``, so requiring none costs nothing and leaves no expression to
# interpret.
# (gate id, the pattern that finds its step, the command it must run)
Gate = tuple[str, re.Pattern[str], str]

GATES: tuple[Gate, ...] = (
    ("release actor guard", GUARD, "python .github/scripts/release_actor_state.py"),
    ("version-tag ruleset check", RULESET_CHECK, "python .github/scripts/tag_ruleset_state.py"),
)

# Shapes that turn a failing command into a passing step. Not a shell parser: a
# fixed list of the ways a one-line gate invocation gets its exit status thrown
# away.
FAILURE_SWALLOWED: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("an || fallback", re.compile(r"\|\|")),
    ("set +e", re.compile(r"(?:^|[\s;&|])set\s+\+[A-Za-z]*e", re.M)),
    ("a trailing true", re.compile(r"(?:^|[;&\n])\s*(?:true|:)\s*$", re.M)),
    ("exit 0", re.compile(r"(?:^|[;&|\n])\s*exit\s+0\b")),
)


def gate_step_violations(where: str, job: Job, gate: Gate, step: Step) -> list[str]:
    """Why this gate step would not stop a release, if it would not."""
    gate_id, _, command = gate
    violations: list[str] = []
    label = (
        f"{where} runs the {gate_id} at step {step.index + 1} "
        f"(line {step.start_line}) but it"
    )
    fields = step_fields(step.text)

    if "if" in fields:
        violations.append(f"{label} carries an if: condition, so the gate can be skipped")

    step_skip = fields.get("continue-on-error")
    if step_skip is not None and step_skip[0] != "false":
        violations.append(
            f"{label} sets continue-on-error: {step_skip[0]}, so its failure does not stop the job"
        )
    if job.continue_on_error is not None and job.continue_on_error != "false":
        violations.append(
            f"{label} sits in a job with continue-on-error: {job.continue_on_error}, "
            "so its failure does not stop the job"
        )

    run = run_command_of(step.text)
    if run is None:
        violations.append(f"{label} has no run command, so it cannot invoke {command}")
        return violations

    swallowed = next((name for name, pattern in FAILURE_SWALLOWED if pattern.search(run)), None)
    commands = commands_in(run)
    if swallowed is not None:
        violations.append(f"{label} discards the gate's exit status with {swallowed}")
    elif commands != [command]:
        violations.append(
            f"{label} does not invoke {command}, it runs: {' ; '.join(commands) or '(nothing)'}"
        )

    return violations


def gate_enforcement_violations(workflows: list[Workflow]) -> list[str]:
    """Every gate step in every workflow, wherever it appears.

    The placement rule below only reaches the gates a publishing job is required
    to carry. This reaches the ones in ``verify``, which has no protected effect
    of its own, where a neutralized gate would otherwise go unread.
    """
    violations: list[str] = []
    for workflow in workflows:
        for job in workflow.jobs:
            where = f"{workflow.path} job {job.name}"
            for gate in GATES:
                for step in job.steps:
                    if not step_matches(step.text, gate[1]):
                        continue
                    violations.extend(gate_step_violations(where, job, gate, step))
    return violations


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

            # Present and early is not the same as enforced. A guard that is
            # skipped, that the job continues past, that runs something other
            # than the script, or whose exit status is discarded leaves the
            # protected steps below it ungated, so the job counts as unguarded
            # here too.
            violations.extend(gate_step_violations(where, job, GATES[0], guard))

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


def ruleset_gate_violations(workflows: list[Workflow]) -> list[str]:
    """Every publishing job runs the ruleset check, or needs a job that does.

    The check has to be an enforced one. A ``tag_ruleset_state.py`` step that is
    skipped, that the job continues past, that runs an ``echo``, or whose exit
    status is discarded does not gate the tag it is there to gate, so it does not
    count as reached.
    """
    violations: list[str] = []

    for workflow in workflows:
        by_name = {job.name: job for job in workflow.jobs}

        def reaches_check(job: Job, seen: set[str], by_name=by_name, workflow=workflow) -> bool:
            if job.name in seen:
                return False
            seen.add(job.name)
            step = _first_step_matching(job, RULESET_CHECK)
            if step is not None and not gate_step_violations(
                f"{workflow.path} job {job.name}", job, GATES[1], step
            ):
                return True
            return any(
                name in by_name and reaches_check(by_name[name], seen) for name in job.needs
            )

        for job in workflow.jobs:
            if not any(_protected_effects_in(step) for step in job.steps):
                continue
            if not reaches_check(job, set()):
                violations.append(
                    f"{workflow.path} job {job.name} publishes without an enforced "
                    "version-tag ruleset check running anywhere upstream of it"
                )

    return violations


def test_the_tag_ruleset_check_gates_the_publishing_job():
    assert ruleset_gate_violations(_read()) == []


def test_every_gate_step_runs_its_command_and_stops_the_job_when_it_fails():
    assert gate_enforcement_violations(_read()) == []


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


# Two jobs, the same shape as publish.yml: the ruleset check sits in a gate job
# with no protected effect of its own, and the publishing job needs it. So a
# neutralized ruleset check has to be caught through that edge, not by finding a
# publish step next to it.
_TWO_JOB_WORKFLOW = """
name: Example
on:
  push:
    tags: ["v*"]
jobs:
  verify:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      actions: read
    steps:
      - uses: actions/checkout@v7
      - name: Require the authorized release actor
        run: python .github/scripts/release_actor_state.py
      - name: Verify version-tag restrictions are active
        run: python .github/scripts/tag_ruleset_state.py
  publish:
    needs: verify
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      actions: read
    steps:
      - uses: actions/checkout@v7
      - name: Require the authorized release actor
        run: python .github/scripts/release_actor_state.py
      - name: Publish to PyPI
        uses: pypa/gh-action-pypi-publish@dc37677b2e1c63e2034f94d8a5b11f265b73ba33
"""

_GUARD_NAME_LINE = "      - name: Require the authorized release actor"
_GUARD_RUN_LINE = "        run: python .github/scripts/release_actor_state.py"
_RULESET_NAME_LINE = "      - name: Verify version-tag restrictions are active"
_RULESET_RUN_LINE = "        run: python .github/scripts/tag_ruleset_state.py"

# (workflow text, the pattern that finds the gate, its name line, its run line,
# the other rules that must reject it once it is neutralized). The case id is on
# the pytest.param.
_GATE_TARGETS = (
    pytest.param(
        (
            _PUBLISHING_JOB,
            GUARD,
            _GUARD_NAME_LINE,
            _GUARD_RUN_LINE,
            (guard_placement_violations,),
        ),
        id="release-actor-guard",
    ),
    pytest.param(
        (
            _TWO_JOB_WORKFLOW,
            RULESET_CHECK,
            _RULESET_NAME_LINE,
            _RULESET_RUN_LINE,
            (ruleset_gate_violations,),
        ),
        id="version-tag-ruleset-check",
    ),
)

# The gate is left in place in every one of these. The filename is still there,
# the step is still first, and the step still refuses when it runs. Each
# mutation takes away one of those words.
_NEUTRALIZERS = (
    pytest.param(
        (
            lambda text, name, run: text.replace(f"{name}\n", f"{name}\n        if: false\n"),
            re.compile(r"carries an if: condition"),
        ),
        id="if-false",
    ),
    pytest.param(
        (
            lambda text, name, run: text.replace(
                f"{name}\n", f"{name}\n        continue-on-error: true\n"
            ),
            re.compile(r"sets continue-on-error: true"),
        ),
        id="continue-on-error-on-the-step",
    ),
    pytest.param(
        (
            lambda text, name, run: text.replace(
                "    runs-on: ubuntu-latest\n",
                "    runs-on: ubuntu-latest\n    continue-on-error: true\n",
                1,
            ),
            re.compile(r"job with continue-on-error: true"),
        ),
        id="continue-on-error-on-the-job",
    ),
    pytest.param(
        (
            lambda text, name, run: text.replace(run, run.replace("run: ", "run: echo ")),
            re.compile(r"does not invoke"),
        ),
        id="echo-in-place-of-the-command",
    ),
    pytest.param(
        (
            lambda text, name, run: text.replace(run, f"{run} || true"),
            re.compile(r"discards the gate's exit status with an \|\| fallback"),
        ),
        id="shell-ignore-failure",
    ),
)


@pytest.mark.parametrize("target", _GATE_TARGETS)
def test_the_rule_passes_a_gate_as_written(target):
    text, _pattern, _name, _run, other_rules = target
    workflow = parse_workflow(text, "synthetic.yml")
    assert gate_enforcement_violations([workflow]) == []
    assert guard_placement_violations([workflow]) == []
    for rule in other_rules:
        assert rule([workflow]) == []


@pytest.mark.parametrize("target", _GATE_TARGETS)
@pytest.mark.parametrize("neutralizer", _NEUTRALIZERS)
def test_the_rule_fails_when_a_gate_keeps_its_filename_but_is_neutralized(target, neutralizer):
    text, pattern, name_line, run_line, other_rules = target
    mutate, expected = neutralizer

    mutated = mutate(text, name_line, run_line)
    assert mutated != text, "mutation did not apply"

    workflow = parse_workflow(mutated, "synthetic.yml")
    # The filename is the only thing the previous version of this rule looked
    # for, so the mutation has to leave it in place to be the case worth testing.
    assert any(
        step_matches(step.text, pattern) for job in workflow.jobs for step in job.steps
    ), "mutation removed the gate instead of neutralizing it"

    enforcement = gate_enforcement_violations([workflow])
    assert any(expected.search(violation) for violation in enforcement), enforcement
    for rule in other_rules:
        assert rule([workflow]), f"{rule.__name__} accepted the neutralized gate"


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
