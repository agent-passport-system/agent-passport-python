"""A deliberately small reader for GitHub workflow files.

The release guards are only worth what their placement is worth, and the
previous round of tests exercised the guards' logic without ever looking at the
workflow that calls them. Removing both actor-guard steps from ``publish.yml``
left all 72 cases in ``test_release_actor_state.py`` passing. So this module
exists to answer two structural questions, and only those two: which jobs does a
workflow declare, and in what order do a job's steps appear.

It is not a YAML parser and must not grow into one. PyYAML is not in the test
extra, and adding a parser dependency to answer a question this narrow would
widen the dependency surface of a patch whose whole subject is narrowing what
the release pipeline trusts. Everything past job and step boundaries is matched
against the step's raw text, which is the stricter choice here: a protected
effect cannot be hidden from it by moving ``twine upload`` from ``run`` into
some other key.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

_BLOCK_SCALAR_KEY = re.compile(r"^(?:-\s+)?[^#\s][^:]*:\s*[|>][-+]?[0-9]*\s*(?:#.*)?$")
_PLAIN_KEY = re.compile(r"^([A-Za-z_][A-Za-z0-9_.-]*):\s*(.*)$")
_SEQUENCE_ITEM = re.compile(r"^-\s")


def indent_of(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def is_blank(line: str) -> bool:
    return line.strip() == ""


def is_comment(line: str) -> bool:
    return line.lstrip().startswith("#")


def block_scalar_mask(lines: list[str]) -> list[bool]:
    """Mark the lines that belong to a ``|`` or ``>`` scalar body.

    A ``run:`` body can contain anything, including lines that look like keys or
    like sequence items, so those lines are masked out before any boundary is
    looked for.
    """
    mask = [False] * len(lines)
    key_indent = -1

    for i, line in enumerate(lines):
        if key_indent >= 0:
            if is_blank(line) or indent_of(line) > key_indent:
                mask[i] = True
                continue
            key_indent = -1

        if is_blank(line) or is_comment(line):
            continue
        if _BLOCK_SCALAR_KEY.match(line.strip()):
            key_indent = indent_of(line)

    return mask


@dataclass(frozen=True)
class Step:
    index: int
    start_line: int
    text: str


@dataclass(frozen=True)
class Job:
    name: str
    start_line: int
    text: str
    steps: list[Step] = field(default_factory=list)
    needs: tuple[str, ...] = ()
    # The job's own ``continue-on-error``, as written, or None. At job level it
    # makes every step's failure non-fatal, a gate's included.
    continue_on_error: str | None = None


@dataclass(frozen=True)
class Workflow:
    path: str
    triggers: tuple[str, ...]
    jobs: list[Job]

    def job(self, name: str) -> Job | None:
        return next((job for job in self.jobs if job.name == name), None)


class _Document:
    def __init__(self, text: str) -> None:
        self.lines = text.split("\n")
        self.mask = block_scalar_mask(self.lines)

    def structural(self, i: int) -> bool:
        return not self.mask[i] and not is_blank(self.lines[i]) and not is_comment(self.lines[i])

    def block_end(self, start: int, indent: int) -> int:
        for i in range(start + 1, len(self.lines)):
            if not self.structural(i):
                continue
            if indent_of(self.lines[i]) <= indent:
                return i
        return len(self.lines)

    def top_level_key(self, key: str) -> tuple[int, str] | None:
        pattern = re.compile(rf"^{re.escape(key)}:\s*(.*)$")
        for i, line in enumerate(self.lines):
            if not self.structural(i) or indent_of(line) != 0:
                continue
            match = pattern.match(line)
            if match:
                return i, match.group(1).strip()
        return None

    def child_keys(self, start: int, indent: int) -> list[tuple[int, str, str]]:
        end = self.block_end(start, indent)
        child_indent: int | None = None
        found: list[tuple[int, str, str]] = []
        for i in range(start + 1, end):
            if not self.structural(i):
                continue
            line_indent = indent_of(self.lines[i])
            if child_indent is None:
                child_indent = line_indent
            if line_indent != child_indent:
                continue
            match = _PLAIN_KEY.match(self.lines[i].strip())
            if match:
                found.append((i, match.group(1), match.group(2).strip()))
        return found


def _steps_of(doc: _Document, job_start: int, job_end: int, job_indent: int) -> list[Step]:
    steps_line = -1
    for i in range(job_start + 1, job_end):
        if not doc.structural(i):
            continue
        if indent_of(doc.lines[i]) <= job_indent:
            break
        if re.match(r"^steps:\s*(?:#.*)?$", doc.lines[i].strip()):
            steps_line = i
            break
    if steps_line == -1:
        return []

    steps_indent = indent_of(doc.lines[steps_line])
    end = min(job_end, doc.block_end(steps_line, steps_indent))

    dash_indent: int | None = None
    starts: list[int] = []
    for i in range(steps_line + 1, end):
        if not doc.structural(i):
            continue
        if not _SEQUENCE_ITEM.match(doc.lines[i].strip()):
            continue
        line_indent = indent_of(doc.lines[i])
        if dash_indent is None:
            dash_indent = line_indent
        if line_indent == dash_indent:
            starts.append(i)

    steps = []
    for position, start in enumerate(starts):
        stop = starts[position + 1] if position + 1 < len(starts) else end
        steps.append(
            Step(
                index=position,
                start_line=start + 1,  # 1-indexed, to match an editor
                text="\n".join(doc.lines[start:stop]),
            )
        )
    return steps


def _job_field(doc: _Document, job_start: int, job_indent: int, key: str) -> str | None:
    for _, name, value in doc.child_keys(job_start, job_indent):
        if name == key:
            return value
    return None


def _needs_of(doc: _Document, job_start: int, job_end: int, job_indent: int) -> tuple[str, ...]:
    for i in range(job_start + 1, job_end):
        if not doc.structural(i):
            continue
        if indent_of(doc.lines[i]) <= job_indent:
            break
        match = re.match(r"^needs:\s*(.*)$", doc.lines[i].strip())
        if not match:
            continue
        inline = match.group(1).strip()
        if inline.startswith("[") and inline.endswith("]"):
            return tuple(p.strip().strip("\"'") for p in inline[1:-1].split(",") if p.strip())
        if inline:
            return (inline.strip("\"'"),)
        # Block sequence form.
        collected = []
        for j in range(i + 1, job_end):
            if not doc.structural(j):
                continue
            if indent_of(doc.lines[j]) <= indent_of(doc.lines[i]):
                break
            item = re.match(r"^-\s*(.+)$", doc.lines[j].strip())
            if item:
                collected.append(item.group(1).strip().strip("\"'"))
        return tuple(collected)
    return ()


def triggers_of(text: str) -> tuple[str, ...]:
    """The event names a workflow responds to.

    ``on`` is read as written rather than through a loaded document, because a
    YAML 1.1 reader folds the bare key ``on`` to the boolean ``True``.
    """
    doc = _Document(text)
    found = doc.top_level_key("on")
    if found is None:
        return ()
    line, inline = found
    if inline and not inline.startswith("#"):
        stripped = inline.strip("[]")
        return tuple(p.strip() for p in stripped.split(",") if p.strip())
    return tuple(key for _, key, _ in doc.child_keys(line, 0))


def parse_workflow(text: str, path: str = "<workflow>") -> Workflow:
    doc = _Document(text)
    triggers = triggers_of(text)

    found = doc.top_level_key("jobs")
    if found is None:
        return Workflow(path=path, triggers=triggers, jobs=[])

    jobs_line, _ = found
    jobs_end = doc.block_end(jobs_line, 0)

    job_indent: int | None = None
    starts: list[tuple[int, str]] = []
    for i in range(jobs_line + 1, jobs_end):
        if not doc.structural(i):
            continue
        line_indent = indent_of(doc.lines[i])
        if job_indent is None:
            job_indent = line_indent
        if line_indent != job_indent:
            continue
        match = _PLAIN_KEY.match(doc.lines[i].strip())
        if match and match.group(2).strip() == "":
            starts.append((i, match.group(1)))

    jobs = []
    for position, (line, name) in enumerate(starts):
        stop = starts[position + 1][0] if position + 1 < len(starts) else jobs_end
        jobs.append(
            Job(
                name=name,
                start_line=line + 1,
                text="\n".join(doc.lines[line:stop]),
                steps=_steps_of(doc, line, stop, job_indent or 0),
                needs=_needs_of(doc, line, stop, job_indent or 0),
                continue_on_error=_job_field(doc, line, job_indent or 0, "continue-on-error"),
            )
        )

    return Workflow(path=path, triggers=triggers, jobs=jobs)


def effective_text(step_text: str) -> str:
    """A step's text with comment lines removed.

    A comment explaining why a step does not publish is not a publish, and
    treating it as one would make the placement rule fire on prose.
    """
    return "\n".join(line for line in step_text.split("\n") if not is_comment(line))


def step_matches(step_text: str, pattern: re.Pattern[str]) -> bool:
    return bool(pattern.search(effective_text(step_text)))


# --- a step's own keys ------------------------------------------------------
#
# Matching a pattern against a step's raw text answers "is this filename
# mentioned here". It does not answer "does this step run that file, and does its
# failure stop the job", and the two came apart: a guard step with ``if: false``,
# with ``continue-on-error: true``, with its command replaced by ``echo``, or
# with ``|| true`` appended still mentions the filename, and the placement rule
# passed all four. So a step's mapping is read one level deep. One level only.
# Nothing below a step's own keys is interpreted, and this is not a shell parser.


def _step_lines(step_text: str) -> list[str]:
    """The step's lines with the leading ``- `` turned into indentation.

    So the step's first key sits at the same column as the rest, and a ``run: |``
    body on the first line does not mask the keys that follow it.
    """
    lines = step_text.split("\n")
    if lines:
        lines[0] = re.sub(r"^(\s*)-(\s)", r"\1 \2", lines[0])
    return lines


def _block_body(doc: _Document, start: int, indent: int) -> str:
    """The deeper-indented lines following ``start``, dedented, comments dropped."""
    body: list[str] = []
    for i in range(start + 1, len(doc.lines)):
        line = doc.lines[i]
        if doc.structural(i) and indent_of(line) <= indent:
            break
        if is_comment(line):
            continue
        body.append(line)
    while body and is_blank(body[-1]):
        body.pop()
    indents = [indent_of(line) for line in body if not is_blank(line)]
    strip = min(indents) if indents else 0
    return "\n".join(line[strip:] for line in body)


def step_fields(step_text: str) -> dict[str, tuple[str, str]]:
    """A step's own keys, mapped to ``(inline value, block body)``."""
    doc = _Document("\n".join(_step_lines(step_text)))
    key_indent = indent_of(doc.lines[0]) if doc.lines else 0

    fields: dict[str, tuple[str, str]] = {}
    for i, line in enumerate(doc.lines):
        if not doc.structural(i) or indent_of(line) != key_indent:
            continue
        match = _PLAIN_KEY.match(line.strip())
        if match is None or match.group(1) in fields:
            continue
        fields[match.group(1)] = (match.group(2).strip(), _block_body(doc, i, key_indent))
    return fields


def run_command_of(step_text: str) -> str | None:
    """What a step's ``run`` executes: the inline value, or the block scalar body.

    None when the step has no ``run`` at all, which for a gate step is its own
    answer.
    """
    run = step_fields(step_text).get("run")
    if run is None:
        return None
    inline, body = run
    if inline and inline[0] not in "|>":
        return inline
    return body


def commands_in(run_body: str) -> list[str]:
    """The commands a ``run`` body contains, one per line, comments dropped.

    Line granularity is deliberate: enough to tell one canonical invocation from
    an ``echo`` of it or from a second command next to it, and a gate step is
    required to be exactly one line, so nothing finer is needed.
    """
    return [
        line.strip()
        for line in run_body.split("\n")
        if line.strip() and not line.strip().startswith("#")
    ]


def read_workflows(directory: Path) -> list[Workflow]:
    return [
        parse_workflow(path.read_text(encoding="utf-8"), path.name)
        for path in sorted(directory.iterdir())
        if path.suffix in {".yml", ".yaml"}
    ]
