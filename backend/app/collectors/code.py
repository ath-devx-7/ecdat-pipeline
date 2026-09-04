"""Code collector — SPEC.md §7.1, build step 11.

Semgrep over the approved paths, and only those. Four decisions shape the module.

**Semgrep runs as a subprocess with a local rule file and nothing else.** No
registry ruleset, no metrics, no version check: ``--metrics=off``,
``--disable-version-check`` and the matching environment variables are set on
every invocation, because §1's air-gap rule governs the scan path and a code
scanner that phones home to fetch rules is a network call in the scan path.

**Approved paths are passed explicitly; Semgrep never walks the tree.** The
runner hands the collector exactly the files the user approved, the collector
hands Semgrep exactly those (in batches, because a command line has a length
limit), and ``--no-git-ignore`` keeps a ``.gitignore`` from silently dropping one
of them. Only files with a source-code extension are sent — Semgrep would skip
a certificate anyway, and starting a process to find that out is waste.

**Captured values travel through the message.** Semgrep without a login omits
``metavars`` and ``lines`` from its JSON, but it still interpolates
metavariables into ``message``. So every rule that captures something writes
``ecdat|algorithm=$ALGO`` and the collector parses it. The static half of a
finding — primitive, observation, mode — lives in ``metadata.ecdat`` on the
rule. Matched source text is read back from the approved file for the evidence
record, which is in scope because the file was approved.

**Key material is never copied into a finding.** The hardcoded-key and
high-entropy rules exist to say *that* a secret is in the source, not to move
it into the database. Their evidence carries the line, the length and the
entropy, and a redaction marker where the snippet would be.

Semgrep running out of memory on a file — ``--max-memory`` is set — is reported
in its JSON as an error for that file while the rest of the run completes. The
collector keeps every finding it got and raises :class:`CollectorPartial` so
the scan is ``partial`` and the gap is named. Losing twenty parsed files over the
twenty-first would be the worse outcome.

**The gap between what is scanned and what is ruled on is checked at startup.**
``CODE_EXTENSIONS`` is deliberately wider than the rule file, so a rule added for
a new language needs no code change. The cost is that a ``.rs`` file is sent to
Semgrep, parsed, and matched against nothing — spend with no coverage, and
invisible unless something says so. :func:`validate_rule_coverage` reads the
``languages:`` keys out of the rule file and logs, once per process, every
extension in ``CODE_EXTENSIONS`` no rule stands behind. It warns rather than
raises: the wider list is the design, and an uncovered extension is a gap to see,
not a reason to refuse to start. The same coverage map feeds the per-extension
breakdown the runner records (§2's partial reporting), which is what turns "300
.go files, 0 findings" into "…and no Go rules".
"""

from __future__ import annotations

import json
import logging
import math
import os
import re
import shutil
import subprocess
import sys
from collections import Counter
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, ClassVar

import yaml

from app.collectors.base import (
    Collector,
    CollectorPartial,
    CollectorTimeout,
    RawFinding,
    ScanContext,
)
from app.config import Settings, get_settings
from app.models.enums import CollectorName, Confidence, Primitive, SourceLayer

logger = logging.getLogger(__name__)

__all__ = [
    "CODE_EXTENSIONS",
    "LANGUAGE_EXTENSIONS",
    "CodeCollector",
    "MESSAGE_PREFIX",
    "REDACTED",
    "REDACTED_OBSERVATIONS",
    "SemgrepRun",
    "findings_from_document",
    "is_code_file",
    "parse_message",
    "rule_languages",
    "ruled_extensions",
    "run_semgrep",
    "semgrep_command",
    "shannon_entropy",
    "validate_rule_coverage",
]

#: What is worth starting Semgrep for. Wider than the rule file on purpose — the
#: rest are languages Semgrep parses, kept so a rule added later is applied
#: without touching this list. :func:`validate_rule_coverage` says at startup
#: which of them nothing rules on yet.
CODE_EXTENSIONS = frozenset(
    {
        ".py", ".java", ".c", ".h", ".cc", ".cpp", ".hpp", ".js", ".jsx", ".ts", ".tsx",
        ".go", ".rb", ".php", ".kt", ".kts", ".scala", ".cs", ".rs", ".swift",
    }
)

#: Semgrep ``languages:`` key → the extensions in :data:`CODE_EXTENSIONS` it
#: covers. Both spellings of every key Semgrep accepts are listed, because a
#: rule written ``languages: [javascript]`` covers the same files as one written
#: ``languages: [js]`` and a coverage check that disagreed would report a gap
#: that is not there. ``.h`` belongs to both C and C++ for the same reason
#: Semgrep is ambiguous about it: the extension does not say which.
LANGUAGE_EXTENSIONS: Mapping[str, frozenset[str]] = {
    "python": frozenset({".py"}),
    "py": frozenset({".py"}),
    "java": frozenset({".java"}),
    "c": frozenset({".c", ".h"}),
    "cpp": frozenset({".cc", ".cpp", ".hpp", ".h"}),
    "c++": frozenset({".cc", ".cpp", ".hpp", ".h"}),
    "go": frozenset({".go"}),
    "golang": frozenset({".go"}),
    "js": frozenset({".js", ".jsx"}),
    "javascript": frozenset({".js", ".jsx"}),
    "ts": frozenset({".ts", ".tsx"}),
    "typescript": frozenset({".ts", ".tsx"}),
    "rb": frozenset({".rb"}),
    "ruby": frozenset({".rb"}),
    "php": frozenset({".php"}),
    "kt": frozenset({".kt", ".kts"}),
    "kotlin": frozenset({".kt", ".kts"}),
    "scala": frozenset({".scala"}),
    "cs": frozenset({".cs"}),
    "csharp": frozenset({".cs"}),
    "c#": frozenset({".cs"}),
    "rs": frozenset({".rs"}),
    "rust": frozenset({".rs"}),
    "swift": frozenset({".swift"}),
}

#: Command lines have a length limit — 32 KB on Windows — and 5000 approved
#: files (§2's cap) would exceed it. Targets go to Semgrep in batches.
MAX_BATCH_CHARS = 16_000

#: Rule messages carrying captured values start with this. See the module docstring.
MESSAGE_PREFIX = "ecdat"

#: Observations whose matched text is a secret, and is not stored.
REDACTED_OBSERVATIONS = frozenset({"hardcoded_key", "high_entropy_literal"})
REDACTED = "<redacted: key material is not copied into findings>"

MAX_SNIPPET_CHARS = 240

_BYTES_LITERAL = re.compile(r"=\s*[bB][\"']")


@dataclass(frozen=True, slots=True)
class SemgrepRun:
    """One Semgrep invocation, as the collector sees it."""

    exit_code: int
    document: Mapping[str, Any] | None
    stderr: str
    command: tuple[str, ...]


#: ``(relative_paths, work_dir, settings, timeout_seconds) -> SemgrepRun``. The
#: collector takes one so a test can stand in for the subprocess.
SemgrepRunner = Callable[[Sequence[str], Path, Settings, float], SemgrepRun]


# --------------------------------------------------------------------------- #
# Rule coverage — what is scanned against what is ruled on
# --------------------------------------------------------------------------- #


def rule_languages(rules_path: Path | str) -> set[str]:
    """Every ``languages:`` key in the rule file, lowercased.

    Reads the YAML rather than asking Semgrep, because this runs at startup and
    §1 keeps the scan path — Semgrep included — off the critical path of coming
    up. A rule file that will not parse is not this function's failure to
    report: Semgrep says so, in the collector, with its own error.
    """
    try:
        document = yaml.safe_load(Path(rules_path).read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        logger.warning("code: rule coverage could not be checked: %s", exc)
        return set()
    if not isinstance(document, Mapping):
        return set()

    languages: set[str] = set()
    for rule in document.get("rules") or ():
        if not isinstance(rule, Mapping):
            continue
        declared = rule.get("languages") or rule.get("paths") or ()
        if isinstance(declared, str):
            declared = [declared]
        languages.update(str(language).strip().lower() for language in declared)
    return languages


def ruled_extensions(rules_path: Path | str | None = None) -> frozenset[str]:
    """The extensions in :data:`CODE_EXTENSIONS` some rule actually matches."""
    path = rules_path if rules_path is not None else get_settings().semgrep_rules_path
    covered: set[str] = set()
    for language in rule_languages(path):
        covered.update(LANGUAGE_EXTENSIONS.get(language, ()))
    return frozenset(covered & CODE_EXTENSIONS)


def validate_rule_coverage(rules_path: Path | str | None = None) -> tuple[str, ...]:
    """Name every scanned extension no rule stands behind. Warns; never raises.

    The list being wider than the rules is the design — see the module docstring
    — so this is a visibility control, not a gate. What it buys is that the gap
    is stated once at startup with the extensions spelled out, instead of being
    inferred later from a scan that found nothing in 300 files.
    """
    path = Path(rules_path) if rules_path is not None else get_settings().semgrep_rules_path
    languages = rule_languages(path)
    unknown = sorted(language for language in languages if language not in LANGUAGE_EXTENSIONS)
    covered = ruled_extensions(path)
    uncovered = tuple(sorted(CODE_EXTENSIONS - covered))

    if uncovered:
        logger.warning(
            "code: %d of %d scanned extension(s) have no rule behind them: %s. Files with "
            "these extensions are sent to semgrep, parsed, and matched against nothing. "
            "Rules live in %s; adding a `languages:` key closes the gap with no code change.",
            len(uncovered),
            len(CODE_EXTENSIONS),
            ", ".join(uncovered),
            path,
        )
    else:
        logger.info("code: every scanned extension has a rule behind it")
    if unknown:
        # A language key this map does not know covers nothing as far as the
        # check is concerned, so its rules would look like a gap that is not one.
        logger.warning(
            "code: rule file declares language(s) this build does not map to an extension: %s. "
            "Their rules still run; they just do not count towards coverage.",
            ", ".join(unknown),
        )
    return uncovered


# --------------------------------------------------------------------------- #
# Invocation
# --------------------------------------------------------------------------- #


def semgrep_executable(settings: Settings) -> str:
    """The configured executable, else the one beside this interpreter, else PATH."""
    if settings.semgrep_executable:
        return settings.semgrep_executable
    beside = Path(sys.executable).parent / ("semgrep.exe" if os.name == "nt" else "semgrep")
    if beside.is_file():
        return str(beside)
    found = shutil.which("semgrep")
    if found:
        return found
    raise RuntimeError(
        "semgrep is not installed. It is a backend requirement (requirements.txt); "
        "set ECDAT_SEMGREP_EXECUTABLE to point at one elsewhere."
    )


def semgrep_command(paths: Sequence[str], settings: Settings) -> list[str]:
    """The exact invocation. Local rules, JSON out, no network, memory capped."""
    return [
        semgrep_executable(settings),
        "scan",
        "--config",
        str(settings.semgrep_rules_path),
        "--json",
        "--metrics=off",
        "--disable-version-check",
        "--no-git-ignore",
        "--max-memory",
        str(settings.semgrep_max_memory_mb),
        "--quiet",
        "--",
        *paths,
    ]


def run_semgrep(
    paths: Sequence[str], work_dir: Path, settings: Settings, timeout_seconds: float
) -> SemgrepRun:
    """Run Semgrep over ``paths`` (relative to ``work_dir``) and parse its JSON."""
    command = semgrep_command(paths, settings)
    env = {
        **os.environ,
        "SEMGREP_SEND_METRICS": "off",
        "SEMGREP_ENABLE_VERSION_CHECK": "0",
    }
    try:
        completed = subprocess.run(
            command,
            cwd=str(work_dir),
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        raise CollectorTimeout(
            f"semgrep did not finish within {timeout_seconds:.0f}s over {len(paths)} file(s)"
        ) from exc

    document: Mapping[str, Any] | None = None
    if completed.stdout.strip():
        try:
            loaded = json.loads(completed.stdout)
            document = loaded if isinstance(loaded, Mapping) else None
        except json.JSONDecodeError:
            document = None
    return SemgrepRun(
        exit_code=completed.returncode,
        document=document,
        stderr=completed.stderr,
        command=tuple(command),
    )


# --------------------------------------------------------------------------- #
# The collector
# --------------------------------------------------------------------------- #


def is_code_file(relative: str) -> bool:
    return PurePosixPath(relative).suffix.lower() in CODE_EXTENSIONS


class CodeCollector(Collector):
    """§7.1. ``source_layer: source`` — what was written, not what runs."""

    name: ClassVar[CollectorName] = CollectorName.CODE

    def __init__(self, runner: SemgrepRunner | None = None) -> None:
        self._run = runner or run_semgrep

    def collect(self, ctx: ScanContext) -> list[RawFinding]:
        settings = get_settings()
        targets = [relative for relative, _ in ctx.iter_files() if is_code_file(relative)]
        if not targets:
            return []

        findings: list[RawFinding] = []
        problems: list[str] = []
        for batch in _batches(targets):
            ctx.check_budget("running semgrep")
            remaining = max(1.0, ctx.collector_timeout_seconds - ctx.elapsed_seconds())
            run = self._run(batch, ctx.work_dir, settings, remaining)
            if run.document is None:
                raise RuntimeError(
                    f"semgrep exited {run.exit_code} without JSON output: "
                    f"{_tail(run.stderr) or '(no stderr)'}"
                )
            findings.extend(findings_from_document(run.document, ctx.work_dir))
            problems.extend(_problems(run))

        logger.info(
            "code: semgrep produced %d finding(s) over %d file(s)%s",
            len(findings),
            len(targets),
            f" with {len(problems)} problem(s)" if problems else "",
        )
        if problems:
            shown = "; ".join(problems[:5])
            if len(problems) > 5:
                shown += f"; and {len(problems) - 5} more"
            raise CollectorPartial(findings, f"semgrep reported {shown}")
        return findings


def _batches(paths: Sequence[str]) -> Iterator[list[str]]:
    batch: list[str] = []
    size = 0
    for path in paths:
        if batch and size + len(path) + 1 > MAX_BATCH_CHARS:
            yield batch
            batch, size = [], 0
        batch.append(path)
        size += len(path) + 1
    if batch:
        yield batch


def _problems(run: SemgrepRun) -> list[str]:
    """What kept this run from being complete. Out-of-memory lands here."""
    problems: list[str] = []
    assert run.document is not None
    for error in run.document.get("errors") or ():
        if not isinstance(error, Mapping):
            continue
        kind = str(error.get("type") or "error")
        where = error.get("path")
        message = str(error.get("message") or "").strip().splitlines()[:1]
        detail = f" ({message[0][:120]})" if message else ""
        problems.append(f"{kind}{f' at {_posix(str(where))}' if where else ''}{detail}")
    if run.exit_code != 0:
        problems.append(f"exit code {run.exit_code}{': ' + _tail(run.stderr) if run.stderr.strip() else ''}")
    return problems


def _tail(text: str, limit: int = 200) -> str:
    text = text.strip()
    return text[-limit:] if len(text) > limit else text


# --------------------------------------------------------------------------- #
# Result → findings
# --------------------------------------------------------------------------- #


def parse_message(message: str) -> dict[str, str]:
    """``ecdat|algorithm=AES|key_size=1024`` → ``{"algorithm": "AES", "key_size": "1024"}``.

    ``literal`` is always the last field and swallows the rest of the message,
    because a string literal can contain the separator.
    """
    if not message.startswith(MESSAGE_PREFIX):
        return {}
    fields: dict[str, str] = {}
    tokens = message.split("|")[1:]
    for index, token in enumerate(tokens):
        key, separator, value = token.partition("=")
        if not separator:
            continue
        key = key.strip()
        if key == "literal":
            fields[key] = _unquote("|".join([value, *tokens[index + 1 :]]))
            break
        fields[key] = _unquote(value.strip())
    return fields


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def shannon_entropy(text: str) -> float:
    """Bits per character. The shape of a credential, and nothing more (§7.1)."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def _rule_id(check_id: str) -> str:
    """Semgrep prefixes the id with the rule file's path; keep the part we wrote."""
    index = check_id.find(f"{MESSAGE_PREFIX}.")
    return check_id[index:] if index >= 0 else check_id


def _posix(path: str) -> str:
    return path.replace("\\", "/")


class _Sources:
    """Lines of the approved files a batch matched, read once each."""

    def __init__(self, work_dir: Path) -> None:
        self._work_dir = work_dir
        self._lines: dict[str, list[str]] = {}

    def lines(self, relative: str, start: int, end: int) -> str:
        if relative not in self._lines:
            try:
                text = (self._work_dir / relative).read_text(encoding="utf-8", errors="replace")
            except OSError:
                text = ""
            self._lines[relative] = text.splitlines()
        lines = self._lines[relative]
        snippet = "\n".join(lines[max(start, 1) - 1 : max(end, start)])
        return snippet[:MAX_SNIPPET_CHARS]


def findings_from_document(document: Mapping[str, Any], work_dir: Path) -> list[RawFinding]:
    """Every result from one of our rules, as a :class:`RawFinding`."""
    sources = _Sources(work_dir)
    findings: list[RawFinding] = []
    for result in document.get("results") or ():
        if not isinstance(result, Mapping):
            continue
        extra = result.get("extra") or {}
        meta = (extra.get("metadata") or {}).get("ecdat")
        if not isinstance(meta, Mapping):
            # Not one of ours. Nothing in this collector guesses what a rule
            # from somewhere else meant.
            continue
        finding = _finding_for(result, extra, meta, sources, str(document.get("version") or ""))
        if finding is not None:
            findings.append(finding)
    return findings


def _finding_for(
    result: Mapping[str, Any],
    extra: Mapping[str, Any],
    meta: Mapping[str, Any],
    sources: _Sources,
    semgrep_version: str,
) -> RawFinding | None:
    path = _posix(str(result.get("path") or ""))
    start = int((result.get("start") or {}).get("line") or 0)
    end = int((result.get("end") or {}).get("line") or start)
    rule_id = _rule_id(str(result.get("check_id") or ""))
    observation = str(meta.get("observation") or "semgrep_match")
    fields = parse_message(str(extra.get("message") or ""))
    snippet = sources.lines(path, start, end)

    evidence: dict[str, Any] = {
        "file": path,
        "line": start,
        "end_line": end,
        "rule_id": rule_id,
        "observation": observation,
        "semgrep_version": semgrep_version,
        "matched": REDACTED if observation in REDACTED_OBSERVATIONS else snippet,
    }

    # The entropy post-filter. The literal itself is used here and dropped.
    if "literal" in fields:
        literal = fields.pop("literal")
        if _BYTES_LITERAL.search(snippet):
            # A byte literal is key material, and the hardcoded-key rules own it.
            return None
        entropy = shannon_entropy(literal)
        if len(literal) < int(meta.get("min_length", 0)) or entropy < float(
            meta.get("min_entropy", 0)
        ):
            return None
        evidence["literal_length"] = len(literal)
        evidence["shannon_entropy"] = round(entropy, 3)

    algorithm = meta.get("algorithm")
    mode = meta.get("mode")
    if algorithm is None and "algorithm" in fields:
        algorithm = f"{meta.get('algorithm_prefix', '')}{fields['algorithm']}"
    transformation = fields.get("transformation")
    if transformation:
        # Java's "ALG/MODE/PADDING". The algorithm and the mode are two facts
        # about one call; the padding is recorded and not interpreted.
        parts = transformation.split("/")
        algorithm = parts[0]
        if len(parts) > 1 and not mode:
            mode = parts[1].upper()
        evidence["transformation"] = transformation
    if not algorithm:
        logger.warning("code: rule %s produced no algorithm for %s:%d; skipped", rule_id, path, start)
        return None

    for key, value in fields.items():
        if key not in ("algorithm", "transformation", "key_size"):
            evidence[key] = value

    key_size: int | None = None
    if "key_size" in fields:
        try:
            key_size = int(fields["key_size"])
        except ValueError:
            evidence["key_size_text"] = fields["key_size"]

    try:
        primitive = Primitive(str(meta.get("primitive")))
    except ValueError:
        primitive = Primitive.UNKNOWN
    confidence: Confidence | None = None
    if meta.get("confidence"):
        try:
            confidence = Confidence(str(meta["confidence"]))
        except ValueError:
            confidence = None

    return RawFinding(
        collector=CollectorName.CODE,
        algorithm_name=str(algorithm),
        source_layer=SourceLayer.SOURCE,
        confidence=confidence,
        primitive=primitive,
        key_size=key_size,
        mode=str(mode).upper() if mode else None,
        evidence_location=f"{path}:{start}",
        evidence_raw=evidence,
    )
