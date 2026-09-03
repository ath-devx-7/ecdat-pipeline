"""Config collector — SPEC.md §7.4.

Four format-specific parsers over four file kinds, found by *name pattern
anywhere in the approved tree* rather than at a fixed path, because a config
file's location is a packaging accident and its name is not.

Everything here is tagged ``source_layer: config``, and that tag carries the
entire weight of §9. A config file is a **claim** about what a service will
negotiate. It is not evidence that the service does. ``confidence: high`` here
means "we read the declaration correctly", never "the declaration is true" —
finding out whether it is true takes a handshake (§7.5), and comparing the two
is the drift check this project exists to do.

Two parsing decisions worth stating up front:

**Positive declarations are enumerated; negative ones are not.** An nginx
``ssl_ciphers`` line names suites the server will offer, so each suite becomes a
finding. A ``jdk.tls.disabledAlgorithms`` line names algorithms the JVM will
*refuse*, so it becomes one finding about the declaration. Splitting a disabled
list into per-algorithm findings would report the absence of a use as a use, and
would land ``RC4`` on a dashboard for a host that has just switched it off.

**Selection keywords are not algorithms.** OpenSSL cipher strings mix concrete
suite names with selector words (``HIGH``, ``@SECLEVEL=0``). Only concrete names
become findings; the rest are recorded as evidence. ``HIGH`` is not an algorithm
and a row claiming it is would be noise a user has to learn to ignore.
"""

from __future__ import annotations

import configparser
import logging
import re
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any, Callable, ClassVar

import crossplane

from app.collectors.base import Collector, RawFinding, ScanContext
from app.models.enums import CollectorName, Confidence, Primitive, SourceLayer

logger = logging.getLogger(__name__)

__all__ = ["ConfigCollector"]

#: Config files can be large (a generated nginx.conf, a vendored java.security).
#: Past this they are skipped rather than parsed — no config a human wrote is
#: this big, and the parsers all hold the file in memory.
MAX_CONFIG_BYTES = 2 * 1024 * 1024

#: Observation names for declarations that are not algorithm uses. As in the
#: certificate collector, the policy pack is where these become ``hygiene``
#: verdicts (§10) — the collector only reports what the file says.
OBS_NO_SERVER_CIPHER_PREFERENCE = "tls-no-server-cipher-preference"
OBS_CERTIFICATE_PATH = "tls-certificate-path"
OBS_PRIVATE_KEY_PATH = "tls-private-key-path"


class ConfigCollector(Collector):
    """§7.4. Four parsers, one collector, ``source_layer: config`` throughout."""

    name: ClassVar[CollectorName] = CollectorName.CONFIG

    def collect(self, ctx: ScanContext) -> list[RawFinding]:
        findings: list[RawFinding] = []
        for relative, absolute in ctx.iter_files():
            ctx.check_budget(f"parsing {relative}")
            parser = _parser_for(relative)
            if parser is None:
                continue
            try:
                if absolute.stat().st_size > MAX_CONFIG_BYTES:
                    logger.info("config: %s is over the parse cap; skipped", relative)
                    continue
            except OSError:
                continue
            try:
                findings.extend(parser(relative, absolute))
            except Exception as exc:  # noqa: BLE001 - one bad file, not a dead scan
                # A malformed config is the user's problem to see, not a reason
                # to lose the other twenty files. The scan still completes; the
                # runner only marks it partial if the collector itself dies.
                logger.warning("config: %s could not be parsed: %s", relative, exc)
        return findings


# --------------------------------------------------------------------------- #
# Dispatch — by name pattern, anywhere in the tree
# --------------------------------------------------------------------------- #


def _is_openssl_cnf(name: str) -> bool:
    return "openssl" in name and name.endswith((".cnf", ".conf"))


def _is_nginx_conf(name: str) -> bool:
    return "nginx" in name and name.endswith(".conf")


def _is_sshd_config(name: str) -> bool:
    return name.endswith("sshd_config")


def _is_java_security(name: str) -> bool:
    return name == "java.security" or name.endswith(".java.security")


def _parser_for(relative: str) -> Callable[[str, Path], list[RawFinding]] | None:
    """Pick a parser from the file's basename. Order matters only in that it is fixed."""
    name = relative.rsplit("/", 1)[-1].lower()
    for matches, parse in (
        (_is_openssl_cnf, parse_openssl_cnf),
        (_is_nginx_conf, parse_nginx_conf),
        (_is_sshd_config, parse_sshd_config),
        (_is_java_security, parse_java_security),
    ):
        if matches(name):
            return parse
    return None


# --------------------------------------------------------------------------- #
# Shared: cipher lists
# --------------------------------------------------------------------------- #

#: A concrete OpenSSL suite name is hyphenated (``ECDHE-RSA-AES128-GCM-SHA256``,
#: ``DES-CBC3-SHA``); a TLS 1.3 suite starts with ``TLS_``. Selector keywords
#: (``HIGH``, ``DEFAULT``, ``aNULL``) are single words, and modifiers carry a
#: ``! - + @`` prefix. The test is deliberately conservative: a token is called a
#: suite only when it is shaped like one, and everything else is kept as evidence
#: rather than reported as a use.
_SUITE_SHAPED = re.compile(r"^(?:TLS_[A-Z0-9_]+|[A-Za-z0-9]+(?:-[A-Za-z0-9]+)+)$")


def _split_cipher_list(value: str, separators: str = ":,") -> tuple[list[str], list[str]]:
    """Split an OpenSSL-style cipher string into ``(concrete suites, control tokens)``."""
    pattern = f"[{re.escape(separators)}\\s]+"
    suites: list[str] = []
    controls: list[str] = []
    for token in re.split(pattern, value.strip().strip("'\"")):
        if not token:
            continue
        if token[0] in "!-+@" or not _SUITE_SHAPED.match(token):
            controls.append(token)
        else:
            suites.append(token)
    return suites, controls


def _cipher_list_findings(
    relative: str,
    line: int | None,
    key: str,
    value: str,
    context: dict[str, Any],
    separators: str = ":,",
) -> list[RawFinding]:
    """One finding per declared suite; one for the declaration when it names none.

    ``CipherString = DEFAULT@SECLEVEL=2`` is all selectors and no suites, and
    dropping it would silently lose a declaration the report should carry — so
    the declaration itself becomes the finding in that case.
    """
    suites, controls = _split_cipher_list(value, separators)
    location = _location(relative, line)
    shared = {
        **context,
        "file": relative,
        "key": key,
        "declared": value,
        "control_tokens": controls,
    }

    if not suites:
        return [
            RawFinding(
                collector=CollectorName.CONFIG,
                algorithm_name=key,
                source_layer=SourceLayer.CONFIG,
                confidence=Confidence.HIGH,
                evidence_location=location,
                evidence_raw={**shared, "observation": "cipher_selection_declared"},
            )
        ]

    return [
        RawFinding(
            collector=CollectorName.CONFIG,
            algorithm_name=suite,
            source_layer=SourceLayer.CONFIG,
            confidence=Confidence.HIGH,
            primitive=Primitive.CIPHER,
            evidence_location=location,
            evidence_raw={
                **shared,
                "observation": "cipher_suite_declared",
                "suite": suite,
            },
        )
        for suite in suites
    ]


def _location(relative: str, line: int | None) -> str:
    return relative if line is None else f"{relative}:{line}"


def _read_text(absolute: Path) -> str:
    """Configs are ASCII in practice; a stray byte must not lose the whole file."""
    return absolute.read_text(encoding="utf-8", errors="replace")


# --------------------------------------------------------------------------- #
# openssl.cnf
# --------------------------------------------------------------------------- #

_OPENSSL_PROTOCOL_KEYS = {"minprotocol": "protocol_floor", "maxprotocol": "protocol_ceiling"}
_OPENSSL_CIPHER_KEYS = {"cipherstring", "ciphersuites"}
_GLOBAL_SECTION = "__global__"


def parse_openssl_cnf(relative: str, absolute: Path) -> list[RawFinding]:
    """``MinProtocol``, ``MaxProtocol``, ``CipherString``, ``Ciphersuites`` (§7.4).

    One observation beyond the four keys is recorded, and it is a fact rather
    than a judgement: whether the file carries a top-level ``openssl_conf``
    pointer. Without it OpenSSL never applies the ``system_default`` section, so
    the hardening in the file is inert — which is exactly the situation the demo
    environment reproduces. It is recorded in evidence and changes nothing else:
    the declaration is still reported, because §9 needs the claim in order to
    compare it against the handshake, and deciding whether an inert declaration
    is an oversight or a leftover is the user's call (§9 rule 4).
    """
    text = _read_text(absolute)
    values = _parse_openssl_sections(text, relative)
    lines = text.splitlines()
    activated = any(
        key.strip().lower() == "openssl_conf"
        for section, key, _ in _iter_ini_assignments(lines)
        if section == _GLOBAL_SECTION
    )
    context = {"activated_by_openssl_conf": activated}

    findings: list[RawFinding] = []
    for section, key, value in values:
        lowered = key.lower()
        line = _find_ini_line(lines, section, key)
        if lowered in _OPENSSL_PROTOCOL_KEYS:
            findings.append(
                RawFinding(
                    collector=CollectorName.CONFIG,
                    # As observed. Collapsing "TLSv1.2" and "TLS 1.2" onto one
                    # identity is the normalizer's job (§8), not this file's.
                    algorithm_name=value,
                    source_layer=SourceLayer.CONFIG,
                    confidence=Confidence.HIGH,
                    primitive=Primitive.PROTOCOL,
                    protocol_version=value,
                    evidence_location=_location(relative, line),
                    evidence_raw={
                        **context,
                        "file": relative,
                        "section": section,
                        "key": key,
                        "declared": value,
                        "observation": _OPENSSL_PROTOCOL_KEYS[lowered],
                    },
                )
            )
        elif lowered in _OPENSSL_CIPHER_KEYS:
            findings.extend(
                _cipher_list_findings(
                    relative, line, key, value, {**context, "section": section}
                )
            )
    return findings


def _parse_openssl_sections(text: str, relative: str) -> list[tuple[str, str, str]]:
    """``(section, key, value)`` triples, via configparser as §7.4 suggests.

    Two adjustments to make it swallow real openssl.cnf files: a synthetic global
    section, because ``openssl_conf = default_conf`` legitimately sits above the
    first header, and interpolation off, because ``$dir/certs`` is openssl syntax
    and not a Python format string.
    """
    parser = configparser.ConfigParser(
        interpolation=None, strict=False, delimiters=("=",), allow_no_value=True
    )
    parser.optionxform = str  # openssl keys are read case-sensitively elsewhere
    try:
        parser.read_string(f"[{_GLOBAL_SECTION}]\n" + text, source=relative)
    except configparser.Error as exc:
        logger.warning("config: %s is not readable as an openssl.cnf: %s", relative, exc)
        return []

    triples: list[tuple[str, str, str]] = []
    for section in parser.sections():
        for key, value in parser.items(section):
            if value is None:
                continue
            # Section headers are commonly written "[ ssl_sect ]".
            triples.append((section.strip(), key.strip(), value.strip()))
    return triples


def _iter_ini_assignments(lines: list[str]) -> Iterator[tuple[str, str, int]]:
    """Walk raw lines yielding ``(section, key, line_number)``.

    configparser gives values but not positions, and ``evidence_location`` is a
    ``path:line``. Re-walking the text is cheaper than a second real parser.
    """
    section = _GLOBAL_SECTION
    for number, raw in enumerate(lines, start=1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
            continue
        if "=" in line:
            yield section, line.split("=", 1)[0].strip(), number


def _find_ini_line(lines: list[str], section: str, key: str) -> int | None:
    for found_section, found_key, number in _iter_ini_assignments(lines):
        if found_section == section and found_key.lower() == key.lower():
            return number
    return None


# --------------------------------------------------------------------------- #
# nginx.conf
# --------------------------------------------------------------------------- #


def parse_nginx_conf(relative: str, absolute: Path) -> list[RawFinding]:
    """``ssl_protocols``, ``ssl_ciphers``, ``ssl_certificate*`` (§7.4), via crossplane.

    ``single=True`` is a scope control, not a performance choice: crossplane
    follows ``include`` directives by default, and an include would open a file
    the user never approved. Everything this collector reads has to come through
    the approved list, so includes are left alone — an included file that *is*
    approved is parsed on its own turn.

    ``ssl_prefer_server_ciphers`` and ``ssl_conf_command Ciphersuites`` are read
    beyond §7.4's key list because the demo environment expects both: TLS 1.3
    suites are declared through the second and nowhere else. ``ssl_ecdh_curve``
    is deliberately *not* read — it is a curve list rather than a protocol, suite
    or certificate path, so it sits outside what §7.4 asks for, and the live
    probe (§7.5) observes the negotiated group directly.
    """
    payload = crossplane.parse(str(absolute), single=True, catch_errors=True)
    findings: list[RawFinding] = []
    for document in payload.get("config", []):
        for error in document.get("errors", []):
            logger.info("config: %s: %s", relative, error.get("error"))
        for directive in _walk_nginx(document.get("parsed", []), server=None):
            findings.extend(_nginx_directive_findings(relative, directive))
    return findings


class _NginxDirective:
    """A directive plus the ``server`` block it was found in."""

    __slots__ = ("args", "line", "name", "server")

    def __init__(self, name: str, args: list[str], line: int, server: dict[str, Any] | None):
        self.name = name
        self.args = args
        self.line = line
        self.server = server


def _walk_nginx(block: Iterable[dict[str, Any]], server: dict[str, Any] | None) -> Iterator[_NginxDirective]:
    """Depth-first walk carrying the enclosing ``server`` block's identity down.

    That identity — the ports it listens on and the names it answers to — is what
    step 8 joins a probe target against. §9 requires the join to come from the
    user's declared target and the config's own ``listen`` line, never from
    guessing, so it has to be recorded here where it is unambiguous.
    """
    for entry in block:
        name = entry.get("directive")
        args = list(entry.get("args") or [])
        line = entry.get("line")
        children = entry.get("block")

        if name == "server" and children is not None:
            yield from _walk_nginx(children, server=_server_identity(children))
            continue

        if name is not None:
            yield _NginxDirective(name, args, line, server)
        if children:
            yield from _walk_nginx(children, server=server)


def _server_identity(block: Iterable[dict[str, Any]]) -> dict[str, Any]:
    listens: list[str] = []
    ports: list[int] = []
    names: list[str] = []
    for entry in block:
        if entry.get("directive") == "listen":
            args = list(entry.get("args") or [])
            listens.append(" ".join(args))
            port = _listen_port(args)
            if port is not None:
                ports.append(port)
        elif entry.get("directive") == "server_name":
            names.extend(entry.get("args") or [])
    return {"listen": listens, "ports": ports, "server_names": names}


def _listen_port(args: list[str]) -> int | None:
    """``8443``, ``0.0.0.0:8443``, ``[::]:8443 ssl`` — the port is the last colon field."""
    if not args:
        return None
    candidate = args[0].rsplit(":", 1)[-1]
    return int(candidate) if candidate.isdigit() else None


def _nginx_directive_findings(relative: str, directive: _NginxDirective) -> list[RawFinding]:
    context = {"directive": directive.name, "args": directive.args, "server": directive.server}
    location = _location(relative, directive.line)

    if directive.name == "ssl_protocols":
        # One finding per declared version: §9 flags diverging usage sites, and a
        # single row covering three versions cannot be diverged from in part.
        return [
            RawFinding(
                collector=CollectorName.CONFIG,
                algorithm_name=version,
                source_layer=SourceLayer.CONFIG,
                confidence=Confidence.HIGH,
                primitive=Primitive.PROTOCOL,
                protocol_version=version,
                evidence_location=location,
                evidence_raw={
                    **context,
                    "file": relative,
                    "observation": "protocol_version_declared",
                    "declared": version,
                },
            )
            for version in directive.args
        ]

    if directive.name == "ssl_ciphers":
        return _cipher_list_findings(
            relative, directive.line, "ssl_ciphers", " ".join(directive.args), context
        )

    if directive.name == "ssl_conf_command" and len(directive.args) >= 2:
        if directive.args[0].lower() in ("ciphersuites", "cipherstring"):
            return _cipher_list_findings(
                relative,
                directive.line,
                f"ssl_conf_command {directive.args[0]}",
                " ".join(directive.args[1:]),
                context,
            )
        return []

    if directive.name in ("ssl_certificate", "ssl_certificate_key"):
        is_key = directive.name.endswith("_key")
        return [
            RawFinding(
                collector=CollectorName.CONFIG,
                algorithm_name=OBS_PRIVATE_KEY_PATH if is_key else OBS_CERTIFICATE_PATH,
                source_layer=SourceLayer.CONFIG,
                confidence=Confidence.HIGH,
                evidence_location=location,
                evidence_raw={
                    **context,
                    "file": relative,
                    "observation": "key_path_declared" if is_key else "certificate_path_declared",
                    # The path as declared. It points into the deployed
                    # filesystem, not into the scan tree, and nothing here
                    # follows it — that would be reading outside the approval.
                    "declared_path": directive.args[0] if directive.args else None,
                },
            )
        ]

    if directive.name == "ssl_prefer_server_ciphers":
        # Only the "off" case is reported. "on" is the expected setting, and a
        # finding for every correctly configured host is noise that trains people
        # to skim the list.
        if not directive.args or directive.args[0].lower() != "off":
            return []
        return [
            RawFinding(
                collector=CollectorName.CONFIG,
                algorithm_name=OBS_NO_SERVER_CIPHER_PREFERENCE,
                source_layer=SourceLayer.CONFIG,
                confidence=Confidence.HIGH,
                evidence_location=location,
                evidence_raw={
                    **context,
                    "file": relative,
                    "observation": "server_cipher_preference_disabled",
                },
            )
        ]

    return []


# --------------------------------------------------------------------------- #
# sshd_config
# --------------------------------------------------------------------------- #

#: Each key names a primitive outright — that is what the directive *means*, so
#: recording it is observation rather than inference.
_SSHD_KEYS: dict[str, tuple[Primitive, str]] = {
    "ciphers": (Primitive.CIPHER, "ssh_cipher_declared"),
    "kexalgorithms": (Primitive.KEY_EXCHANGE, "ssh_kex_declared"),
    "macs": (Primitive.HASH, "ssh_mac_declared"),
    "hostkeyalgorithms": (Primitive.SIGNATURE, "ssh_host_key_algorithm_declared"),
}

#: OpenSSH list modifiers: ``+`` appends to the default, ``-`` removes from it,
#: ``^`` moves to the front. Kept as evidence — with ``-`` the line declares what
#: the host will *not* offer, which is the negative case this file's docstring
#: says not to enumerate.
_SSHD_MODIFIERS = "+-^"


def parse_sshd_config(relative: str, absolute: Path) -> list[RawFinding]:
    """``Ciphers``, ``KexAlgorithms``, ``MACs``, ``HostKeyAlgorithms`` (§7.4).

    Plain ``key value`` lines. ``Match`` blocks scope later directives to a subset
    of connections; they are not tracked here, so a directive inside one is
    reported as declared with its ``Match`` context left unrecorded. Worth knowing
    before trusting the location: the declaration is real, its scope is narrower
    than the file suggests.
    """
    findings: list[RawFinding] = []
    for number, raw in enumerate(_read_text(absolute).splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.replace("=", " ", 1).split(None, 1)
        if len(parts) != 2:
            continue
        key, value = parts[0].strip(), parts[1].strip()
        entry = _SSHD_KEYS.get(key.lower())
        if entry is None:
            continue
        primitive, observation = entry

        modifier = value[0] if value[:1] in _SSHD_MODIFIERS else None
        tokens = [token for token in re.split(r"[,\s]+", value.lstrip(_SSHD_MODIFIERS)) if token]
        if modifier == "-":
            # A removal list is a declaration of what is switched off. One
            # finding for the declaration, not one per algorithm.
            findings.append(
                RawFinding(
                    collector=CollectorName.CONFIG,
                    algorithm_name=key,
                    source_layer=SourceLayer.CONFIG,
                    confidence=Confidence.HIGH,
                    evidence_location=_location(relative, number),
                    evidence_raw={
                        "file": relative,
                        "key": key,
                        "declared": value,
                        "modifier": modifier,
                        "entries": tokens,
                        "observation": "ssh_algorithms_removed",
                    },
                )
            )
            continue

        findings.extend(
            RawFinding(
                collector=CollectorName.CONFIG,
                algorithm_name=token,
                source_layer=SourceLayer.CONFIG,
                confidence=Confidence.HIGH,
                primitive=primitive,
                evidence_location=_location(relative, number),
                evidence_raw={
                    "file": relative,
                    "key": key,
                    "declared": value,
                    "modifier": modifier,
                    "observation": observation,
                },
            )
            for token in tokens
        )
    return findings


# --------------------------------------------------------------------------- #
# java.security
# --------------------------------------------------------------------------- #

_JAVA_SECURITY_KEYS = ("jdk.tls.disabledalgorithms", "jdk.certpath.disabledalgorithms")


def parse_java_security(relative: str, absolute: Path) -> list[RawFinding]:
    """``jdk.tls.disabledAlgorithms`` and ``jdk.certpath.disabledAlgorithms`` (§7.4).

    One finding per property, never one per entry. These lists say what the JVM
    will *refuse*; enumerating them would put ``RC4`` on the dashboard for a host
    that has just disabled it. What the file declares — and, by omission, what it
    permits — is a single observation about the property, with the parsed entries
    kept as evidence so a reader can see what is missing from the list.
    """
    findings: list[RawFinding] = []
    for key, value, number in _java_properties(_read_text(absolute)):
        if key.lower() not in _JAVA_SECURITY_KEYS:
            continue
        entries = [entry.strip() for entry in value.split(",") if entry.strip()]
        findings.append(
            RawFinding(
                collector=CollectorName.CONFIG,
                algorithm_name=key,
                source_layer=SourceLayer.CONFIG,
                confidence=Confidence.HIGH,
                evidence_location=_location(relative, number),
                evidence_raw={
                    "file": relative,
                    "key": key,
                    "declared": value,
                    "entries": entries,
                    "observation": "disabled_algorithms_declared",
                },
            )
        )
    return findings


def _java_properties(text: str) -> Iterator[tuple[str, str, int]]:
    """``(key, value, first line)``, joining the backslash continuations these files use."""
    key: str | None = None
    value_parts: list[str] = []
    start = 0

    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if key is None:
            if not line or line.startswith(("#", "!")) or "=" not in line:
                continue
            head, _, tail = line.partition("=")
            key, start = head.strip(), number
            value_parts = [tail.strip()]
        else:
            value_parts.append(line)

        if value_parts and value_parts[-1].endswith("\\"):
            value_parts[-1] = value_parts[-1][:-1].strip()
            continue

        yield key, " ".join(part for part in value_parts if part), start
        key, value_parts = None, []

    if key is not None:
        yield key, " ".join(part for part in value_parts if part), start
