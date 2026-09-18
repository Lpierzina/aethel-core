#!/usr/bin/env python3
"""Check that a WebAssembly component exposes exactly its declared WIT surface.

The expected surface comes from WIT declaration syntax, while the actual surface
comes from `wasm-tools component wit`, which decodes the component structurally.
Doc comments are deliberately ignored. The theory that comments could cause a
false pass was tested and disproved: doc comments are not embedded in compiled
components. Declaration parsing is defense in depth, not a fix for that theory.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

IDENT = r"[A-Za-z][A-Za-z0-9-]*"
INTERFACE_RE = re.compile(rf"\binterface\s+({IDENT})\s*\{{")
WORLD_RE = re.compile(r"\bworld\s+[A-Za-z][A-Za-z0-9-]*\s*\{")
RESOURCE_RE = re.compile(rf"\bresource\s+({IDENT})\s*\{{")
FUNCTION_RE = re.compile(rf"\b({IDENT})\s*:\s*(?:static\s+)?func\s*\(")
EXPORT_RE = re.compile(r"\bexport\s+([^;{]+);")


class WitSyntaxError(ValueError):
    """Raised when this deliberately small declaration parser cannot proceed."""


def strip_comments(source: str) -> str:
    """Remove WIT line and block comments without treating their text as syntax."""
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", "", source)


def block_after_open_brace(source: str, open_brace: int) -> tuple[str, int]:
    """Return a balanced brace body's text and the index after its closing brace."""
    depth = 0
    for index in range(open_brace, len(source)):
        char = source[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[open_brace + 1 : index], index + 1
    raise WitSyntaxError("unterminated WIT declaration block")


def declarations(source: str, pattern: re.Pattern[str]) -> list[tuple[str, str]]:
    """Return named balanced declaration bodies for `interface` or `world`."""
    result: list[tuple[str, str]] = []
    for match in pattern.finditer(source):
        body, _ = block_after_open_brace(source, source.index("{", match.start(), match.end()))
        result.append((match.group(1) if match.lastindex else "", body))
    return result


def top_level_functions(body: str) -> set[str]:
    """Find WIT `name: func` declarations only at this declaration's top level."""
    functions: set[str] = set()
    statement_start = 0
    index = 0
    while index < len(body):
        char = body[index]
        if char == "{":
            _, end = block_after_open_brace(body, index)
            statement_start = end
            index = end
        elif char == ";":
            statement = body[statement_start : index + 1]
            match = FUNCTION_RE.search(statement)
            if match:
                functions.add(match.group(1))
            statement_start = index + 1
            index += 1
        else:
            index += 1
    return functions


def resource_methods(interface_body: str) -> set[str]:
    """Find `resource method: [static] func` declarations as resource.method."""
    methods: set[str] = set()
    for resource in RESOURCE_RE.finditer(interface_body):
        body, _ = block_after_open_brace(
            interface_body,
            interface_body.index("{", resource.start(), resource.end()),
        )
        methods.update(f"{resource.group(1)}.{method}" for method in top_level_functions(body))
    return methods


def exported_interface_names(source: str) -> set[str]:
    """Resolve named interface exports from all WIT worlds in this document."""
    names: set[str] = set()
    for _, world_body in declarations(source, WORLD_RE):
        for match in EXPORT_RE.finditer(world_body):
            reference = match.group(1).strip()
            if re.match(rf"^{IDENT}\s*:\s", reference) or "=" in reference:
                raise WitSyntaxError(
                    f"unsupported inline or aliased world export: {reference!r}"
                )
            name = reference.rsplit("/", 1)[-1].split("@", 1)[0].strip()
            if not re.fullmatch(IDENT, name):
                raise WitSyntaxError(f"unsupported world export: {reference!r}")
            names.add(name)
    if not names:
        raise WitSyntaxError("no named interface exports found in a WIT world")
    return names


def extract_exports(wit_source: str) -> set[str]:
    """Extract canonical free-function and resource-method names from WIT."""
    source = strip_comments(wit_source)
    wanted_interfaces = exported_interface_names(source)
    found_interfaces: set[str] = set()
    exports: set[str] = set()
    for interface_name, interface_body in declarations(source, INTERFACE_RE):
        if interface_name in wanted_interfaces:
            found_interfaces.add(interface_name)
            exports.update(top_level_functions(interface_body))
            exports.update(resource_methods(interface_body))
    missing_interfaces = wanted_interfaces - found_interfaces
    if missing_interfaces:
        raise WitSyntaxError(
            "exported interface declarations not found: "
            + ", ".join(sorted(missing_interfaces))
        )
    return exports


def component_wit(component: Path) -> str:
    """Ask component-aware wasm-tools to decode the artifact's WIT declaration."""
    try:
        return subprocess.run(
            ["wasm-tools", "component", "wit", str(component)],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    except FileNotFoundError as error:
        raise RuntimeError("wasm-tools is required to inspect component exports") from error
    except subprocess.CalledProcessError as error:
        raise RuntimeError(error.stderr.strip() or "wasm-tools component wit failed") from error


def format_exports(exports: set[str]) -> str:
    return "\n".join(sorted(exports))


def check_exports(expected: set[str], actual: set[str]) -> tuple[set[str], set[str]]:
    """Return (missing, unexpected), allowing callers and tests to use set equality."""
    return expected - actual, actual - expected


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compare WIT-derived exports with a component's decoded WIT."
    )
    parser.add_argument("wit_file", type=Path, help="canonical expected WIT file")
    parser.add_argument("component_file", type=Path, help="compiled component file")
    args = parser.parse_args(argv)

    try:
        expected = extract_exports(args.wit_file.read_text(encoding="utf-8"))
        actual = extract_exports(component_wit(args.component_file))
    except (OSError, RuntimeError, WitSyntaxError) as error:
        print(f"component export check error: {error}", file=sys.stderr)
        return 2

    missing, unexpected = check_exports(expected, actual)
    if missing or unexpected:
        print("Component export set does not match the WIT-derived export set.")
        if missing:
            print("\nMissing exports:")
            print(format_exports(missing))
        if unexpected:
            print("\nUnexpected exports:")
            print(format_exports(unexpected))
        return 1

    print(f"WIT-derived export set ({len(expected)} exports):")
    print(format_exports(expected))
    print(f"\nComponent export set matches exactly ({len(actual)} exports).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
