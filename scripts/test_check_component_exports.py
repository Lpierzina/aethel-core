#!/usr/bin/env python3
"""Focused self-tests for scripts/check-component-exports.py."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

CHECKER_PATH = Path(__file__).with_name("check-component-exports.py")
SPEC = importlib.util.spec_from_file_location("component_export_checker", CHECKER_PATH)
assert SPEC and SPEC.loader
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)

WIT = """\
package aethel:core@0.1.0;

interface identity {
  /// Comments can say ghost: func() and must not count.
  plp-project-at-context: func() -> bool;
  resource master-identity {
    sign: func() -> bool;
  }
  resource issuer-public-parameters {
    deserialize: static func() -> bool;
  }
  resource credential {
    present: func() -> bool;
  }
}

interface secret-sharing {
  htss-reconstruct: func() -> bool;
}

world aethel-core {
  export identity;
  export secret-sharing;
}
"""


class ComponentExportCheckerTests(unittest.TestCase):
    def test_free_functions_are_extracted(self) -> None:
        exports = checker.extract_exports(WIT)
        self.assertIn("plp-project-at-context", exports)
        self.assertIn("htss-reconstruct", exports)

    def test_resource_methods_are_extracted(self) -> None:
        exports = checker.extract_exports(WIT)
        self.assertIn("credential.present", exports)
        self.assertIn("master-identity.sign", exports)
        self.assertIn("issuer-public-parameters.deserialize", exports)

    def test_comments_and_non_declarations_are_ignored(self) -> None:
        exports = checker.extract_exports(WIT)
        self.assertNotIn("ghost", exports)
        self.assertEqual(len(exports & {"credential.present"}), 1)
        self.assertNotIn("not-a-declaration", exports)

    def test_missing_export_fails(self) -> None:
        missing, unexpected = checker.check_exports(
            {"credential.present", "htss-reconstruct"}, {"htss-reconstruct"}
        )
        self.assertEqual(missing, {"credential.present"})
        self.assertFalse(unexpected)

    def test_unexpected_export_fails(self) -> None:
        missing, unexpected = checker.check_exports(
            {"htss-reconstruct"}, {"htss-reconstruct", "credential.present"}
        )
        self.assertFalse(missing)
        self.assertEqual(unexpected, {"credential.present"})

    def test_ordering_is_irrelevant_and_equality_is_exact(self) -> None:
        expected = set(reversed(["plp-project-at-context", "credential.present"]))
        actual = {"credential.present", "plp-project-at-context"}
        self.assertEqual(checker.check_exports(expected, actual), (set(), set()))
        self.assertEqual(
            checker.format_exports(actual),
            "credential.present\nplp-project-at-context",
        )

    def test_credential_present_negative_control_fails(self) -> None:
        """A component WIT missing this resource method must be rejected."""
        broken_component_wit = WIT.replace("    present: func() -> bool;\n", "")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            wit_file = root / "expected.wit"
            component = root / "broken.component.wasm"
            wasm_tools = root / "wasm-tools"
            wit_file.write_text(WIT, encoding="utf-8")
            component.touch()
            wasm_tools.write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = component ] && [ \"$2\" = wit ]; then\n"
                "  cat <<'WIT'\n"
                f"{broken_component_wit}"
                "WIT\n"
                "else\n"
                "  exit 64\n"
                "fi\n",
                encoding="utf-8",
            )
            wasm_tools.chmod(wasm_tools.stat().st_mode | stat.S_IXUSR)
            output = io.StringIO()
            with patch.dict(
                os.environ, {"PATH": f"{root}{os.pathsep}{os.environ['PATH']}"}
            ), contextlib.redirect_stdout(output):
                result = checker.main([str(wit_file), str(component)])

        self.assertEqual(result, 1)
        self.assertIn("Missing exports:\ncredential.present", output.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
