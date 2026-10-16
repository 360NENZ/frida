import importlib.util
import unittest
from pathlib import Path


spec = importlib.util.spec_from_file_location(
    "runtime_identifier_check", Path(__file__).with_name("check-runtime-identifiers.py")
)
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


class RuntimeIdentifierCheckTest(unittest.TestCase):
    def test_detects_unlisted_runtime_strings(self):
        remaining = checker.remaining_identifiers(
            b"meshlink\x00frida\x00FRIDA_FRUITY_KCDATA_ITEM_TYPE_ARRAY_PADa\x00"
            b"FRIDA_1.0\x00/home/oleavr/src/frida-core/agent\x00js-event-loop\x00"
            b"agent-worker\x00io-worker\x00main-worker\x00meshlink-worker\x00"
            b"runtime-compiler.so\x00"
            b"cert-worker\x00helper-factory\x00usb-worker\x00"
            b"pulse-reader\x00app-launch\x00"
        )
        self.assertIn("meshlink-worker", remaining)
        self.assertIn("main-worker", remaining)
        self.assertIn("agent-worker", remaining)
        self.assertIn("io-worker", remaining)
        self.assertIn("js-event-loop", remaining)
        self.assertIn("runtime-compiler.so", remaining)
        for name in ("cert-worker", "helper-factory", "usb-worker", "pulse-reader", "app-launch"):
            self.assertIn(name, remaining)
        self.assertIn("frida", remaining)
        self.assertIn("FRIDA_FRUITY_KCDATA_ITEM_TYPE_ARRAY_PADa", remaining)
        self.assertIn("FRIDA_1.0", remaining)
        self.assertIn("/home/oleavr/src/frida-core/agent", remaining)

    def test_allows_neutral_identifiers_and_weekday(self):
        self.assertEqual(
            checker.remaining_identifiers(b"meshlink_agent\x00MESHLINK_1.0\x00Friday\x00"),
            [],
        )

    def test_detects_wide_runtime_strings(self):
        for encoding in ("utf-16-le", "utf-16-be"):
            with self.subTest(encoding=encoding):
                contents = (
                    "FridaHostSession\x00".encode(encoding)
                    + "custom FrIdA plugin\x00".encode(encoding)
                )
                remaining = checker.remaining_identifiers(contents)
                self.assertIn("FridaHostSession", remaining)
                self.assertIn("custom FrIdA plugin", remaining)

    def test_allows_neutral_wide_strings(self):
        for encoding in ("utf-16-le", "utf-16-be"):
            with self.subTest(encoding=encoding):
                self.assertEqual(
                    checker.remaining_identifiers("meshlink_agent\x00Friday\x00".encode(encoding)),
                    [],
                )


if __name__ == "__main__":
    unittest.main()
