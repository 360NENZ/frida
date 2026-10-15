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
            b"FRIDA_1.0\x00/home/oleavr/src/frida-core/agent\x00"
        )
        self.assertIn("frida", remaining)
        self.assertIn("FRIDA_FRUITY_KCDATA_ITEM_TYPE_ARRAY_PADa", remaining)
        self.assertIn("FRIDA_1.0", remaining)
        self.assertIn("/home/oleavr/src/frida-core/agent", remaining)

    def test_allows_neutral_identifiers_and_weekday(self):
        self.assertEqual(
            checker.remaining_identifiers(b"meshlink_agent\x00MESHLINK_1.0\x00Friday\x00"),
            [],
        )


if __name__ == "__main__":
    unittest.main()
