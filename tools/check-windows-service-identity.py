from pathlib import Path
import sys


root = Path(__file__).resolve().parent.parent
source = (root / "subprojects/frida-core/src/windows/frida-helper-service-glue.c").read_text(encoding="utf-8")

assert 'g_strdup_printf ("Runtime %s helper (%s)", suffix, servicename_utf8)' in source
assert '"Frida %s helper' not in source

for filename in sys.argv[1:]:
    contents = Path(filename).read_bytes()
    assert b"Frida %s helper" not in contents, filename
    assert "Frida %s helper".encode("utf-16le") not in contents, filename

print("Windows helper service display name is neutral")
