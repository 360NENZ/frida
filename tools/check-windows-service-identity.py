from pathlib import Path
import sys


root = Path(__file__).resolve().parent.parent
source = (root / "subprojects/frida-core/src/windows/frida-helper-service-glue.c").read_text(encoding="utf-8")

assert 'g_strdup_printf ("Runtime %s helper (%s)", suffix, servicename_utf8)' in source
assert '"Frida %s helper' not in source

backend = (root / "subprojects/frida-core/src/windows/frida-helper-backend.vala").read_text(encoding="utf-8")
assert '"runtime-" + Uuid.string_random ()' in backend
assert 'Path.build_filename (program_files_path, "Frida")' not in backend

injector = (root / "subprojects/frida-core/src/windows/winjector.vala").read_text(encoding="utf-8")
assert 'Uuid.string_random () + ".dll"' in injector
assert "blob%u.dll" not in injector

for relative_path, names in (
    ("lib/base/windows-glue.c", ("HandleStream", "HandleInputStream", "HandleOutputStream")),
    ("lib/pipe/pipe-windows.c", ("PipeInputStream", "PipeOutputStream")),
):
    source = (root / "subprojects/frida-core" / relative_path).read_text(encoding="utf-8")
    for name in names:
        assert f"G_DEFINE_TYPE (MeshlinkWindows{name}," in source
        assert f"G_DEFINE_TYPE (FridaWindows{name}," not in source

for filename in sys.argv[1:]:
    contents = Path(filename).read_bytes()
    assert b"Frida %s helper" not in contents, filename
    assert "Frida %s helper".encode("utf-16le") not in contents, filename
    for name in ("HandleStream", "HandleInputStream", "HandleOutputStream", "PipeInputStream", "PipeOutputStream"):
        marker = f"FridaWindows{name}".encode("ascii")
        assert marker not in contents, (filename, marker)
        assert marker.decode("ascii").encode("utf-16le") not in contents, (filename, marker)

print("Windows helper service and injected blob names are neutral")
