from pathlib import Path
import re
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

build = (root / "subprojects/frida-core/meson.build").read_text(encoding="utf-8")
assert "if host_os_family == 'windows' and not is_shared\n  add_project_arguments('-DVALA_EXTERN=extern', language: 'c')" in build
assert "frida_component_cflags += '-DFRIDA_RUNTIME_TYPE_PREFIX=' + runtime_type_prefix" in build

runtime_type = (root / "subprojects/frida-core/lib/base/runtime-type.h").read_text(encoding="utf-8")
assert "#define FRIDA_RUNTIME_TYPE(name) FRIDA_RUNTIME_TYPE_EXPAND(FRIDA_RUNTIME_TYPE_PREFIX, name)" in runtime_type

for relative_path, names in (
    ("lib/base/windows-glue.c", ("HandleStream", "HandleInputStream", "HandleOutputStream")),
    ("lib/pipe/pipe-windows.c", ("PipeInputStream", "PipeOutputStream")),
):
    source = (root / "subprojects/frida-core" / relative_path).read_text(encoding="utf-8")
    assert '#include "runtime-type.h"' in source or '#include "../base/runtime-type.h"' in source
    for name in names:
        assert f"typedef FridaWindows{name} FRIDA_RUNTIME_TYPE (Windows{name});" in source
        assert f"typedef FridaWindows{name}Class FRIDA_RUNTIME_TYPE (Windows{name}Class);" in source
        assert f"G_DEFINE_TYPE (FRIDA_RUNTIME_TYPE (Windows{name})," in source
        assert f"G_DEFINE_TYPE (MeshlinkWindows{name}," not in source
        assert f"G_DEFINE_TYPE (FridaWindows{name}," not in source

for filename in sys.argv[1:]:
    contents = Path(filename).read_bytes()
    assert b"Frida %s helper" not in contents, filename
    assert "Frida %s helper".encode("utf-16le") not in contents, filename
    for name in ("HandleStream", "HandleInputStream", "HandleOutputStream", "PipeInputStream", "PipeOutputStream"):
        marker = f"FridaWindows{name}".encode("ascii")
        assert marker not in contents, (filename, marker)
        assert marker.decode("ascii").encode("utf-16le") not in contents, (filename, marker)
    assert b"frida_adb_client_close\0" not in contents, filename
    assert re.search(rb"\.\./subprojects/frida-core/[^\0\r\n\"]+\.vala", contents) is None, filename
    assert b"frida_service_context_free" not in contents, filename
    assert b"subprojects/frida-core/src/libfrida-core.a.p/" not in contents, filename
    for pdb in (b"frida-server-raw.pdb", b"frida-helper-raw.pdb", b"libml-agent.pdb"):
        assert pdb not in contents, (filename, pdb)

print("Windows helper service and injected blob names are neutral")
