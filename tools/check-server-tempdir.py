from pathlib import Path


root = Path(__file__).resolve().parent.parent
server = (root / "subprojects/frida-core/server/server.vala").read_text(encoding="utf-8")
system = (root / "subprojects/frida-core/src/system.vala").read_text(encoding="utf-8")

assert "io.meshlink.service" not in server
assert "TemporaryDirectory.always_use ((directory != null) ? directory : TemporaryDirectory.make_name ())" in server
assert 'new StringBuilder ("runtime-")' in system

print("Server defaults to a per-instance temporary directory")
