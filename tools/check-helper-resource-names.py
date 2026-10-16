from pathlib import Path


root = Path(__file__).resolve().parent.parent / "subprojects/frida-core/src"
linux = (root / "linux/frida-helper-process.vala").read_text(encoding="utf-8")

assert linux.count('make_temporary_helper (Uuid.string_random ().replace ("-", ""), blob') == 2
assert "new MemoryHelperFile (name, new Bytes.static (data))" in linux
assert 'new TemporaryFile.from_stream (name,' in linux
assert '"runtime-helper' not in linux

print("Android/Linux embedded helper files and memfds use per-instance names")
