from pathlib import Path


root = Path(__file__).resolve().parent.parent / "subprojects/frida-core/src"
injectors = {
    "linux/linjector.vala": ".so",
    "windows/winjector.vala": ".dll",
    "darwin/fruitjector.vala": ".dylib",
    "freebsd/binjector.vala": ".so",
    "prospero/binjector.vala": ".so",
    "qnx/qinjector.vala": ".so",
}

for name, extension in injectors.items():
    source = (root / name).read_text(encoding="utf-8")
    assert "blob%u" not in source, name
    assert "next_blob_id" not in source, name
    assert f'Uuid.string_random () + "{extension}"' in source, name

linux = (root / "linux/linjector.vala").read_text(encoding="utf-8")
assert linux.count("MemoryFileDescriptor.from_bytes (make_memfd_name (), blob)") == 2
assert 'Uuid.string_random ().replace ("-", "").substring (0, Random.int_range (12, 29))' in linux

print("Injected blob names are per-injection across supported platforms")
