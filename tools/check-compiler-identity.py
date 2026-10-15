from pathlib import Path


root = Path(__file__).resolve().parent.parent
compiler = (root / "subprojects/frida-core/src/compiler/compiler.vala").read_text(encoding="utf-8")

assert 'MemoryFileDescriptor.from_bytes ("runtime-compiler.so"' in compiler
assert '"frida-compiler-backend.so"' not in compiler

print("Compiler backend memfd name is neutral")
