from pathlib import Path
import re


root = Path(__file__).resolve().parent.parent
compiler = (root / "subprojects/frida-core/src/compiler/compiler.vala").read_text(encoding="utf-8")

assert 'MemoryFileDescriptor.from_bytes ("runtime-compiler.so"' in compiler
assert '"frida-compiler-backend.so"' not in compiler

compiler_dir = root / "subprojects/frida-core/src/compiler"
frontend = (compiler_dir / "frontend_capi.go").read_text(encoding="utf-8")
exports = re.findall(r"//export (_relay_compiler_backend_\w+)", frontend)
lookups = re.findall(r'resolve_symbol \(backend, "(_relay_compiler_backend_\w+)"\)', compiler)
assert len(exports) == 11 and len(set(exports)) == len(exports)
assert sorted(lookups) == sorted(exports * 2)
for name in exports:
    assert f"func {name}(" in frontend

assert 'lower_case_cprefix = "relay_compiler_backend_"' in compiler
glue = (compiler_dir / "backend-glue.c").read_text(encoding="utf-8")
assert glue.count("_relay_compiler_backend_init_go_runtime (void)") == 2
assert not re.search(r'resolve_symbol \(backend, "_frida_compiler_backend_', compiler)
assert "_frida_compiler_backend_" not in (frontend + glue)
assert "_relay_compiler_backend_*;" in (compiler_dir / "backend.version").read_text(encoding="utf-8")
assert "__relay_compiler_backend_*" in (compiler_dir / "backend.symbols").read_text(encoding="utf-8")

meson = (compiler_dir / "meson.build").read_text(encoding="utf-8")
builder = (compiler_dir / "build-backend.py").read_text(encoding="utf-8")
core_meson = (root / "subprojects/frida-core/meson.build").read_text(encoding="utf-8")
resources = (compiler_dir / "compiler.resources").read_text(encoding="utf-8")
assert "frida-compiler-backend" not in (meson + builder + core_meson + compiler)
assert "'runtime-compiler-backend' + shlib_suffix" in meson
assert "'runtime-compiler-backend' + exe_suffix" in meson
assert 'backend_stem = "runtime-compiler-backend"' in builder
assert "'FRIDA_COMPILER_BACKEND_NAME', 'runtime-compiler-backend' + shlib_suffix" in core_meson
assert "'FRIDA_COMPILER_BACKEND_NAME', 'runtime-compiler-backend' + exe_suffix" in core_meson
assert "namespace = Relay.Data.Compiler" in resources
assert "Relay.Data.Compiler.get_runtime_compiler_backend_so_blob ()" in compiler
assert "Relay.Data.Compiler.get_runtime_compiler_backend_blob ()" in compiler

print("Compiler backend runtime identities and exported symbols agree")
