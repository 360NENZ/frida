from pathlib import Path
import re


workspace = Path(__file__).resolve().parent.parent
root = workspace / "subprojects/frida-core/src/barebone/agent"
linux = (root / "linux/meshlink-kmod.c").read_text(encoding="utf-8")
macos = (root / "macos/frida-kext.c").read_text(encoding="utf-8")
rust = (root / "src/lib.rs").read_text(encoding="utf-8")
xnu = (root / "src/xnu.rs").read_text(encoding="utf-8")
makefile = (root / "linux/Makefile").read_text(encoding="utf-8")
workflow = (workspace / ".github/workflows/ci.yml").read_text(encoding="utf-8")

for source in (linux, macos, rust, xnu, makefile, workflow):
    assert not re.search(r"\bfrida_agent_(?:start|stop|wake|init|private|heap|relocs|disc)", source)

assert "int meshlink_agent_start (u64 own_base, u64 own_size);" in linux
module_init = re.search(
    r"static int __init\s+meshlink_kmod_init \(void\)\s*\{(.*?)\n\}",
    linux,
    re.DOTALL,
)
assert module_init is not None
init_body = module_init.group(1)
assert re.search(
    r"meshlink_kmod_own_range \(&own_base, &own_size\);\s*"
    r"return meshlink_agent_start \(own_base, own_size\);",
    init_body,
)
assert rust.count("pub extern \"C\" fn meshlink_agent_start(own_base: u64, own_size: u64)") == 2
assert "extern int meshlink_agent_start (uint64_t own_base, uint64_t own_size);" in macos
assert "meshlink_agent_start (frida_own_base, frida_own_size)" in macos

for name in ("meshlink_agent_start", "meshlink_agent_stop"):
    assert name in makefile.split("ENTRY_POINTS :=", 1)[1].split("\n", 1)[0]
    assert name in workflow.split("EXPECTED_GLOBALS:", 1)[1].split("\n", 2)[1]

macos_symbols = set(re.findall(
    r"\bconst (?:uintptr_t|unsigned) (meshlink_agent_[A-Za-z_0-9]+)\s*=", macos
))
rust_symbols = set(re.findall(r"\bstatic (meshlink_agent_[A-Za-z_0-9]+):", rust + xnu))
assert rust_symbols and rust_symbols <= macos_symbols, sorted(rust_symbols - macos_symbols)

print(f"Barebone entrypoints: Linux range arguments and {len(rust_symbols)} XNU constants match")
