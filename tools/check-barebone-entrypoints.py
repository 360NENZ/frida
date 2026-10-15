from pathlib import Path
import re


workspace = Path(__file__).resolve().parent.parent
root = workspace / "subprojects/frida-core/src/barebone/agent"
linux = (root / "linux/meshlink-kmod.c").read_text(encoding="utf-8")
macos = (root / "macos/frida-kext.c").read_text(encoding="utf-8")
rust = (root / "src/lib.rs").read_text(encoding="utf-8")
xnu = (root / "src/xnu.rs").read_text(encoding="utf-8")
winnt = (root / "src/winnt.rs").read_text(encoding="utf-8")
win9x = (root / "src/win9x.rs").read_text(encoding="utf-8")
xnu_user = (root / "src/xnu_user.rs").read_text(encoding="utf-8")
user_sources = {
    name: (root / f"src/{name}_user.rs").read_text(encoding="utf-8")
    for name in ("winnt", "win9x")
}
host_session = (
    workspace / "subprojects/frida-core/src/barebone/barebone-host-session.vala"
).read_text(encoding="utf-8")
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

winnt_tag = re.search(r"const POOL_TAG: u32 = (0x[0-9a-f_]+);", winnt)
host_tag = re.search(r"private const uint64 POOL_TAG = (0x[0-9a-f]+);", host_session)
assert winnt_tag is not None and host_tag is not None
assert int(winnt_tag.group(1), 16) == int(host_tag.group(1), 16)
assert int(winnt_tag.group(1), 16) != 0x64697246

entries = {
    "winnt": {"meshlink_winnt_user_main", "meshlink_winnt_user_bootstrap"},
    "win9x": {"meshlink_win9x_user_main"},
}
for flavor, names in entries.items():
    source = user_sources[flavor]
    for name in names:
        assert f'#[unsafe(no_mangle)]\npub extern "C" fn {name}' in source
        assert name in (winnt if flavor == "winnt" else win9x)
    for arch in (("x86", "x86_64", "arm64") if flavor == "winnt" else ("x86",)):
        script = (root / f"agent-{flavor}-{arch}.lds").read_text(encoding="utf-8")
        globals_ = set(re.findall(
            r"\b([a-z_][a-z_0-9]+);",
            script.split("global:", 1)[1].split("local:", 1)[0],
        ))
        assert globals_ == {"_start"} | names, (flavor, arch, globals_)
    assert not re.search(r"\bfrida_(?:winnt|win9x)_user_", source)

assert "pub extern \"C\" fn meshlink_xnu_user_entry" in xnu_user
assert "meshlink_xnu_user_entry as *const ()" in xnu_user
assert not re.search(r"\bfrida_xnu_user_entry\b", xnu_user)
assert (
    'KMOD_EXPLICIT_DECL (re.meshlink.agent, "1.0", meshlink_kext_start, meshlink_kext_stop)'
    in macos
)
assert not re.search(r"\bfrida_kext_(?:start|stop)\b", macos)

winnt_asm_symbols = {
    "meshlink_winnt_run_on_stack",
    "meshlink_winnt_fault_vector",
    "meshlink_winnt_fault_vector_chain",
    "meshlink_winnt_fault_vector_control",
    "meshlink_winnt_fault_vector_onward",
    "meshlink_winnt_fault_vector_end",
    "meshlink_winnt_fault_thunk",
}
assert set(re.findall(r"(?m)^\.global (meshlink_winnt_[a-z_]+)$", winnt)) == winnt_asm_symbols
assert set(re.findall(r"(?m)^(meshlink_winnt_[a-z_]+):$", winnt)) == winnt_asm_symbols
assert all(
    f"static {name}: u8;" in winnt
    for name in winnt_asm_symbols if "fault_vector" in name
)
assert "fn meshlink_winnt_fault_thunk();" in winnt
assert "static mut meshlink_winnt_fault_stacks:" in winnt
assert "adrp x17, meshlink_winnt_fault_stacks" in winnt
assert "extern \"C\" fn meshlink_winnt_on_fault(" in winnt
assert "bl meshlink_winnt_on_fault" in winnt
assert not re.search(r"\bfrida_winnt_[a-z_]+\b", winnt)

print(f"Barebone entrypoints: Linux range arguments and {len(rust_symbols)} XNU constants match")
