from pathlib import Path
import re


workspace = Path(__file__).resolve().parent.parent
root = workspace / "subprojects/frida-core/src/barebone/agent"
linux = (root / "linux/meshlink-kmod.c").read_text(encoding="utf-8")
macos = (root / "macos/frida-kext.c").read_text(encoding="utf-8")
macos_readme = (root / "macos/README.md").read_text(encoding="utf-8")
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
assert "meshlink_agent_start (meshlink_own_base, meshlink_own_size)" in macos

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
assert not re.search(r"\b(?:frida_|FRIDA_)[A-Za-z_0-9]+\b", macos)
for operation in ("open", "close", "read", "write", "ioctl"):
    name = f"meshlink_dev_{operation}"
    assert f".d_{operation} = {name}" in macos
    assert re.search(rf"(?m)^{name} \(", macos)
for macro in ("MESHLINK_IOC_SET_ADDR", "MESHLINK_IOC_START", "MESHLINK_IOC_GET_IMAGE"):
    assert f"#define {macro} " in macos
assert "MESHLINK_IOC_SET_ADDR" in macos_readme
assert "MESHLINK_IOC_START" in macos_readme
assert "MeshlinkAddrRequest" in macos_readme

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

win9x_asm_symbols = {
    "meshlink_win9x_event_thunk",
    "meshlink_win9x_wake_event_thunk",
    "meshlink_win9x_thread_start_thunk",
    "meshlink_win9x_control_thunk",
    "meshlink_win9x_time_out_thunk",
    "meshlink_win9x_thread_thunk",
    "meshlink_win9x_hw_int_thunk",
}
assert set(re.findall(r"(?m)^\.global (meshlink_win9x_[a-z_]+)$", win9x)) == win9x_asm_symbols
assert win9x_asm_symbols <= set(re.findall(r"(?m)^(meshlink_win9x_[a-z_]+):$", win9x))
assert all(f"fn {name}();" in win9x for name in win9x_asm_symbols - {
    "meshlink_win9x_time_out_thunk",
})
fault_thunks = {
    "meshlink_win9x_fault_thunk_ud": 6,
    "meshlink_win9x_fault_thunk_gp": 13,
    "meshlink_win9x_fault_thunk_pf": 14,
}
for name, number in fault_thunks.items():
    assert f"FAULT_THUNK {name}, {number}" in win9x
    assert f"fn {name}();" in win9x
callbacks = set(re.findall(
    r"(?m)^\s+call (meshlink_win9x_(?:on_[a-z_]+|thread_start))$", win9x
))
assert callbacks == {
    "meshlink_win9x_on_event",
    "meshlink_win9x_on_wake_event",
    "meshlink_win9x_on_thread_start",
    "meshlink_win9x_on_control",
    "meshlink_win9x_on_fault",
    "meshlink_win9x_thread_start",
    "meshlink_win9x_on_hw_int",
}
assert all(f'extern "C" fn {name}(' in win9x for name in callbacks)
assert "static mut meshlink_win9x_resume:" in win9x
assert "meshlink_win9x_resume@GOTOFF" in win9x
assert not re.search(r"\bfrida_win9x_[a-z_]+\b", win9x)

print(f"Barebone entrypoints: Linux range arguments and {len(rust_symbols)} XNU constants match")
