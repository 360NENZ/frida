from pathlib import Path
import re


linux = (
    Path(__file__).resolve().parent.parent
    / "subprojects/frida-core/src/barebone/agent/src/linux"
)
sources = {
    name: (linux / name).read_text(encoding="utf-8")
    for name in ("user.rs", "injection.rs", "kfault.rs")
}
all_sources = "\n".join(sources.values())
names = {
    "meshlink_start_thread",
    "meshlink_syscall",
    "meshlink_pte_exec_trampoline",
    "meshlink_arm64_call_original",
}
identifier = r"(meshlink_[A-Za-z_0-9]+)"
globals_ = set(re.findall(rf'"\.globl {identifier}"', all_sources))
labels = set(re.findall(rf'"{identifier}:"', all_sources))
declarations = set(re.findall(rf"\bfn\s+{identifier}\s*\(", all_sources)) & names

assert globals_ == labels == declarations == names, (
    sorted(globals_), sorted(labels), sorted(declarations)
)
assert not re.search(
    r"\b(?:frida_(?:start_thread|syscall|pte_exec_trampoline|arm64_call_original|"
    r"linux_user_entry|arm64_fixup)|FRIDA_ARM64_ORIGINAL_CONT)\b",
    all_sources,
)
assert "pub extern \"C\" fn meshlink_linux_user_entry" in sources["user.rs"]
assert "meshlink_linux_user_entry as *const ()" in sources["user.rs"]
assert "#[unsafe(no_mangle)]\nstatic mut MESHLINK_ARM64_ORIGINAL_CONT" in sources["kfault.rs"]
assert "cont = sym MESHLINK_ARM64_ORIGINAL_CONT" in sources["kfault.rs"]

print(f"Barebone Linux assembly: {len(names)} labels match Rust declarations")
