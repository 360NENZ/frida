from pathlib import Path
import re


root = Path(__file__).resolve().parent.parent / "subprojects/frida-core/src/barebone/agent"
linux = (root / "linux/meshlink-kmod.c").read_text(encoding="utf-8")
macos = (root / "macos/frida-kext.c").read_text(encoding="utf-8")
kmod = (root / "src/linux/kmod.rs").read_text(encoding="utf-8")
hostlink = (root / "src/hostlink_chardev.rs").read_text(encoding="utf-8")

for source in (linux, macos, kmod, hostlink):
    assert "frida_kmod_" not in source


def definitions(source):
    return set(re.findall(r"^meshlink_kmod_[A-Za-z_0-9]+(?=\s*\()", source, re.MULTILINE))


def declarations(source):
    return set(re.findall(r"\bfn\s+(meshlink_kmod_[A-Za-z_0-9]+)\s*\(", source))


linux_definitions = definitions(linux)
macos_definitions = definitions(macos)
kernel_imports = declarations(kmod)
link_imports = declarations(hostlink)

assert kernel_imports and link_imports
assert kernel_imports <= linux_definitions, sorted(kernel_imports - linux_definitions)
assert link_imports - {"meshlink_kmod_link_pending"} <= linux_definitions
assert link_imports <= macos_definitions, sorted(link_imports - macos_definitions)
assert "meshlink_kmod_link_pending" in link_imports

print(
    f"Barebone kernel bridge: {len(kernel_imports)} Linux imports, "
    f"{len(link_imports)} shared/macOS link imports"
)
