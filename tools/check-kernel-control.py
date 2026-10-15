from pathlib import Path
import re


root = Path(__file__).resolve().parent.parent
sources = {
    "subprojects/frida-gum/gum/gumcloak.c": (
        "GUM_KERNEL_CLOAK_MAGIC",
        "GUM_KERNEL_CLOAK_TOKEN",
    ),
    "subprojects/frida-core/src/linux/kernel-injector.vala": (
        "CONTROL_MAGIC",
        "CONTROL_TOKEN",
    ),
    "subprojects/frida-core/src/barebone/agent/linux/meshlink-kmod.c": (
        "MESHLINK_CONTROL_MAGIC",
        "MESHLINK_CONTROL_TOKEN",
    ),
}

values = []
for path, names in sources.items():
    contents = (root / path).read_text(encoding="utf-8")
    pair = []
    for name in names:
        matches = re.findall(rf"\b{re.escape(name)}\s*(?:=\s*)?(0x[0-9a-fA-F]+)", contents)
        assert len(matches) == 1, (path, name, matches)
        pair.append(int(matches[0], 16))
    values.append(tuple(pair))
    assert "0x46524944" not in contents
    assert "0x1d5f9e6b2c7a4038" not in contents

assert len(set(values)) == 1, values
magic, token = values[0]
readme = (root / "subprojects/frida-core/src/barebone/agent/linux/README.md").read_text(encoding="utf-8")
assert f"prctl(0x{magic:x}, op, arg1, arg2, 0x{token:x})" in readme
print("Kernel control constants match across Gum, core, and module")
