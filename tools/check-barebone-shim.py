from pathlib import Path
import os
import re
import subprocess
import tempfile


root = Path(__file__).resolve().parent.parent
linux = root / "subprojects/frida-core/src/barebone/agent/src/linux"
source = linux / "regparm.c"
rust = "\n".join(path.read_text(encoding="utf-8") for path in linux.glob("*.rs"))


def symbols(output, prefix):
    return set(re.findall(rf"\b({prefix}[A-Za-z_0-9]+)\s*$", output, re.MULTILINE))


with tempfile.TemporaryDirectory() as directory:
    obj = Path(directory) / "regparm.o"
    subprocess.run(
        [os.environ.get("CC", "cc"), "-m32", "-O2", "-fPIC", "-ffreestanding",
         "-c", str(source), "-o", str(obj)],
        check=True,
    )
    defined = subprocess.check_output(
        ["nm", "--defined-only", "--extern-only", str(obj)], text=True
    )
    undefined = subprocess.check_output(["nm", "--undefined-only", str(obj)], text=True)

assert "frida" not in (defined + undefined).lower()

shim_symbols = symbols(defined, r"meshlink_(?:k_|kcb_)")
rust_shim_symbols = set(re.findall(r"\bmeshlink_(?:k_|kcb_)[A-Za-z_0-9]+", rust))
assert shim_symbols == rust_shim_symbols, (
    "Missing C shims:", sorted(rust_shim_symbols - shim_symbols),
    "Unused C shims:", sorted(shim_symbols - rust_shim_symbols),
)

callbacks = symbols(undefined, r"meshlink_cb_")
rust_callbacks = set(re.findall(
    r'#\[unsafe\(no_mangle\)\]\s*(?:pub\s+)?unsafe\s+extern\s+"C"\s+fn\s+'
    r'(meshlink_cb_[A-Za-z_0-9]+)\b',
    rust,
))
assert callbacks == rust_callbacks, (
    "Missing Rust callbacks:", sorted(callbacks - rust_callbacks),
    "Unused Rust callbacks:", sorted(rust_callbacks - callbacks),
)

assert shim_symbols and callbacks
print(f"Barebone x86 shim ABI: {len(shim_symbols)} C shims, {len(callbacks)} Rust callbacks")
