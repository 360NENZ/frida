import sys
from pathlib import Path


LEGACY_MARKERS = (
    b"frida-json-root",
    b"/_frida.js",
    b"frida-console-",
    b"re.frida.hostlink",
    b"frida-context",
    b"frida-ctrl",
)


if len(sys.argv) < 2:
    raise SystemExit("usage: check-runtime-identifiers.py BINARY [BINARY ...]")

for filename in sys.argv[1:]:
    path = Path(filename)
    contents = path.read_bytes()
    remaining = [marker.decode("ascii") for marker in LEGACY_MARKERS if marker in contents]
    if remaining:
        raise SystemExit(f"{path}: legacy runtime identifiers remain: {', '.join(remaining)}")

print("No legacy runtime identifiers from the audited set remain")
