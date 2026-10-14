import sys
from pathlib import Path


LEGACY_MARKERS = (
    b"frida-json-root",
    b"/_frida.js",
    b"frida-console-",
    b"re.frida.hostlink",
    b"frida-context",
    b"frida-ctrl",
    b"frida-selinux-error-quark",
    b"FridaDummyInputStream",
    b"FridaVirtualInputStream",
    b"FridaVirtualOutputStream",
    b"FridaWebConnection",
    b"FridaPortalClientLiveAgentSession",
    b"FridaFileDescriptorGuardCloseListener",
    b"FridaDirListCloaker",
    b"FridaVirtualStream",
    b"FridaAgentMessageTransmitter",
    b"FridaBaseAgentSession",
    b"FridaPortalClient",
    b"FridaScriptEngine",
    b"FridaExitMonitor",
    b"FridaFileDescriptorGuard",
    b"FridaForkMonitor",
    b"FridaThreadCountCloaker",
    b"FridaThreadListCloaker",
    b"FridaFDListCloaker",
    b"FridaDirListFilter",
    b"FridaProcessInvader",
    b"FridaRpcClient",
    b"FridaRpcPeer",
    b"FridaPeerSocket",
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
