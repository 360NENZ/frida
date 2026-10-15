import re
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
    b"Frida/",
    b"FridaHostSession\x00",
    b"FridaAgentSessionProvider\x00",
    b"FridaAgentSession\x00",
    b"FridaAgentController\x00",
    b"FridaAgentMessageSink\x00",
    b"FridaGadgetSession\x00",
    b"FridaChannel\x00",
    b"FridaServiceSession\x00",
    b"FridaTransportBroker\x00",
    b"FridaPortalSession\x00",
    b"FridaBusSession\x00",
    b"FridaNullAuthenticationService\x00",
    b"FridaUnauthorizedHostSession\x00",
    b"FridaWebService\x00",
    b"FridaWebServiceConnectionHandler\x00",
    b"FridaWebServiceFlavor\x00",
    b"FridaPortConflictBehavior\x00",
    b"FridaDynamicInterfaceObserver\x00",
    b"FridaDynamicInterface\x00",
    b"FridaTunnelInterfaceObserver\x00",
    b"FridaThreadIgnoreScope\x00",
    b"FridaExitHandler\x00",
    b"FridaPeerSessionDescription\x00",
    b"FridaPeerSetup\x00",
    b"frida_context != null",
    b"Frida\x00",
    b"lolcathost",
    b"FridaSctpConnection\x00",
    b"_frida_sctp_connection_",
    b"FridaThreadSuspendMonitor",
    b"FridaUnwindSitter",
    b"FridaFuture",
    b"FridaPromise",
    b"org.tools.bridge.Gadget",
    b"FridaAgentScriptId",
    b"FridaAgentSessionId",
    b"FridaChannelId",
    b"FridaInjectorPayloadId",
    b"FridaPortalMembershipId",
    b"FridaServiceSessionId",
    b"Frida.",
    b"-isystem /frida",
    b"FRIDA_V8_EXTRA_FLAGS",
    b"../subprojects/frida-core/",
    b"../subprojects/frida-gum/",
)


def remaining_identifiers(contents: bytes) -> list[str]:
    remaining = {marker.decode("ascii").rstrip("\0") for marker in LEGACY_MARKERS if marker in contents}
    for match in re.finditer(rb"[\x20-\x7e]{5,}", contents):
        text = match.group()
        if b"frida" in text.lower() and text.lower() != b"friday":
            remaining.add(text[:160].decode("ascii") + ("..." if len(text) > 160 else ""))
    return sorted(remaining)


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit("usage: check-runtime-identifiers.py BINARY [BINARY ...]")

    for filename in sys.argv[1:]:
        path = Path(filename)
        remaining = remaining_identifiers(path.read_bytes())
        if remaining:
            examples = ", ".join(remaining[:12])
            raise SystemExit(f"{path}: {len(remaining)} legacy runtime identifiers remain: {examples}")

    print("No legacy runtime identifiers from the audited set remain")


if __name__ == "__main__":
    main()
