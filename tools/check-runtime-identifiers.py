import argparse
import re
from pathlib import Path


LEGACY_MARKERS = (
    b"agent-worker",
    b"io-worker",
    b"js-event-loop",
    b"main-worker",
    b"meshlink-worker",
    b"io.meshlink.service",
    b"rpc-worker",
    b"rpc-listener-",
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
    b"runtime-compiler.so",
    b"cert-worker",
    b"helper-factory",
    b"usb-worker",
    b"pulse-reader",
    b"app-launch",
    b"/_meshlink_worker_runtime.js",
    b"/meshlink/bootstrap.js",
    b"meshlink:rpc",
    b"Meshlink Agent",
    b"Meshlink/v",
)

ORIGINAL_MARKERS = tuple(marker for marker in LEGACY_MARKERS if b"frida" in marker.lower()) + (
    b"agent-worker",
    b"io-worker",
    b"js-event-loop",
    b"main-worker",
    b"rpc-worker",
    b"rpc-listener-",
    b"lolcathost",
)


def remaining_identifiers(contents: bytes, original_only: bool = False) -> list[str]:
    markers = ORIGINAL_MARKERS if original_only else LEGACY_MARKERS
    remaining = {
        marker.decode("ascii").rstrip("\0")
        for marker in markers
        if marker in contents
        or any(
            marker.decode("ascii").encode(encoding) in contents
            for encoding in ("utf-16-le", "utf-16-be")
        )
    }
    for match in re.finditer(rb"[\x20-\x7e]{5,}", contents):
        text = match.group()
        if b"frida" in text.lower() and text.lower() != b"friday":
            remaining.add(text[:160].decode("ascii") + ("..." if len(text) > 160 else ""))
        if not original_only:
            for type_name in re.finditer(rb"Meshlink[A-Z][A-Za-z0-9_]*", text):
                remaining.add(type_name.group().decode("ascii"))
    for encoding, pattern in (
        ("utf-16-le", rb"(?:[\x20-\x7e]\x00){5,}"),
        ("utf-16-be", rb"(?:\x00[\x20-\x7e]){5,}"),
    ):
        for match in re.finditer(pattern, contents):
            text = match.group().decode(encoding)
            if "frida" in text.lower() and text.lower() != "friday":
                remaining.add(text[:160] + ("..." if len(text) > 160 else ""))
            if not original_only:
                remaining.update(re.findall(r"Meshlink[A-Z][A-Za-z0-9_]*", text))
    return sorted(remaining)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original-only", action="store_true")
    parser.add_argument("binaries", nargs="+", type=Path)
    args = parser.parse_args()

    for path in args.binaries:
        remaining = remaining_identifiers(path.read_bytes(), original_only=args.original_only)
        if remaining:
            examples = ", ".join(remaining[:12])
            raise SystemExit(f"{path}: {len(remaining)} legacy runtime identifiers remain: {examples}")

    scope = "original Frida" if args.original_only else "legacy runtime"
    print(f"No {scope} identifiers from the audited set remain")


if __name__ == "__main__":
    main()
