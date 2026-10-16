import plistlib
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
EXPECTED = {
    "subprojects/frida-core/lib/gadget/gadget-glue.c": {
        "meshlink_dylib_range=": 2,
        "meshlink_gadget_config=": 2,
    },
    "subprojects/frida-core/src/fruity/injector.vala": {
        "meshlink_dylib_range=": 1,
        "meshlink_gadget_config=": 1,
    },
    "subprojects/frida-gum/gum/backend-darwin/gumdarwinmapper.c": {
        "meshlink_dylib_range=": 1,
    },
    "subprojects/frida-gum/tests/core/mapper.c": {
        "meshlink_gadget_config": 1,
    },
}

for name, markers in EXPECTED.items():
    source = (ROOT / name).read_text(encoding="utf-8")
    for legacy in ("frida_dylib_range", "frida_gadget_config"):
        assert legacy not in source, f"{name}: legacy Darwin parameter {legacy}"
    for marker, count in markers.items():
        assert source.count(marker) == count, f"{name}: expected {count} occurrences of {marker}"

print("Darwin injection parameter producers and consumer agree")

PAYLOAD_GLUE = ROOT / "subprojects/frida-core/lib/payload"
for name, legacy, current in (
    ("thread-suspend-monitor-glue.c", "_frida_thread_suspend_monitor_", "_meshlink_thread_suspend_monitor_"),
    ("unwind-sitter-glue.c", "_frida_unwind_sitter_", "_meshlink_unwind_sitter_"),
):
    source = (PAYLOAD_GLUE / name).read_text(encoding="utf-8")
    assert legacy not in source, f"{name}: legacy payload entrypoint"
    assert current in source, f"{name}: missing payload entrypoint"

assert '"Frida"' not in (PAYLOAD_GLUE / "unwind-sitter-glue.c").read_text(encoding="utf-8")

fruity_injector = (ROOT / "subprojects/frida-core/src/fruity/injector.vala").read_text(encoding="utf-8")
gadget = (ROOT / "subprojects/frida-core/lib/gadget/gadget.vala").read_text(encoding="utf-8")
gadget_glue = (ROOT / "subprojects/frida-core/lib/gadget/gadget-glue.c").read_text(encoding="utf-8")
assert ".add_int_value (Random.int_range (49152, 65536))" in fruity_injector
assert ".add_string_value (\"pick-next\")" in fruity_injector
assert "27043" not in fruity_injector
assert 'Environment.set_thread_name ("net-io-%u".printf (listen_port))' in gadget
assert 'Environment.set_thread_name ("net-io-unix")' in gadget
assert r'/^net-io-(\d+)$/.match (name, 0, out info)' in fruity_injector
assert "rpc-listener-" not in gadget and "rpc-listener-" not in fruity_injector
assert 'worker_name = g_uuid_string_random ();' in gadget_glue
assert "worker_name[15] = '\\0';" in gadget_glue
assert 'g_thread_new (worker_name, run_worker_loop, NULL)' in gadget_glue
assert '"io-worker"' not in gadget_glue
assert '"rpc-worker"' not in gadget_glue

darwin_gadget = (ROOT / "subprojects/frida-core/lib/gadget/gadget-darwin.m").read_text(encoding="utf-8")
for name in (
    "detect_bundle_id",
    "detect_bundle_name",
    "detect_documents_dir",
    "has_objc_class",
    "set_thread_name",
    "detect_darwin_location_fields",
    "ensure_debugger_breakpoints_only",
    "allow_stolen_breakpoints",
    "break_and_resume",
    "break_and_detach",
):
    assert f"relay_gadget_environment_{name} (" in darwin_gadget, name
assert "frida_gadget_environment_" not in darwin_gadget

for name, identifier in (
    ("server/frida-server.plist", "io.meshlink.Server"),
    ("src/darwin/frida-helper.plist", "io.meshlink.Helper"),
):
    info = plistlib.loads((ROOT / "subprojects/frida-core" / name).read_bytes())
    assert info["CFBundleIdentifier"] == identifier
    assert info["CFBundleName"] == "Meshlink"

server_entitlements = plistlib.loads(
    (ROOT / "subprojects/frida-core/server/frida-server.xcent").read_bytes()
)
assert server_entitlements["application-identifier"] == "io.meshlink.Server"
assert 'Environment.get_variable ("MESHLINK_DTRACE_PREDICATE")' in (
    ROOT / "subprojects/frida-core/src/darwin/frida-helper-backend.vala"
).read_text(encoding="utf-8")
assert "identity = 'MeshlinkAgent'" in (
    ROOT / "subprojects/frida-core/lib/agent/meson.build"
).read_text(encoding="utf-8")

code_segment = (ROOT / "subprojects/frida-gum/gum/backend-darwin/gumcodesegment-darwin.c").read_text(encoding="utf-8")
assert 'gum_file_open_tmp ("io-XXXXXX.dylib", &dylib_path)' in code_segment
assert '"frida-XXXXXX.dylib"' not in code_segment

device_monitor = (ROOT / "subprojects/frida-core/src/fruity/device-monitor-macos.vala").read_text(encoding="utf-8")
assert 'new Darwin.GCD.DispatchQueue ("net.pairing.worker", Darwin.GCD.DispatchQueueAttr.SERIAL)' in device_monitor
assert "re.frida.fruity.remotepairing" not in device_monitor

simmy = (ROOT / "subprojects/frida-core/src/simmy/simmy-host-session-glue.m").read_text(encoding="utf-8")
assert 'dispatch_queue_create ("io.meshlink.simmy.queue", DISPATCH_QUEUE_SERIAL)' in simmy
assert "re.frida.simmy.queue" not in simmy

policyd = (ROOT / "subprojects/frida-core/src/darwin/policyd.h").read_text(encoding="utf-8")
server = (ROOT / "subprojects/frida-core/server/server.vala").read_text(encoding="utf-8")
assert '#define FRIDA_POLICYD_SERVICE_NAME "io.meshlink.policyd"' in policyd
assert "re.frida.policyd" not in policyd
assert 'Path.get_basename (args[0]) == "meshlink-policyd"' in server
assert '"frida-policyd"' not in server
