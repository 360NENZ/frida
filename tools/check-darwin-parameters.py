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
assert ".add_int_value (Random.int_range (49152, 65536))" in fruity_injector
assert ".add_string_value (\"pick-next\")" in fruity_injector
assert "27043" not in fruity_injector
