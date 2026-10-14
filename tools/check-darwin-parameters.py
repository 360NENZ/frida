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
