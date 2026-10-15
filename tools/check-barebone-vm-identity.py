from pathlib import Path
import ast
import json


workspace = Path(__file__).resolve().parent.parent
core = workspace / "subprojects/frida-core"
source = (core / "tests/vm.py").read_text(encoding="utf-8")
names = {
    "VIRTIO_SERIAL_ID",
    "GDB_ID",
    "DEBUGCON_ID",
    "PORT_NAME",
    "LINK_ANSWER_MARKER",
    "LINK_GONE_MARKER",
    "MODULE_LOAD_FAILED_MARKER",
}
values = {
    node.targets[0].id: ast.literal_eval(node.value)
    for node in ast.parse(source).body
    if isinstance(node, ast.Assign)
    and len(node.targets) == 1
    and isinstance(node.targets[0], ast.Name)
    and node.targets[0].id in names
}
assert values.keys() == names
assert values == {
    "VIRTIO_SERIAL_ID": "meshlink-vserial",
    "GDB_ID": "meshlink-gdb",
    "DEBUGCON_ID": "meshlink-debugcon",
    "PORT_NAME": "meshlink",
    "LINK_ANSWER_MARKER": "meshlink-link ",
    "LINK_GONE_MARKER": "meshlink-link-gone",
    "MODULE_LOAD_FAILED_MARKER": "meshlink-kmod-load-failed",
}
assert "socket,id=meshlink,path={args.socket}" in source
assert "virtserialport,chardev=meshlink,name={port}" in source
assert "exec 3<> /dev/meshlink" in source
assert "frida-vserial" not in source

for name in ("win9x", "winnt"):
    config = json.loads(
        (core / f"src/barebone/agent/etc/{name}.json").read_text(encoding="utf-8")
    )
    assert config["agent"]["transport"]["bus"] == f'{values["VIRTIO_SERIAL_ID"]}.0'

print("Barebone VM port names match guest configurations")
