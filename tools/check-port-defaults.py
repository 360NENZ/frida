import re
from pathlib import Path


root = Path(__file__).resolve().parent.parent / "subprojects/frida-core"
socket = (root / "lib/base/socket.vala").read_text(encoding="utf-8")
ports = dict(
    re.findall(r"public const uint16 DEFAULT_(CONTROL|CLUSTER)_PORT = (\d+);", socket)
)
assert ports == {"CONTROL": "39117", "CLUSTER": "39127"}, ports

barebone = (root / "src/barebone/agent/linux/README.md").read_text(encoding="utf-8")
assert "meshlinkd --device barebone -l 127.0.0.1:39117" in barebone
assert "adb forward tcp:39117" in barebone
assert "27042" not in barebone and "27052" not in barebone

print("Control, cluster, and barebone endpoint defaults agree")
