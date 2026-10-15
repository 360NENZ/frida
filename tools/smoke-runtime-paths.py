import sys
import re
from pathlib import Path

import frida


address, *command = sys.argv[1:]
if not command:
    raise SystemExit("usage: smoke-runtime-paths.py ADDRESS EXECUTABLE [ARG ...]")

device = frida.get_device_manager().add_remote_device(address)
pid = device.spawn(command)
try:
    session = device.attach(pid)
    try:
        device.resume(pid)
        for runtime in ("qjs", "v8"):
            messages = []
            script = session.create_script("hexdump(null);", runtime=runtime)
            script.on("message", lambda message, data: messages.append(message))
            script.load()
            assert len(messages) == 1, (runtime, messages)
            assert messages[0]["type"] == "error", (runtime, messages)
            assert "/meshlink/runtime/hexdump.js:" in messages[0]["stack"], (runtime, messages)
            script.unload()

            messages.clear()
            script = session.create_script(
                "send({legacy: typeof Frida, version: Meshlink.version});", runtime=runtime
            )
            script.on("message", lambda message, data: messages.append(message))
            script.load()
            assert len(messages) == 1, (runtime, messages)
            identity = messages[0]["payload"]
            assert identity["legacy"] == "undefined" and identity["version"], (runtime, identity)
            script.unload()

        if sys.platform == "linux":
            maps = Path(f"/proc/{pid}/maps").read_text(encoding="utf-8")
            assert not re.search(r"/memfd:runtime-(?:32|64|arm|arm64)\.so", maps)
            assert re.search(
                r"/memfd:[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}-(?:32|64)\.so",
                maps,
            ), "Expected a session-specific agent memfd"
    finally:
        session.detach()
finally:
    try:
        device.kill(pid)
    except frida.ProcessNotFoundError:
        pass

print("QuickJS and V8 runtime paths passed")
