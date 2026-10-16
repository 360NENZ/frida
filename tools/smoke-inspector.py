import json
import socket
import sys
from urllib.request import urlopen

import frida


address, *command = sys.argv[1:]
if not command:
    raise SystemExit("usage: smoke-inspector.py ADDRESS EXECUTABLE [ARG ...]")

device = frida.get_device_manager().add_remote_device(address)
pid = device.spawn(command)
try:
    session = device.attach(pid)
    try:
        script = session.create_script("rpc.exports = { ping() { return 1; } };", runtime="v8")
        script.load()
        device.resume(pid)
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            inspector_port = probe.getsockname()[1]
        script.enable_debugger(inspector_port)
        try:
            with urlopen(f"http://127.0.0.1:{inspector_port}/json/version", timeout=5) as response:
                version = json.load(response)
            with urlopen(f"http://127.0.0.1:{inspector_port}/json/list", timeout=5) as response:
                targets = json.load(response)
            assert version["Browser"].startswith("Runtime/v")
            assert len(targets) == 1
            assert targets[0]["description"] == "Runtime Agent"
            assert targets[0]["faviconUrl"] == ""
        finally:
            script.disable_debugger()
    finally:
        session.detach()
finally:
    try:
        device.kill(pid)
    except frida.ProcessNotFoundError:
        pass

print("Inspector metadata passed")
