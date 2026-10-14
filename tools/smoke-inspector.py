import json
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
        script.enable_debugger(39229)
        try:
            with urlopen("http://127.0.0.1:39229/json/version", timeout=5) as response:
                version = json.load(response)
            with urlopen("http://127.0.0.1:39229/json/list", timeout=5) as response:
                targets = json.load(response)
            assert version["Browser"].startswith("Meshlink/v")
            assert len(targets) == 1
            assert targets[0]["description"] == "Meshlink Agent"
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
