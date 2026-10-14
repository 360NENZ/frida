import subprocess
import sys
import threading

import frida


address, component = sys.argv[1:]
package = component.split("/", 1)[0]
device = frida.get_device_manager().add_remote_device(address)
spawned = []
spawn_added = threading.Event()


def on_spawn_added(spawn):
    if spawn.identifier == package:
        spawned.append(spawn)
        spawn_added.set()


device.on("spawn-added", on_spawn_added)
device.enable_spawn_gating()
launcher = None
try:
    subprocess.run(["adb", "shell", "am", "force-stop", package], check=True)
    launcher = subprocess.Popen(
        ["adb", "shell", "am", "start", "-n", component],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert spawn_added.wait(30), f"No gated spawn for {package}"
    pid = spawned[0].pid
    assert any(s.pid == pid for s in device.enumerate_pending_spawn())
    session = device.attach(pid)
    try:
        script = session.create_script("rpc.exports = { ping() { return 42; } };")
        script.load()
        assert script.exports_sync.ping() == 42
        device.resume(pid)
    finally:
        session.detach()
    stdout, stderr = launcher.communicate(timeout=30)
    assert launcher.returncode == 0, (stdout, stderr)
finally:
    device.disable_spawn_gating()
    for spawn in spawned:
        if any(s.pid == spawn.pid for s in device.enumerate_pending_spawn()):
            device.resume(spawn.pid)
    if launcher is not None and launcher.poll() is None:
        launcher.kill()
        launcher.communicate()

print(f"Android spawn gating passed for {package}")
