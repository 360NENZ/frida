from pathlib import Path


root = Path(__file__).resolve().parent.parent / "subprojects/frida-core/src"
client = (root / "android-helper/client.vala").read_text(encoding="utf-8")
helper = (root / "android-helper/org/tools/bridge/Helper.java").read_text(encoding="utf-8")
host = (root / "linux/linux-host-session.vala").read_text(encoding="utf-8")
dex = (root / "android-helper/helper.dex").read_bytes()

assert 'string helper_path = "/data/local/tmp/" + instance_id + ".dex";' in client
assert 'string helper_path = "/data/local/tmp/" + instance_id + ".dex";' in host
assert 'string socket_name = "/" + instance_id;' in client
assert '"localabstract:" + socket_name' in client
assert '"--nice-name=%s org.tools.bridge.Helper %s %s; rm -f %s; echo BYE."' in client
assert "args.length != 2" in helper
assert "new File(args[0]).delete();" in helper
assert "new LocalServerSocket(args[1])" in helper
assert helper.count("new Thread(UUID.randomUUID().toString().substring(0, 15))") == 2
assert dex.startswith(b"dex\n035\0")

for marker in (
    b"runtime-helper-",
    b"Connection Listener",
    b"Connection Handler",
    b"android.worker",
):
    assert marker not in dex, marker

print("Android helper source and embedded DEX use per-instance names")
