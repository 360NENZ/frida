from pathlib import Path


root = Path(__file__).resolve().parent.parent / "subprojects/frida-core"
injector = (root / "src/droidy/injector.vala").read_text(encoding="utf-8")
gadget = (root / "lib/gadget/gadget.vala").read_text(encoding="utf-8")
host_session = (root / "src/droidy/droidy-host-session.vala").read_text(encoding="utf-8")

assert 'string instance_id = Uuid.string_random ().replace ("-", "");' in injector
for directory in ('"/data/local/tmp/"', '"/data/data/" + package + "/"'):
    for extension in (".so", ".config"):
        assert f'{directory} + instance_id + "{extension}"' in injector
assert "string unix_socket_path = instance_id;" in injector
assert '"unix:" + unix_socket_path' in injector
assert '"localabstract:" + gadget.unix_socket_path' in host_session
assert 'stem + ".config"' in gadget
assert "runtime-gadget-" not in injector
assert "/gadget.so" not in injector and "/gadget.config" not in injector

print("Droidy Gadget paths and abstract socket share a session-specific identity")
