from pathlib import Path


root = Path(__file__).resolve().parent.parent / "subprojects/frida-core/src"
host = (root / "linux/linux-host-session.vala").read_text(encoding="utf-8")
payload = (root / "linux/helpers/zymbiote.c").read_text(encoding="utf-8")

assert 'string name = "/" + Uuid.string_random ().replace ("-", "");' in host
assert "server_name = name;" in host
assert "payload.write_string (cursor, server_name);" in host
assert 'new UnixSocketAddress.with_type (name, -1, UnixSocketAddressType.ABSTRACT)' in host
assert '"/runtime-worker-" + Uuid.string_random ()' not in host
assert "zymbiote.socket_path[i]" in payload

print("Zymbiote control socket has no fixed runtime prefix")
