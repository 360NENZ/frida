from pathlib import Path


root = Path(__file__).resolve().parent.parent / "subprojects/frida-core"

socket = (root / "lib/base/socket.vala").read_text(encoding="utf-8")
assert '"Meshlink/"' not in socket
assert 'request_headers.replace ("User-Agent"' not in socket
assert 'get_response_headers ().replace ("Server"' not in socket

for name in ("lib/base/session.vala", "src/frida.vala"):
    source = (root / name).read_text(encoding="utf-8")
    assert "agent.set_software" not in source, name

certificate = (root / "lib/base/p2p-glue.c").read_text(encoding="utf-8")
assert "frida_oid_organization" not in certificate
assert 'X509_NAME_add_entry_by_txt (name, "O"' not in certificate

print("Network metadata contains no fixed runtime brand")
