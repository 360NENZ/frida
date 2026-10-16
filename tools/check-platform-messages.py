from pathlib import Path


core = Path(__file__).resolve().parent.parent / "subprojects/frida-core"

darwin_helper = (core / "src/darwin/frida-helper-backend-glue.m").read_text(encoding="utf-8")
assert 'withDescription:@"process termination requested"' in darwin_helper
assert '"killed from Frida"' not in darwin_helper

vz_memory = (core / "src/barebone/vz-physical-memory.vala").read_text(encoding="utf-8")
assert '"the service needs root or the com.apple.system-task-ports entitlement"' in vz_memory
assert "frida-core needs root" not in vz_memory

freebsd_injector = (core / "src/freebsd/binjector-glue.c").read_text(encoding="utf-8")
assert freebsd_injector.count('" try running as root"') == 2
assert "try running Frida as root" not in freebsd_injector

print("Platform runtime messages contain no legacy product name")
