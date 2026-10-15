from pathlib import Path


root = Path(__file__).resolve().parent.parent / "subprojects/frida-core"
prospero = (root / "src/prospero/binjector.vala").read_text(encoding="utf-8")
kernel = (root / "src/barebone/agent/linux/meshlink-kmod.c").read_text(encoding="utf-8")

assert "AGENT_THREAD_NAME" not in prospero
assert "Uuid.string_random ().substring (0, 15)" in prospero
assert "process.write (name, thread_name.data[0:thread_name.length + 1])" in prospero

assert '"agent-worker"' not in kernel
assert '"op-worker"' not in kernel
assert "get_random_bytes (&nonce, sizeof (nonce))" in kernel
assert kernel.count('kthread_run (') == 2
assert kernel.count('"%s", name)') == 2

print("Prospero and Linux kernel worker names are per-instance")
