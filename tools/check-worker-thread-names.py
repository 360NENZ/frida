from pathlib import Path


root = Path(__file__).resolve().parent.parent / "subprojects/frida-core"
prospero = (root / "src/prospero/binjector.vala").read_text(encoding="utf-8")
kernel = (root / "src/barebone/agent/linux/meshlink-kmod.c").read_text(encoding="utf-8")
native = (root / "src/barebone/agent/src/linux/native.rs").read_text(encoding="utf-8")
name_module = (root / "src/barebone/agent/src/linux/thread_name.rs").read_text(encoding="utf-8")
main_glue = (root / "src/frida-glue.c").read_text(encoding="utf-8")
container = (root / "src/agent-container.vala").read_text(encoding="utf-8")
agent = (root / "lib/agent/agent.vala").read_text(encoding="utf-8")
linux_host = (root / "src/linux/linux-host-session.vala").read_text(encoding="utf-8")
darwin_helper = (root / "src/darwin/frida-helper-service.vala").read_text(encoding="utf-8")
gum_linux = (
    Path(__file__).resolve().parent.parent
    / "subprojects/frida-gum/gum/backend-linux/gumprocess-linux.c"
).read_text(encoding="utf-8")

assert "AGENT_THREAD_NAME" not in prospero
assert "Uuid.string_random ().substring (0, 15)" in prospero
assert "process.write (name, thread_name.data[0:thread_name.length + 1])" in prospero

assert '"agent-worker"' not in kernel
assert '"op-worker"' not in kernel
assert "get_random_bytes (&nonce, sizeof (nonce))" in kernel
assert kernel.count('kthread_run (') == 2
assert kernel.count('"%s", name)') == 2
assert 'c"meshlink-worker"' not in native
assert "make_thread_name(" in native
assert "SEQUENCE.fetch_add(1, Ordering::Relaxed)" in name_module
assert "name.as_ptr().cast()" in native

assert '"main-worker"' not in main_glue
assert "thread_name[15] = '\\0';" in main_glue
assert "g_thread_new (thread_name, run_main_loop, NULL)" in main_glue
assert '"agent-container"' not in container
assert "new Thread<bool> (Uuid.string_random ().substring (0, 15), run)" in container

assert 'new Thread<void> (Uuid.string_random ().substring (0, 15), run_emulated_agent)' in agent
assert '"emulated-worker"' not in agent
assert 'new Thread<void> (Uuid.string_random ().substring (0, 15), run)' in linux_host
assert '"android-worker"' not in linux_host
assert 'new Thread<int> (Uuid.string_random ().substring (0, 15), () =>' in darwin_helper
assert '"helper-worker"' not in darwin_helper
assert "worker_name = g_uuid_string_random ();" in gum_linux
assert "worker_name[15] = '\\0';" in gum_linux
assert "g_thread_new (worker_name, gum_linux_handle_modify_thread_comms," in gum_linux
assert '"gum-modify-thread-worker"' not in gum_linux

for path, legacy, replacement in (
    (
        "lib/base/p2p.vala",
        "cert-worker",
        "new Thread<bool> (Uuid.string_random ().substring (0, 15), () =>",
    ),
    (
        "src/windows/frida-helper-process.vala",
        "helper-factory",
        "new Thread<bool> (Uuid.string_random ().substring (0, 15), obtain_worker)",
    ),
    (
        "src/fruity/device-monitor-portable.vala",
        "usb-worker",
        "new Thread<void> (Uuid.string_random ().substring (0, 15), perform_usb_work)",
    ),
    (
        "src/qnx/qinjector.vala",
        "pulse-reader",
        "new Thread<void> (Uuid.string_random ().substring (0, 15), process_io)",
    ),
    (
        "src/prospero/binjector.vala",
        "app-launch",
        "new Thread<void> (Uuid.string_random ().substring (0, 15), request.run)",
    ),
):
    source = (root / path).read_text(encoding="utf-8")
    assert f'"{legacy}"' not in source, path
    assert replacement in source, path

print("Prospero, kernel, and core worker names are per-instance")
