import sys

import frida


address, *command = sys.argv[1:]
if not command:
    raise SystemExit("usage: smoke-cmodule.py ADDRESS EXECUTABLE [ARG ...]")

device = frida.get_device_manager().add_remote_device(address)
pid = device.spawn(command)
try:
    session = device.attach(pid)
    try:
        device.resume(pid)
        messages = []
        script = session.create_script(
            """
            const module = new CModule(
                'int answer(void) { return 42; }',
                null,
                { toolchain: 'external' }
            );
            send(new NativeFunction(module.answer, 'int', [])());
            """,
            runtime="qjs",
        )
        script.on("message", lambda message, data: messages.append(message))
        script.load()
        assert messages == [{"type": "send", "payload": 42}], messages
        script.unload()
    finally:
        session.detach()
finally:
    try:
        device.kill(pid)
    except frida.ProcessNotFoundError:
        pass

print("External CModule passed")
