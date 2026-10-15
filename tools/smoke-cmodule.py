import argparse
import json

import frida


parser = argparse.ArgumentParser()
parser.add_argument("--toolchain", choices=("external", "internal"), default="external")
parser.add_argument("address")
parser.add_argument("command", nargs=argparse.REMAINDER)
args = parser.parse_args()
address, command = args.address, args.command
if not command:
    raise SystemExit("usage: smoke-cmodule.py ADDRESS EXECUTABLE [ARG ...]")

device = frida.get_device_manager().add_remote_device(address)
pid = device.spawn(command)
try:
    session = device.attach(pid)
    try:
        device.resume(pid)
        messages = []
        source = "#include <gum/gumprocess.h>\nint answer(void) { return 42; }"
        script = session.create_script(
            f"const module = new CModule({json.dumps(source)}, null, "
            f"{{ toolchain: '{args.toolchain}' }});"
            "send(new NativeFunction(module.answer, 'int', [])());",
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

print(f"{args.toolchain.capitalize()} CModule passed")
