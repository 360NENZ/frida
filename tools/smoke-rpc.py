import asyncio
import sys

import frida
import frida.aio


address, *command = sys.argv[1:]
if not command:
    raise SystemExit("usage: smoke-rpc.py ADDRESS EXECUTABLE [ARG ...]")


def check_sync():
    device = frida.get_device_manager().add_remote_device(address)
    pid = device.spawn(command)
    try:
        session = device.attach(pid)
        try:
            script = session.create_script(
                "rpc.exports = { add(a, b) { return a + b; }, "
                "async twice(value) { return value * 2; } };"
            )
            script.load()
            device.resume(pid)
            assert sorted(script.list_exports_sync()) == ["add", "twice"]
            assert script.exports_sync.add(2, 3) == 5
        finally:
            session.detach()
    finally:
        try:
            device.kill(pid)
        except frida.ProcessNotFoundError:
            pass


async def check_async():
    manager = frida.aio.get_device_manager()
    device = await manager.add_remote_device(address)
    pid = await device.spawn(command)
    try:
        session = await device.attach(pid)
        try:
            script = await session.create_script(
                "rpc.exports = { async twice(value) { return value * 2; } };"
            )
            await script.load()
            await device.resume(pid)
            assert await script.exports.twice(7) == 14
        finally:
            await session.detach()
    finally:
        try:
            await device.kill(pid)
        except frida.ProcessNotFoundError:
            pass


check_sync()
asyncio.run(check_async())
print("Synchronous and asynchronous RPC passed")
