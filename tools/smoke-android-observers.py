import argparse
import re
import subprocess

import frida


LEGACY_THREADS = {
    "agent-worker",
    "android-worker",
    "emulated-worker",
    "gum-js-loop",
    "gum-modify-thread-worker",
    "js-event-loop",
    "main-worker",
    "rpc-worker",
}


def read_proc(serial: str, path: str) -> str:
    return subprocess.run(
        ["adb", "-s", serial, "shell", "su", "-c", f"cat {path}"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("address")
    parser.add_argument("serial")
    args = parser.parse_args()

    device = frida.get_device_manager().add_remote_device(args.address)
    pid = device.spawn(["/system/bin/sleep", "60"])
    try:
        session = device.attach(pid)
        try:
            device.resume(pid)
            for runtime in ("qjs", "v8"):
                script = session.create_script(
                    "rpc.exports = { ping() { return 1; } };", runtime=runtime
                )
                script.load()
                try:
                    assert script.exports_sync.ping() == 1, runtime
                finally:
                    script.unload()

            maps = read_proc(args.serial, f"/proc/{pid}/maps")
            threads = read_proc(args.serial, f"/proc/{pid}/task/*/comm").splitlines()

            assert not re.search(r"frida", maps, re.IGNORECASE), "Legacy module path in maps"
            assert re.search(
                r"/memfd:[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}-(?:32|64|arm|arm64)\.so",
                maps,
            ), "Expected a session-specific agent memfd"
            assert not LEGACY_THREADS.intersection(threads), threads
            assert not any("frida" in name.lower() for name in threads), threads
            print(f"Android pid {pid}: {len(threads)} threads, randomized agent mapping")
            print("Thread names:", ", ".join(threads))
        finally:
            session.detach()
    finally:
        try:
            device.kill(pid)
        except frida.ProcessNotFoundError:
            pass


if __name__ == "__main__":
    main()
