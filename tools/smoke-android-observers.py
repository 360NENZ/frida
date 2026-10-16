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
GLIB_THREADS = {"gmain", "gdbus", "pool", "pool-spawner"}


def read_root(serial: str, command: str) -> str:
    return subprocess.run(
        ["adb", "-s", serial, "shell", "su", "-c", command],
        check=True,
        capture_output=True,
        text=True,
    ).stdout


def read_proc(serial: str, path: str) -> str:
    return read_root(serial, f"cat {path}")


def read_fd_targets(serial: str, pid: int) -> set[str]:
    return set(read_root(serial, f"readlink /proc/{pid}/fd/*").splitlines())


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("address")
    parser.add_argument("serial")
    args = parser.parse_args()

    device = frida.get_device_manager().add_remote_device(args.address)
    pid = device.spawn(["/system/bin/sleep", "300"])
    try:
        original_threads = set(read_proc(args.serial, f"/proc/{pid}/task/*/comm").splitlines())
        original_fds = read_fd_targets(args.serial, pid)
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
                    try:
                        script.unload()
                    except frida.InvalidOperationError:
                        pass

            maps = read_proc(args.serial, f"/proc/{pid}/maps")
            threads = read_proc(args.serial, f"/proc/{pid}/task/*/comm").splitlines()
            new_fds = read_fd_targets(args.serial, pid) - original_fds

            assert not re.search(r"frida", maps, re.IGNORECASE), "Legacy module path in maps"
            assert re.search(
                r"/memfd:[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}-(?:32|64|arm|arm64)\.so",
                maps,
            ), "Expected a session-specific agent memfd"
            assert not LEGACY_THREADS.intersection(threads), threads
            assert not any("frida" in name.lower() for name in threads), threads
            new_threads = set(threads) - original_threads
            assert not {
                name for name in new_threads
                if name in GLIB_THREADS or name.startswith("pool-")
            }, threads
            assert not any(
                re.search(r"frida|/memfd:runtime-(?:32|64|arm|arm64)\.so", path, re.IGNORECASE)
                for path in new_fds
            ), new_fds
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
