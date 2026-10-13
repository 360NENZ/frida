# Matched Windows client

These wheels contain the Python bindings and CLI built with this fork's
protocol. Install them in a dedicated virtual environment, not over an
existing Frida installation. Python 3.12 x64 is the tested runtime.

From the extracted archive in PowerShell:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --no-index --find-links .\wheels frida frida-tools
.\.venv\Scripts\frida-ps.exe -H 127.0.0.1:39117
```

For a USB-connected Android device, forward the fork's server port first:

```powershell
adb forward tcp:39117 tcp:39117
```

The server listens on `127.0.0.1:39117` by default. The archive is named
`meshlink-client-windows-x86_64` to distinguish it from upstream Frida;
Python module and CLI entry-point names remain `frida` inside the isolated
environment for compatibility with existing tooling.
