# Matched Linux client

This archive contains the Python bindings and CLI built with the same
`frida-core` protocol as this fork's server. Official Frida Python/CLI packages
do not speak this fork's renamed D-Bus protocol. The server executable is
`bin/meshlinkd`; the Linux and Android Gadget attachment is `libmeshlink.so`.

Extract the archive, then from its root:

```sh
python3 -m venv .venv
.venv/bin/pip install 'colorama>=0.2.7,<1' 'prompt-toolkit>=2,<4' \
  'pygments>=2,<3' 'websockets>=13,<14'
site_dir="$(dirname "$(dirname "$(find "$PWD/lib" -name '_frida.abi3.so' -print -quit)")")"
PYTHONPATH="$site_dir" .venv/bin/python bin/frida-ps -H 127.0.0.1:39117
```

Use the same `PYTHONPATH` and Python executable with any script under `bin/`.
The fork's default control port is `39117`; use `meshlinkd -l ADDRESS` and the
matching client address to override it. A sidecar Gadget configuration for
`libmeshlink.so` must be named `libmeshlink.config`.
