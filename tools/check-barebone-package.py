from pathlib import Path
import json
import tomllib


workspace = Path(__file__).resolve().parent.parent
root = workspace / "subprojects/frida-core/src/barebone/agent"
manifest = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
lock = tomllib.loads((root / "Cargo.lock").read_text(encoding="utf-8"))
package = "meshlink-barebone-agent"
library = "meshlink_barebone_agent"

assert manifest["package"]["name"] == package
assert manifest["lib"]["name"] == library
assert manifest["bin"][0]["name"] == package
assert any(entry["name"] == package for entry in lock["package"])
assert not any(entry["name"] == "frida-barebone-agent" for entry in lock["package"])
assert f"use {library} as _;" in (root / "src/main.rs").read_text(encoding="utf-8")

for name in ("physical", "vz", "xnu", "win9x", "winnt"):
    config = json.loads((root / f"etc/{name}.json").read_text(encoding="utf-8"))
    assert Path(config["agent"]["path"]).name == package, name

for name in ("linux", "macos"):
    makefile = (root / name / "Makefile").read_text(encoding="utf-8")
    assert f"lib{library}.a" in makefile
    assert "libfrida_barebone_agent.a" not in makefile

workflow = (workspace / ".github/workflows/ci.yml").read_text(encoding="utf-8")
release_script = (workspace / ".github/scripts/rename-release-assets.sh").read_text(
    encoding="utf-8"
)
assert "frida-barebone-agent" not in workflow + release_script
assert f"/release/{package}" in workflow
assert "macos/meshlink-agent.kext" in workflow
assert f"{package}-*" in release_script

print("Barebone Cargo package and CI artifact paths match")
