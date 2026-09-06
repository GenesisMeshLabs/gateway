"""Create a checksummed, explicitly allowlisted gateway distribution archive."""
import argparse
import hashlib
import json
import subprocess
import tomllib
import zipfile
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--platform", required=True)
    parser.add_argument("--output", type=Path, default=Path(".local/dist"))
    args = parser.parse_args()
    if not all(c.isalnum() or c in "-_" for c in args.platform):
        parser.error("platform must contain only letters, digits, hyphens or underscores")
    root = Path(__file__).resolve().parents[1]
    version = tomllib.loads((root / "Cargo.toml").read_text())["package"]["version"]
    actual = subprocess.check_output([str(args.binary.resolve()), "--version"], text=True).strip()
    if actual != f"genesis-mesh-gateway {version}":
        parser.error("binary version does not match Cargo.toml")
    args.output.mkdir(parents=True, exist_ok=True)
    archive = args.output / f"genesis-mesh-gateway-{version}-{args.platform}.zip"
    files = ["README.md", "docs/distribution.md", "docs/operations.md", "docs/services.md", "docs/mesh.md", "ui/openapi.json", "ui/services.json",
             "deploy/compose.yml", "deploy/kubernetes.yaml"]
    binary_hash = hashlib.sha256(args.binary.read_bytes()).hexdigest()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        bundle.write(args.binary, args.binary.name)
        for file in files:
            bundle.write(root / file, file)
        bundle.writestr("manifest.json", json.dumps({"version": version, "platform": args.platform,
                        "binary": args.binary.name, "binary_sha256": binary_hash}, indent=2))
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    archive.with_suffix(".zip.sha256").write_text(f"{digest}  {archive.name}\n")
    print(archive)


if __name__ == "__main__":
    main()
