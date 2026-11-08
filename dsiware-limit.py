"""Raise the DSiWare title limit (40) of the 3DS HOME Menu to N <= 256 with three Luma3DS IPS patches.

  python3 -I dsiware-limit.py --identify [--dumps DIR]
  python3 -I dsiware-limit.py --max N [--dumps DIR] [--out DIR]

Reads every decrypted code dump DIR/<titleID>.dec.code (default dumps/) and picks the target whose SHA-256
matches, from targets/<role>/<build>/target.py. A dump without a target is refused; --identify lists the dumps,
their hashes and their targets without building anything. Writes
  OUT/luma/titles/<titleID>/code.ips   HOME Menu, System Settings > Data Management
  OUT/luma/sysmodules/<titleID>.ips    NS
plus OUT/patched/<titleID>.code and OUT/manifest.tsv for the emulator tests (default OUT is out/max-N).
Copy OUT/luma to the SD root. What each patch does is in the docstring of its target.py.
"""
import argparse
import hashlib
import importlib.util
import sys
from pathlib import Path
from typing import NamedTuple

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))  # targets import patchkit; python -I does not add the script directory
import patchkit  # noqa: E402

ROLES = ("home", "settings", "ns")
TITLES = {  # title ID: (role, region), from https://www.3dbrew.org/wiki/Title_list
    "0004003000008202": ("home", "JPN"),
    "0004003000008F02": ("home", "USA"),
    "0004003000009802": ("home", "EUR"),
    "000400300000A102": ("home", "CHN"),
    "000400300000A902": ("home", "KOR"),
    "000400300000B102": ("home", "TWN"),
    "0004001000020000": ("settings", "JPN"),
    "0004001000021000": ("settings", "USA"),
    "0004001000022000": ("settings", "EUR"),
    "0004001000026000": ("settings", "CHN"),
    "0004001000027000": ("settings", "KOR"),
    "0004001000028000": ("settings", "TWN"),
    "0004013000008002": ("ns", "all"),
}


class Target(NamedTuple):
    role: str
    dir: Path
    module: object

    def __str__(self):
        return str(self.dir.relative_to(HERE))


def load_targets():
    targets = {}
    for path in sorted(HERE.glob("targets/*/*/target.py")):
        role = path.parent.parent.name
        assert role in ROLES, f"{path}: unknown role {role!r}, expected one of {ROLES}"
        spec = importlib.util.spec_from_file_location(f"targets.{role}.{path.parent.name}", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        assert module.SHA256 not in targets, f"{path}: SHA-256 already taken by {targets[module.SHA256]}"
        targets[module.SHA256] = Target(role, path.parent, module)
    return targets


def luma_path(tid, role):
    return f"sysmodules/{tid}.ips" if role == "ns" else f"titles/{tid}/code.ips"


def scan(dumps_dir, targets):
    """[(title ID, dump path, code, sha256, target or None, problem or None)] for every dump in dumps_dir."""
    found = []
    for path in sorted(dumps_dir.glob("*.dec.code")):
        tid = path.name.removesuffix(".dec.code").upper()
        code = path.read_bytes()
        sha = hashlib.sha256(code).hexdigest()
        target, problem = targets.get(sha), None
        if tid not in TITLES:
            problem = "not a HOME Menu, System Settings or NS title ID"
        elif target is None:
            problem = "no target for this SHA-256 (CONTRIBUTING.md)"
        elif target.role != TITLES[tid][0]:
            problem = f"the file name says {TITLES[tid][0]}, but the dump is the {target.role} build {target}"
        found.append((tid, path, code, sha, None if problem else target, problem))
    return found


def identify(found):
    for tid, _, _, sha, target, problem in found:
        role, region = TITLES.get(tid, ("?", "?"))
        print(f"{tid}  {role:8}  {region:3}  {sha}  {target or problem}")


def main():
    if not __debug__:
        sys.exit("run without -O: the patch checks are asserts")
    ap = argparse.ArgumentParser(description="Raise the DSiWare limit of the HOME Menu, System Settings and NS.")
    ap.add_argument("--max", type=int, help="DSiWare limit, 2..256")
    ap.add_argument("--identify", action="store_true", help="list the dumps and their targets, build nothing")
    ap.add_argument("--dumps", type=Path, default=HERE / "dumps", help="directory with <titleID>.dec.code")
    ap.add_argument("--out", type=Path, help="output directory (default out/max-N)")
    args = ap.parse_args()
    found = scan(args.dumps, load_targets())
    if not found:
        sys.exit(f"no <titleID>.dec.code in {args.dumps}")
    if args.identify:
        identify(found)
        return
    n = args.max
    if n is None or not 2 <= n <= 256:
        sys.exit("--max must be 2..256")

    builds = []
    for tid, path, code, _, target, _ in found:
        if target is None:
            continue
        try:
            recs = target.module.records(n, code)
        except ValueError as e:
            sys.exit(f"--max {n} does not fit {target}: {e}")
        ips, patched = patchkit.build(tid, code, recs)
        builds.append((tid, path, target, recs, ips, patched))

    out = args.out or HERE / "out" / f"max-{n}"
    manifest = []
    for tid, path, target, recs, ips, patched in builds:
        ips_path = out / "luma" / luma_path(tid, target.role)
        patched_path = out / "patched" / f"{tid}.code"
        for p, data in ((ips_path, ips), (patched_path, patched)):
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)
        manifest.append(f"{tid}\t{target.role}\t{target.dir}\t{path.resolve()}\t{patched_path.resolve()}\t{ips_path.resolve()}\n")
        print(f"{tid}: {target}, {len(recs)} records, {len(ips)} bytes, sha256 {hashlib.sha256(ips).hexdigest()}")
    if builds:
        (out / "manifest.tsv").write_text("".join(manifest))
        print(f"-> {out}/luma (copy to the SD root)")
    missing = [r for r in ROLES if r not in {b[2].role for b in builds}]
    if missing:
        print(f"note: nothing built for {', '.join(missing)}; the three patches belong together (README.md)")
    refused = [(tid, problem) for tid, _, _, _, target, problem in found if target is None]
    for tid, problem in refused:
        print(f"{tid}: refused, {problem}", file=sys.stderr)
    sys.exit(1 if refused else 0)


if __name__ == "__main__":
    main()
