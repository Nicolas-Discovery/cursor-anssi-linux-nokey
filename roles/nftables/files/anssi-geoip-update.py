#!/usr/bin/env python3
"""anssi-geoip-update - refresh nftables GeoIP allow/deny sets.

Reads /etc/anssi-geoip.yaml, downloads per-country zone files from the
configured provider (default: ipdeny.com) and writes:

  * <output_v4> / <output_v6>:
        nftables include files defining sets `geoip_allow_v4` and `geoip_allow_v6`
        with the union of CIDRs from allowed_continents + allowed_countries,
        minus blocked_countries.

  * <output_blocked_v4> / <output_blocked_v6>:
        nftables include files defining sets `geoip_block_v4` and `geoip_block_v6`
        with the CIDRs of explicitly blocked countries (used to override
        whitelist or to log them separately).

After regenerating the files, when called with --apply, it reloads nftables
via `systemctl reload nftables`.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
import urllib.request
import urllib.error
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.stderr.write("python3-yaml is required\n")
    sys.exit(2)


# Continent -> ISO-3166 alpha-2 country list (ipdeny convention, lowercase).
# This mapping is intentionally embedded so the script keeps working without
# Internet access for the mapping itself - only the zone files are fetched.
CONTINENT_COUNTRIES: dict[str, list[str]] = {
    "AF": [  # Africa
        "dz", "ao", "bj", "bw", "bf", "bi", "cm", "cv", "cf", "td", "km", "cd",
        "cg", "ci", "dj", "eg", "gq", "er", "et", "ga", "gm", "gh", "gn", "gw",
        "ke", "ls", "lr", "ly", "mg", "mw", "ml", "mr", "mu", "yt", "ma", "mz",
        "na", "ne", "ng", "re", "rw", "sh", "st", "sn", "sc", "sl", "so", "za",
        "ss", "sd", "sz", "tz", "tg", "tn", "ug", "eh", "zm", "zw",
    ],
    "AS": [  # Asia
        "af", "am", "az", "bh", "bd", "bt", "bn", "kh", "cn", "cy", "ge", "hk",
        "in", "id", "ir", "iq", "il", "jp", "jo", "kz", "kp", "kr", "kw", "kg",
        "la", "lb", "mo", "my", "mv", "mn", "mm", "np", "om", "pk", "ps", "ph",
        "qa", "sa", "sg", "lk", "sy", "tw", "tj", "th", "tl", "tr", "tm", "ae",
        "uz", "vn", "ye",
    ],
    "EU": [  # Europe (geographic - includes RU, UA, TR-european part etc.)
        "al", "ad", "at", "by", "be", "ba", "bg", "hr", "cz", "dk", "ee", "fo",
        "fi", "fr", "de", "gi", "gr", "gg", "hu", "is", "ie", "im", "it", "je",
        "lv", "li", "lt", "lu", "mt", "md", "mc", "me", "nl", "mk", "no", "pl",
        "pt", "ro", "ru", "sm", "rs", "sk", "si", "es", "se", "ch", "ua", "gb",
        "va", "ax", "sj",
    ],
    "NA": [  # North America (geographic)
        "ai", "ag", "aw", "bs", "bb", "bz", "bm", "bq", "vg", "ca", "ky", "cr",
        "cu", "cw", "dm", "do", "sv", "gl", "gd", "gp", "gt", "ht", "hn", "jm",
        "mq", "mx", "ms", "ni", "pa", "pr", "bl", "kn", "lc", "mf", "pm", "vc",
        "sx", "tt", "tc", "us", "vi",
    ],
    "OC": [  # Oceania
        "as", "au", "ck", "fj", "pf", "gu", "ki", "mh", "fm", "nr", "nc", "nz",
        "nu", "nf", "mp", "pw", "pg", "pn", "ws", "sb", "tk", "to", "tv", "vu",
        "wf",
    ],
    "SA": [  # South America
        "ar", "bo", "br", "cl", "co", "ec", "fk", "gf", "gy", "py", "pe", "sr",
        "uy", "ve",
    ],
    "AN": [  # Antarctica
        "aq", "bv", "tf", "gs", "hm",
    ],
}


def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def http_get(url: str, timeout: int = 30) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "anssi-geoip-update/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        return resp.read()


def fetch_zone(base_url: str, country: str, family: str, cache_dir: Path) -> list[str]:
    """Return the list of CIDRs for a country in the given family ('v4'|'v6').

    Caches the file under cache_dir; on network failure, falls back to cache.
    """
    suffix = "ipv4" if family == "v4" else "ipv6"
    fname = f"{country}.{suffix}.zone"
    target = cache_dir / fname

    url = f"{base_url}/{country}-aggregated.zone"
    try:
        data = http_get(url)
        target.write_bytes(data)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
        if not target.exists():
            raise RuntimeError(f"no network and no cache for {country}/{family}: {exc}") from exc

    return [
        line.strip()
        for line in target.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]


def expand_countries(cfg: dict) -> set[str]:
    """Compute effective ALLOWED country set after applying every rule."""
    countries: set[str] = set()
    for cont in cfg.get("allowed_continents") or []:
        countries.update(CONTINENT_COUNTRIES.get(cont.upper(), []))
    countries.update(c.lower() for c in (cfg.get("allowed_countries") or []))
    blocked = {c.lower() for c in (cfg.get("blocked_countries") or [])}
    return countries - blocked


def write_set(path: str, name: str, family: str, cidrs: list[str]) -> None:
    """Write a single nftables include file declaring an `set` element list."""
    family_attr = "ipv4_addr" if family == "v4" else "ipv6_addr"
    tmpfd, tmppath = tempfile.mkstemp(prefix="anssi-geoip-", dir=os.path.dirname(path))
    os.close(tmpfd)
    with open(tmppath, "w", encoding="utf-8") as fh:
        fh.write(f"# Auto-generated by anssi-geoip-update for set {name}\n")
        fh.write(f"# Members: {len(cidrs)}\n")
        fh.write(
            "set " + name + " {\n"
            f"    type {family_attr};\n"
            "    flags interval;\n"
            "    auto-merge;\n"
        )
        if cidrs:
            fh.write("    elements = {\n")
            chunked = []
            for c in sorted(set(cidrs)):
                chunked.append("        " + c)
            fh.write(",\n".join(chunked))
            fh.write("\n    }\n")
        fh.write("}\n")
    os.chmod(tmppath, 0o640)
    os.replace(tmppath, path)


def main() -> int:
    parser = argparse.ArgumentParser(description="Refresh ANSSI GeoIP nftables sets.")
    parser.add_argument("--config", default="/etc/anssi-geoip.yaml")
    parser.add_argument("--apply", action="store_true", help="reload nftables after update")
    args = parser.parse_args()

    cfg = load_config(args.config)
    cache_dir = Path(cfg["cache_dir"])
    cache_dir.mkdir(parents=True, exist_ok=True)

    allowed = sorted(expand_countries(cfg))
    blocked = sorted({c.lower() for c in (cfg.get("blocked_countries") or [])})

    allow_v4: list[str] = []
    allow_v6: list[str] = []
    block_v4: list[str] = []
    block_v6: list[str] = []

    for cc in allowed:
        try:
            allow_v4.extend(fetch_zone(cfg["base_url_v4"], cc, "v4", cache_dir))
            allow_v6.extend(fetch_zone(cfg["base_url_v6"], cc, "v6", cache_dir))
        except RuntimeError as exc:
            sys.stderr.write(f"WARN: {exc}\n")

    for cc in blocked:
        try:
            block_v4.extend(fetch_zone(cfg["base_url_v4"], cc, "v4", cache_dir))
            block_v6.extend(fetch_zone(cfg["base_url_v6"], cc, "v6", cache_dir))
        except RuntimeError as exc:
            sys.stderr.write(f"WARN: {exc}\n")

    write_set(cfg["output_v4"], "geoip_allow_v4", "v4", allow_v4)
    write_set(cfg["output_v6"], "geoip_allow_v6", "v6", allow_v6)
    write_set(cfg["output_blocked_v4"], "geoip_block_v4", "v4", block_v4)
    write_set(cfg["output_blocked_v6"], "geoip_block_v6", "v6", block_v6)

    if args.apply:
        try:
            subprocess.run(
                ["nft", "-c", "-f", "/etc/nftables.conf"],
                check=True,
                capture_output=True,
            )
            subprocess.run(["systemctl", "reload", "nftables"], check=True)
        except subprocess.CalledProcessError as exc:
            sys.stderr.write("ERROR: nftables reload failed:\n")
            sys.stderr.write(exc.stderr.decode("utf-8", errors="replace"))
            return 1

    sys.stdout.write(
        f"OK: allow_v4={len(set(allow_v4))} allow_v6={len(set(allow_v6))} "
        f"block_v4={len(set(block_v4))} block_v6={len(set(block_v6))}\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
