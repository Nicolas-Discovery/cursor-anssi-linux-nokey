#!/usr/bin/env python3
"""anssi-ssh-allowlist-update - refresh the nftables SSH allowlist from Azure.

Reads /etc/anssi-ssh-allowlist.yaml, downloads a plain-text IP/CIDR list from
an Azure Blob Storage bucket (container + blob) and regenerates the nftables
include file that defines the `ssh_allow_v4` / `ssh_allow_v6` sets used by the
master ruleset to gate the SSH port.

The effective allowlist is:

    static_allow_v4/v6   (from the config, always applied)
        UNION
    the IPs/CIDRs fetched from the Azure blob

Authentication (in order of precedence):
    1. Shared Key  - the storage ACCOUNT KEY read from `key_file` (mode 0600).
                     The request is signed with HMAC-SHA256 (no SDK required).
    2. SAS token   - appended to the blob URL when `sas_token` is set.
    3. Anonymous   - public container, no credentials.

Resilience: the last successfully fetched blob is cached on disk. If Azure is
unreachable, the cached list is reused so a bucket/network outage can never
empty the allowlist and lock operators out. If there is no cache either, only
the static_allow_* entries are emitted.

With --apply the script validates and reloads nftables after writing the file.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import ipaddress
import os
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from email.utils import formatdate
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.stderr.write("python3-yaml is required\n")
    sys.exit(2)

# Azure Storage REST API version used for Shared Key signing.
X_MS_VERSION = "2021-08-06"


def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def read_account_key(key_file: str) -> str | None:
    try:
        key = Path(key_file).read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return key or None


def build_shared_key_headers(account: str, account_key: str,
                             container: str, blob: str) -> dict[str, str]:
    """Return the headers (incl. Authorization) for a Shared Key GET request."""
    x_ms_date = formatdate(timeval=None, usegmt=True)  # RFC 1123, GMT
    canonical_headers = f"x-ms-date:{x_ms_date}\nx-ms-version:{X_MS_VERSION}\n"
    canonical_resource = f"/{account}/{container}/{blob}"
    string_to_sign = "\n".join([
        "GET",   # HTTP verb
        "",      # Content-Encoding
        "",      # Content-Language
        "",      # Content-Length (empty for GET)
        "",      # Content-MD5
        "",      # Content-Type
        "",      # Date (x-ms-date is used instead)
        "",      # If-Modified-Since
        "",      # If-Match
        "",      # If-None-Match
        "",      # If-Unmodified-Since
        "",      # Range
        canonical_headers + canonical_resource,
    ])
    key_bytes = base64.b64decode(account_key)
    signature = base64.b64encode(
        hmac.new(key_bytes, string_to_sign.encode("utf-8"),
                 hashlib.sha256).digest()
    ).decode("utf-8")
    return {
        "x-ms-date": x_ms_date,
        "x-ms-version": X_MS_VERSION,
        "Authorization": f"SharedKey {account}:{signature}",
    }


def fetch_blob(cfg: dict) -> bytes:
    """Download the blob body from Azure. Raises RuntimeError on failure."""
    account = cfg["account_name"]
    container = cfg["container"]
    blob = cfg["blob"]
    suffix = cfg.get("endpoint_suffix") or "core.windows.net"
    timeout = int(cfg.get("timeout") or 30)

    url = f"https://{account}.blob.{suffix}/{container}/{blob}"
    headers = {"User-Agent": "anssi-ssh-allowlist-update/1.0"}

    sas = (cfg.get("sas_token") or "").strip().lstrip("?")
    account_key = read_account_key(cfg.get("key_file", "")) if cfg.get("key_file") else None

    if account_key:
        headers.update(build_shared_key_headers(account, account_key, container, blob))
    elif sas:
        url = f"{url}?{sas}"
    # else: anonymous / public container

    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            return resp.read()
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
        raise RuntimeError(f"Azure blob fetch failed: {exc}") from exc


def parse_ip_list(data: str) -> tuple[list[str], list[str]]:
    """Parse a text IP/CIDR list into (v4, v6) lists, ignoring invalid lines."""
    v4: list[str] = []
    v6: list[str] = []
    for raw in data.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # Allow trailing inline comments: "1.2.3.4/32  # office"
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        try:
            net = ipaddress.ip_network(line, strict=False)
        except ValueError:
            sys.stderr.write(f"WARN: ignoring invalid entry: {line!r}\n")
            continue
        (v4 if net.version == 4 else v6).append(str(net))
    return v4, v6


def write_allowlist(path: str, set_v4: str, set_v6: str,
                    v4: list[str], v6: list[str]) -> None:
    """Atomically (re)write the nftables include file with both sets."""
    def render_set(name: str, family_attr: str, cidrs: list[str]) -> str:
        out = [
            f"set {name} {{",
            f"    type {family_attr};",
            "    flags interval;",
            "    auto-merge;",
        ]
        if cidrs:
            out.append("    elements = {")
            out.append(",\n".join("        " + c for c in sorted(set(cidrs))))
            out.append("    }")
        out.append("}")
        return "\n".join(out)

    body = (
        "# Auto-generated by anssi-ssh-allowlist-update - DO NOT EDIT BY HAND.\n"
        f"# ssh_allow_v4 members: {len(set(v4))} / ssh_allow_v6 members: {len(set(v6))}\n\n"
        + render_set(set_v4, "ipv4_addr", v4)
        + "\n\n"
        + render_set(set_v6, "ipv6_addr", v6)
        + "\n"
    )

    directory = os.path.dirname(path)
    tmpfd, tmppath = tempfile.mkstemp(prefix="anssi-ssh-allow-", dir=directory)
    try:
        with os.fdopen(tmpfd, "w", encoding="utf-8") as fh:
            fh.write(body)
        os.chmod(tmppath, 0o640)
        os.replace(tmppath, path)
    except BaseException:
        try:
            os.unlink(tmppath)
        except OSError:
            pass
        raise


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Refresh the nftables SSH allowlist from an Azure bucket.")
    parser.add_argument("--config", default="/etc/anssi-ssh-allowlist.yaml")
    parser.add_argument("--apply", action="store_true",
                        help="reload nftables after update")
    args = parser.parse_args()

    cfg = load_config(args.config)

    static_v4 = list(cfg.get("static_allow_v4") or [])
    static_v6 = list(cfg.get("static_allow_v6") or [])
    cache_file = cfg.get("cache_file") or "/var/lib/anssi-nftables/ssh-allowlist.cache"
    output = cfg["output"]
    set_v4 = cfg.get("set_v4") or "ssh_allow_v4"
    set_v6 = cfg.get("set_v6") or "ssh_allow_v6"

    bucket_v4: list[str] = []
    bucket_v6: list[str] = []

    if cfg.get("azure_enabled", True):
        try:
            data = fetch_blob(cfg).decode("utf-8", errors="replace")
            bucket_v4, bucket_v6 = parse_ip_list(data)
            # Persist the last known-good list for offline fallback.
            try:
                Path(cache_file).parent.mkdir(parents=True, exist_ok=True)
                Path(cache_file).write_text(data, encoding="utf-8")
            except OSError as exc:
                sys.stderr.write(f"WARN: could not write cache {cache_file}: {exc}\n")
        except RuntimeError as exc:
            sys.stderr.write(f"WARN: {exc}\n")
            # Fall back to the last successfully fetched list, if any.
            try:
                cached = Path(cache_file).read_text(encoding="utf-8")
                bucket_v4, bucket_v6 = parse_ip_list(cached)
                sys.stderr.write("WARN: using cached Azure allowlist (offline fallback)\n")
            except OSError:
                sys.stderr.write("WARN: no cache available; static_allow_* only\n")

    # Effective allowlist = static UNION bucket.
    all_v4 = sorted(set(static_v4) | set(bucket_v4))
    all_v6 = sorted(set(static_v6) | set(bucket_v6))

    write_allowlist(output, set_v4, set_v6, all_v4, all_v6)

    if args.apply:
        try:
            subprocess.run(["nft", "-c", "-f", "/etc/nftables.conf"],
                           check=True, capture_output=True)
            subprocess.run(["systemctl", "reload", "nftables"], check=True)
        except subprocess.CalledProcessError as exc:
            sys.stderr.write("ERROR: nftables reload failed:\n")
            if exc.stderr:
                sys.stderr.write(exc.stderr.decode("utf-8", errors="replace"))
            return 1

    sys.stdout.write(
        f"OK: ssh_allow_v4={len(all_v4)} (static={len(set(static_v4))}, "
        f"bucket={len(set(bucket_v4))}) ssh_allow_v6={len(all_v6)} "
        f"(static={len(set(static_v6))}, bucket={len(set(bucket_v6))})\n"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
