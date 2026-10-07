# cursor-anssi-linux-nokey

Ansible stack that hardens a Debian 13 (Trixie) host to the **ANSSI BP-028 v2.0
"élevé / critique"** profile, with **password-only** authentication
(**no SSH key, no MFA/TOTP**), **IPv4 + IPv6**, an **nftables firewall** with
**GeoIP continent / country / IP whitelist + blacklist** logic **plus a
dedicated SSH IP allowlist refreshed from an Azure Blob Storage bucket**,
**CrowdSec** (with central-console enrolment, parser whitelist and a
continent-aware profile), and three optional add-on roles: **Docker**
(CIS-hardened, IPv6 disabled), **Grafana Alloy** log shipping to Loki, and
**Wazuh** agent enrolment.

> **Access model.** There is no SSH key and no second factor. The only secret
> is the account password. Because password-only auth is weak on its own, SSH
> is locked down **at the firewall**: the SSH port only accepts connections
> from an IP allowlist that is pulled from an **Azure Blob Storage bucket**
> (authenticated with the storage **account key**) and merged with a static
> break-glass list. Keep your bastion/admin CIDRs in `static_allow_*` so a
> bucket outage can never lock you out.

> All tunables are in **one** file: `inventory/group_vars/all.yml`. Versions, toggles,
> hardening parameters, GeoIP policy, the SSH allowlist / Azure bucket settings,
> CrowdSec enrolment token reference, Docker daemon, Loki and Wazuh
> configuration - everything is there.

---

## 1. Layout

```
.
├── ansible.cfg                       # Disables key auth, password-only (no MFA)
├── controller-requirements.txt       # Python deps for the controller (ansible-core, lint)
├── requirements.yml                  # Ansible Galaxy collection (ansible.posix)
├── inventory/
│   ├── hosts.yml.example
│   ├── secrets.vault.yml.example
│   └── group_vars/
│       └── all.yml                   # SINGLE source of truth (every variable)
├── playbooks/
│   └── site.yml
└── roles/
    ├── anssi_base/                   # Mandatory ANSSI baseline
    ├── nftables/                     # Firewall + GeoIP refresh
    ├── crowdsec/                     # CrowdSec engine + bouncer + enrolment
    ├── docker/                       # Optional, hardened, IPv6 disabled
    ├── loki/                         # Optional Grafana Alloy -> Loki
    └── wazuh/                        # Optional Wazuh agent
```

## 2. Supported controller versions

| Component       | Version range                          | Notes |
| --------------- | -------------------------------------- | ----- |
| Python          | `>= 3.10`                              | Required by `ansible-core` 2.16+. |
| `ansible-core`  | `>= 2.16, < 2.21` (pinned via pip)     | 2.16/2.17/2.18/2.19/2.20 LTS line. 2.14 / 2.15 are EOL and no longer tested. |
| `ansible.posix` | `>= 2.0.0, < 3.0.0` (pinned in `requirements.yml`) | Provides `ansible.posix.mount` plus the `profile_tasks` / `timer` callbacks. |

The stack does **not** depend on `community.general`. The previous
`community.general.yaml` callback has been replaced by the built-in
`ansible.builtin.default` callback with `callback_result_format = yaml`
(available since `ansible-core` 2.13).

## 3. Quick start

```bash
# 1. Create a dedicated controller virtualenv and install ansible-core + lint
python3 -m venv .venv
. .venv/bin/activate
pip install -U pip
pip install -r controller-requirements.txt

# 2. Install the pinned collection
ansible-galaxy collection install -r requirements.yml --force

# 3. Customise inventory
cp inventory/hosts.yml.example inventory/hosts.yml
$EDITOR inventory/hosts.yml

# 4. Encrypt secrets (vault)
cp inventory/secrets.vault.yml.example inventory/secrets.vault.yml
$EDITOR inventory/secrets.vault.yml
ansible-vault encrypt inventory/secrets.vault.yml

# 5. Review the single variable file
$EDITOR inventory/group_vars/all.yml

# 6. Run
ansible-playbook -i inventory/hosts.yml playbooks/site.yml \
  --ask-pass --ask-become-pass \
  -e @inventory/secrets.vault.yml --ask-vault-pass
```

> **Important — do not lock yourself out.**
> SSH is only reachable from the firewall allowlist. Before running the
> playbook, make sure the IP you connect from is covered by one of:
> `nftables.ip_whitelist_v4/v6`, `nftables.ssh_restriction.static_allow_v4/v6`,
> or the Azure bucket contents. The `static_allow_*` lists are the safe
> break-glass path and should always contain your bastion/admin CIDRs.

## 4. The single variable file (`inventory/group_vars/all.yml`)

It lives next to the inventory so that Ansible auto-loads it for every
host targeted via `-i inventory/hosts.yml` or `-i inventory/`. No
`vars_files` directive is needed.

Every option of every role lives in this file, organised in eight sections:

| Section | Purpose |
| --- | --- |
| 0. Profile | ANSSI hardening profile + target distro pinning |
| 1. Role toggles | `role_*_enabled` flags for every role |
| 2. Versions | Pinned versions (CrowdSec, Docker, Alloy, Wazuh, ...) |
| 3. ANSSI base | Packages, sysctl (kernel/IPv4/IPv6), modules, mounts, PAM, SSH (password-only), sudo, audit, AppArmor, GRUB, NTP, journald, banner |
| 4. nftables | Firewall policy, SSH IP allowlist (Azure bucket + static), GeoIP allow/block continents / countries / whitelist / blacklist |
| 5. CrowdSec | Repo, collections, parsers, enrolment token reference, parser whitelist, GeoIP profile |
| 6. Docker | Daemon hardening, IPv6 disabled, log driver, userns-remap, etc. |
| 7. Loki | Grafana Alloy repo, Loki push URL, basic auth, TLS, journald + file sources |
| 8. Wazuh | Manager address + port, enrolment via authd password, agent options |

**Authentication is password-only.** There is no SSH key and no TOTP: the
`anssi_base.twofa` block is disabled (`enabled: false`) and
`anssi_base.ssh.authentication_methods` is `password`. `/etc/pam.d/sshd` is
rendered as a password-only PAM chain (reusing `common-auth` with faillock).

**Additional SSH-related keys** (under `anssi_base.ssh` unless noted):

| Key | Purpose |
| --- | --- |
| `ssh.allow_from_any_address` | Users allowed as `user@*` in `AllowUsers` (application-layer source filter, in addition to the firewall). |
| `ssh.user_allow_from_addresses` | Map `username → [ CIDR, … ]` → `AllowUsers user@CIDR`. IPv6: use `[addr]/len`. |
| `existing_users_add_to_ssh_group` | Existing POSIX accounts appended to `ssh-users` via `usermod -aG` (user must already exist). |

> `ssh.user_allow_from_addresses` / `ssh.allow_from_any_address` are a
> *second*, application-layer source restriction (OpenSSH `AllowUsers`). They
> are complementary to the nftables SSH allowlist described in §5 — the
> firewall is the primary control.

## 5. Firewall logic (SSH allowlist + GeoIP)

Decision flow inside the `inet filter` input chain:

```
1. ct state established,related      -> ACCEPT
2. ip(6) saddr @ip_blacklist_*       -> DROP (highest priority, even over whitelist)
3. ip(6) saddr @ip_whitelist_*       -> ACCEPT (skip SSH restriction + GeoIP)
4. tcp dport 22, saddr @ssh_allow_*  -> ACCEPT   (the SSH IP allowlist)
   tcp dport 22, anything else       -> DROP + log [nft-ssh-denied]
5. ip(6) saddr @geoip_block_*        -> DROP    (e.g. ru, by — even though EU continent)
6. ip(6) saddr @geoip_allow_*        -> jump to services_v4 / services_v6 (NON-SSH services)
7. default                           -> DROP
```

SSH is handled **before** the generic GeoIP/service logic and is *not* listed
in `nftables.allowed_services`, so it is never opened continent-wide. The
`ssh_allow_v4` / `ssh_allow_v6` sets are the union of
`nftables.ssh_restriction.static_allow_*` and the IPs pulled from the Azure
bucket (see §5.1).

### 5.1 SSH allowlist from an Azure Blob Storage bucket

`nftables.ssh_restriction.azure` configures a helper,
`/usr/local/sbin/anssi-ssh-allowlist-update`, that:

1. Downloads a plain-text IP/CIDR list (one entry per line, `#` comments
   allowed) from `https://<account>.blob.<endpoint_suffix>/<container>/<blob>`.
2. Authenticates with the storage **account key** (Azure *Shared Key*,
   HMAC-SHA256 — implemented with the Python standard library, no Azure SDK
   required). A **SAS token** or anonymous access are also supported.
3. Validates every entry, splits IPv4/IPv6, merges with `static_allow_*`, and
   regenerates `/etc/nftables.d/15-ssh-allow.conf` (the `ssh_allow_*` sets).
4. With `--apply`, revalidates (`nft -c`) and reloads nftables.

The account key is supplied via Ansible Vault as **`azure_ssh_allowlist_key`**
and written to `nftables.ssh_restriction.azure.key_file` (mode `0600`). A
systemd timer (`anssi-ssh-allowlist-update.timer`) refreshes the allowlist on
`refresh_interval` (default daily). The last successfully fetched list is
cached at `/var/lib/anssi-nftables/ssh-allowlist.cache`; if Azure is
unreachable the cached list (and always `static_allow_*`) is reused, so a
bucket/network outage can never empty the allowlist.

Blob format example:

```
# ssh allowlist - one address or CIDR per line
203.0.113.10/32        # bastion
198.51.100.0/24        # office range
2001:db8:42::/48       # office v6
```

The allowed set is computed as
`union(allowed_continents) ∪ allowed_countries  −  blocked_countries`,
so by default with `allowed_continents=[EU]`, `allowed_countries=[gb]`,
`blocked_countries=[ru, by]` you get every European country plus the UK,
minus Russia and Belarus.

The Python helper `/usr/local/sbin/anssi-geoip-update` downloads
[ipdeny.com](https://www.ipdeny.com) zone files (IPv4 + IPv6) every day
through a hardened systemd timer, regenerates the include files in
`/etc/nftables.d/` and reloads the ruleset.

## 6. CrowdSec

* Engine + nftables bouncer (IPv4 **and** IPv6) installed from the upstream
  packagecloud repository.
* `crowdsec.collections` and `crowdsec.parsers` are looped through
  `cscli`. The `crowdsecurity/geoip-enrich` parser is mandatory because the
  GeoIP profile relies on it.
* **Console enrolment** is driven by `crowdsec.enroll_token` (the
  *registration variable*), which itself is sourced from the Vault variable
  `crowdsec_enroll_token`. Tags and host name are set automatically.
* A **parser whitelist** lives at
  `/etc/crowdsec/parsers/s02-enrich/anssi-whitelists.yaml` and exposes
  `crowdsec.whitelist.{ips,cidrs,expression}`.
* The **GeoIP profile** mirrors the firewall policy at the application
  layer: any source whose country is in `blocked_countries` (or whose
  continent is not in `allowed_continents`) is banned for
  `crowdsec.geoip_decision_duration`.

## 7. Optional roles

| Role | Enable with | Notes |
| --- | --- | --- |
| Docker | `role_docker_enabled: true` | IPv6 disabled in `daemon.json`, ICC off, userns-remap, no-new-privileges, custom seccomp, json-file logging, live-restore. |
| Loki | `role_loki_enabled: true` | Installs Grafana Alloy from the official Grafana APT repo, ships journald + auth.log + audit.log to Loki over HTTPS basic auth + tenant ID. |
| Wazuh | `role_wazuh_enabled: true` | Adds the upstream Wazuh 5.x APT repo, installs the agent, registers with `agent-auth -P <password>` and groups. |

## 8. Compliance summary (selected ANSSI BP-028 controls)

| Control | Implementation |
| --- | --- |
| R1, R3 | `required_packages` / `forbidden_packages` |
| R5, R8 | `unattended-upgrades` + GRUB `lockdown=confidentiality` |
| R6, R7 | `/etc/modprobe.d/anssi-blacklist.conf` |
| R12 | `grub_password_pbkdf2` superuser entry |
| R26 | Root password locked, `PermitRootLogin no` |
| R28-R32 | Mount options enforced via `ansible.posix.mount` |
| R31, R68-R70 | `pwquality.conf`, `faillock.conf`, `common-password` |
| R55-R63 | `sshd_config` template (no DSA/ECDSA, modern KEX/ciphers/MACs) |
| R59 | `sudoers` defaults: `use_pty`, log I/O, requiretty |
| R72 | `auditd` config + ANSSI rule set (immutable, `-e 2`) |
| R34, R36 | AppArmor enforced, `kernel.yama.ptrace_scope = 2` |
| R20 | Chrony with French NTP pool by default |
| R37-R47 | sysctl drop-in `90-anssi.conf` (kernel + IPv4 + IPv6 hardening) |

## 9. Re-running

The stack is idempotent. To refresh GeoIP sets only:

```bash
sudo /usr/local/sbin/anssi-geoip-update --apply
```

To refresh the SSH allowlist from the Azure bucket only:

```bash
sudo /usr/local/sbin/anssi-ssh-allowlist-update --apply
# or inspect the merged result without reloading:
sudo /usr/local/sbin/anssi-ssh-allowlist-update && cat /etc/nftables.d/15-ssh-allow.conf
```

To enforce only one section (e.g. SSH):

```bash
ansible-playbook -i inventory/hosts.yml playbooks/site.yml -t ssh
```

## 10. Troubleshooting SSH (`kex_exchange_identification` / connection reset)

If Ansible prints:

```text
kex_exchange_identification: read: Connection reset by peer
Connection reset by <host> port 22
```

typical causes are:

1. **One new SSH connection per task (most common here)** — A playbook run with
   SSH multiplexing disabled forces **every** task to open a new TCP connection
   and run KEX + password auth. Long runs can hit **`MaxStartups`** on `sshd`
   (extra connections get RST during KEX) or trigger **fail2ban / CrowdSec**.
   The shipped `ansible.cfg` uses **`ControlMaster=auto`** + **`ControlPersist=4h`**
   and **`control_path_dir`** so you authenticate once and reuse the master socket
   for the whole run. Ensure `~/.ansible/cp` on the controller is writable.

2. **Firewall / SSH allowlist** — After the nftables role, SSH is only open to
   sources in **`ssh_allow_*`** (the Azure bucket + `ssh_restriction.static_allow_*`)
   plus **`nftables.ip_whitelist_*`**. Run Ansible from an allowed IP, or add it to
   `static_allow_*` / the bucket, before enabling the restriction.

3. **Transients** — `retries = 5` and `timeout = 60` under `[ssh_connection]` cover
   brief network glitches.

**Server-side** defaults in `inventory/group_vars/all.yml` now include a higher
**`anssi_base.ssh.max_startups`** and **`max_sessions: 10`** for heavy Ansible
runs; adjust under `anssi_base.ssh` if you need stricter values after onboarding.
