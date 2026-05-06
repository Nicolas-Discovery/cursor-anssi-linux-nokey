# cursor-anssi-linux-nokey

Ansible stack that hardens a Debian 13 (Trixie) host to the **ANSSI BP-028 v2.0
"élevé / critique"** profile, with **password + TOTP** authentication only
(no SSH key), **IPv4 + IPv6**, an **nftables firewall** with **GeoIP
continent / country / IP whitelist + blacklist** logic, **CrowdSec**
(with central-console enrolment, parser whitelist and a continent-aware
profile), and three optional add-on roles: **Docker** (CIS-hardened, IPv6
disabled), **Loki / Promtail** log shipping, and **Wazuh** agent enrolment.

> All tunables are in **one** file: `group_vars/all.yml`. Versions, toggles,
> hardening parameters, GeoIP policy, CrowdSec enrolment token reference,
> Docker daemon, Loki and Wazuh configuration - everything is there.

---

## 1. Layout

```
.
├── ansible.cfg                       # Disables key auth, forces password+TOTP
├── requirements.yml                  # Ansible collections (ansible.posix etc.)
├── inventory/
│   ├── hosts.yml.example
│   └── secrets.vault.yml.example
├── group_vars/
│   └── all.yml                       # SINGLE source of truth (every variable)
├── playbooks/
│   └── site.yml
└── roles/
    ├── anssi_base/                   # Mandatory ANSSI baseline
    ├── nftables/                     # Firewall + GeoIP refresh
    ├── crowdsec/                     # CrowdSec engine + bouncer + enrolment
    ├── docker/                       # Optional, hardened, IPv6 disabled
    ├── loki/                         # Optional Promtail -> Loki
    └── wazuh/                        # Optional Wazuh agent
```

## 2. Supported controller versions

| Component     | Version range                             | Notes |
| ------------- | ----------------------------------------- | ----- |
| `ansible-core`  | `>= 2.15, <= 2.18`                      | 2.14 also works but is EOL since Nov 2023; upgrade if possible. |
| `ansible.posix` | `>= 1.5.4, < 2.0.0` (pinned)            | 2.x requires `ansible-core >= 2.16`; 1.x is broader. |
| `community.general` | `>= 8.0.0, < 10.0.0` (pinned)       | 12.0.0 removed the `yaml` callback we used to depend on. |

The `ansible.cfg` shipped here uses `stdout_callback = ansible.builtin.default`
with `result_format = yaml` — the supported replacement for the removed
`community.general.yaml` callback (available in `ansible-core >= 2.13`).

## 3. Quick start

```bash
# 1. Install dependencies on the controller
ansible-galaxy collection install -r requirements.yml --force

# 2. Customise inventory
cp inventory/hosts.yml.example inventory/hosts.yml
$EDITOR inventory/hosts.yml

# 3. Encrypt secrets (vault)
cp inventory/secrets.vault.yml.example inventory/secrets.vault.yml
$EDITOR inventory/secrets.vault.yml
ansible-vault encrypt inventory/secrets.vault.yml

# 4. Review the single variable file
$EDITOR group_vars/all.yml

# 5. Run
ansible-playbook -i inventory/hosts.yml playbooks/site.yml \
  --ask-pass --ask-become-pass \
  -e @inventory/secrets.vault.yml --ask-vault-pass
```

> **Important — TOTP bootstrapping.**
> The 2FA module rejects logins without a configured secret (`nullok=false`).
> Run `google-authenticator -t -d -f -r 3 30 -W -e 5 -i ANSSI-CRITICAL` as
> the admin user **before** logging out from the first SSH session, or you
> will be locked out. The role prints a hint listing every user missing
> `~/.google_authenticator`.

## 4. The single variable file (`group_vars/all.yml`)

Every option of every role lives in this file, organised in eight sections:

| Section | Purpose |
| --- | --- |
| 0. Profile | ANSSI hardening profile + target distro pinning |
| 1. Role toggles | `role_*_enabled` flags for every role |
| 2. Versions | Pinned versions (CrowdSec, Docker, Promtail, Wazuh, ...) |
| 3. ANSSI base | Packages, sysctl (kernel/IPv4/IPv6), modules, mounts, PAM, SSH, 2FA, sudo, audit, AppArmor, GRUB, NTP, journald, banner |
| 4. nftables | Firewall policy + GeoIP allow/block continents / countries / whitelist / blacklist |
| 5. CrowdSec | Repo, collections, parsers, enrolment token reference, parser whitelist, GeoIP profile |
| 6. Docker | Daemon hardening, IPv6 disabled, log driver, userns-remap, etc. |
| 7. Loki | Promtail binary version + URL, basic auth, TLS, scrape jobs |
| 8. Wazuh | Manager address + port, enrolment via authd password, agent options |

## 5. GeoIP / firewall logic

Decision flow inside the `inet filter` table:

```
1. ct state established,related      -> ACCEPT
2. ip(6) saddr @ip_blacklist_*       -> DROP (highest priority, even over whitelist)
3. ip(6) saddr @ip_whitelist_*       -> ACCEPT (skip GeoIP)
4. ip(6) saddr @geoip_block_*        -> DROP    (e.g. ru, by — even though EU continent)
5. ip(6) saddr @geoip_allow_*        -> jump to services_v4 / services_v6
6. default                           -> DROP
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
| Loki | `role_loki_enabled: true` | Installs Promtail, ships journald + auth.log + audit.log over HTTPS basic auth + tenant ID. |
| Wazuh | `role_wazuh_enabled: true` | Adds upstream APT repo, installs the agent, registers with `agent-auth -P <password>` and groups. |

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

To enforce only one section (e.g. SSH):

```bash
ansible-playbook -i inventory/hosts.yml playbooks/site.yml -t ssh
```
