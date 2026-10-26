# SOAR-SME setup guide

Version 1.0.0. This guide builds SOAR-SME step by step. Every server step can be done with one `setup.sh` command
(**Quick way**) or by hand (**Manual way**); do not mix both within one step. Each step ends with **Check** items and an
**If it fails** list. `bash setup.sh extract ./src` writes every embedded file to a folder for review or manual use.

| Step | Where | Command |
| --- | --- | --- |
| 1 Plan groups, response and data | On paper | — |
| 2 Prepare, configure, check | Server | `init`, `check` |
| 3 Wazuh 4.x | Server | `install-wazuh` |
| 4 Database, n8n, dashboard | Server | `stack` |
| 5 Wazuh API account | Server | `api` |
| 6 Rules, log collection, enrollment password, firewall | Server | `wazuh`, `test-rules` |
| 7 Retention | Server, dashboard | `retention` |
| 8 Windows endpoints | Endpoints, server | `windows-kit`, `Install-SoarEndpoint.ps1` |
| 9 Detection traps | Domain controller | manual |
| 10 Notification channels and services | Browser | manual |
| 11 n8n | Server | `n8n` |
| 12 Accounts and approvals | Dashboard | — |
| 13 Test | Server, endpoints | `test-notify`, `test-ar`, test plan |
| 14 Go live gradually | Dashboard | — |

`sudo bash setup.sh install` runs steps 2 to 8 (server side) in order and asks before installing Wazuh. Every command is
safe to run again.

## Step 1 — Plan groups, response and data

**Why:** SOAR-SME acts according to the Wazuh agent group of each machine. Deciding first avoids moving agents later.

1. Count your endpoints (`ENDPOINTS`): up to 25 is a test or small-office setup, 26–100 and 101–300 need bigger servers (see README), more
   than 300 is not supported on one server.
2. Give each kind of machine a group and a mode:

| Mode | High risk | Medium risk | Use for |
| --- | --- | --- | --- |
| `contain` | popup, evidence; kill **after approval**, or **automatically** if the group is in *auto-kill* and the signal is high-fidelity | popup | workstations |
| `notify` | popup, evidence; kill proposed for approval | popup | servers, domain controllers |
| `monitor` | nothing | nothing | sensitive or shared machines, pilot phase |

   *High-fidelity* means a rule that is conclusive by itself (LSASS access, Defender detection, ransomware precursors,
   decoy account, DCSync) or a hash flagged by threat intelligence, **and** a program running from a folder users can
   write to (Downloads, AppData, Temp, Public, ProgramData). A host in several groups gets the most restrictive mode;
   hosts in no group get the fallback mode (`notify` or `monitor`).
3. Choose a log profile per group: `standard`, or `lean` (PowerShell script blocks only when Windows flags them as
   suspicious, no Sysmon file-create events; less volume, but the Startup-folder rule and some PowerShell detections are lost).
4. Choose the data mode: **local** (default, nothing leaves the server) or **cloud** (masked case data to the AI and
   threat-intelligence services you configure).
5. Choose the notification channels (Telegram for approvals; Teams, Slack, Discord for notifications) and a realistic
   decoy account name (not `svc_sqlbackup`).

## Step 2 — Prepare the server, configure and check

**Where:** the server (Ubuntu Server 22.04 or 24.04, with the IP the endpoints will use).

```bash
git clone https://github.com/<owner>/soar-sme.git && cd soar-sme
sudo bash setup.sh init
sudo bash setup.sh check
```

`init` asks for: server IP, number of endpoints, groups and modes, fallback mode, liveness groups, time zone, decoy name,
forwarding level of built-in Wazuh alerts, dashboard address (127.0.0.1 = SSH tunnel only), **HTTPS on the LAN**
(yes/no and port), **enrollment password** (yes/no), indexer and dashboard URLs for a distributed Wazuh, retention days.
It writes `/opt/soar/soar.conf` (see [CONFIGURATION.md](CONFIGURATION.md)).

`check` prints `[OK]`, `[!!]` (read it) and `[X]` (fix it first): Ubuntu version, sizing for your number of endpoints
(CPU, RAM, disk), NTP, Wazuh version (4.9.1 or later), cluster role, rule ID conflicts (100110–100299), ports, UFW,
events already lost by Wazuh (`events_dropped`, `discarded_count`), Internet access.

**Check:** ☐ `soar.conf` exists ☐ `check` ends with "No blocking problem found" (or only "Wazuh is not installed").

**If it fails:** wrong IP → `init` again · port in use → change `N8N_PORT` / `DASHBOARD_PORT` / `HTTPS_PORT` ·
Wazuh older than 4.9.1 → upgrade it (CVE-2025-24016); for an isolated lab only, add `--force`.

## Step 3 — Install Wazuh 4.x

**Quick way:** `sudo bash setup.sh install-wazuh` (series from `WAZUH_SERIES`, default 4.14) or
`sudo bash setup.sh install-wazuh --series 4.12`. Series older than 4.9 are refused. The official installation assistant
installs manager, indexer and dashboard (10–20 minutes); the packages are then put on hold so `apt upgrade` cannot jump to Wazuh 5.

**Manual way:**

```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
sudo apt-mark hold wazuh-manager wazuh-indexer wazuh-dashboard filebeat
```

Passwords: `sudo tar -O -xf /root/wazuh-install/wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt`.

**Check:** ☐ `https://<server-ip>` opens the Wazuh dashboard ☐ `apt-mark showhold` lists the Wazuh packages.

## Step 4 — Database, n8n and dashboard (Docker)

**Quick way:** `sudo bash setup.sh stack` installs Docker if needed, copies the stack to `/opt/soar`, creates
`/opt/soar/.env` with random secrets, starts PostgreSQL, n8n 2.43.7 and the dashboard (plus the nginx HTTPS proxy when
`DASHBOARD_HTTPS="yes"`), applies the database schema and copies your groups and Wazuh settings into the dashboard.
It prints the first admin password (`DASHBOARD_PASSWORD` in `.env`).

**After:**
- Open an SSH tunnel from your PC: `ssh -L 5678:127.0.0.1:5678 -L 8080:127.0.0.1:8080 <user>@<server-ip>`.
- `http://127.0.0.1:5678`: create the n8n owner account.
- `http://127.0.0.1:8080` (or `https://<server-ip>:8443` with HTTPS): sign in as `admin`, then **Account**: change the
  password and set up two-factor sign-in.
- Back up `/opt/soar/.env` (`sudo bash setup.sh backup`): it holds the n8n encryption key.

**Check:** ☐ `curl -s http://127.0.0.1:8080/api/health` returns `{"status":"ok"}` ☐ you can sign in.

**If it fails:** `sudo docker compose -f /opt/soar/docker-compose.yml logs dashboard` (or `n8n`, `postgres`).

## Step 5 — Wazuh API account

**Quick way:** `sudo bash setup.sh api` creates the user `soar` with only `agent:read` and `active-response:command`.

**Manual way:** authenticate as `wazuh`, then create policy `soar_policy` (actions `agent:read`, `active-response:command`,
resource `agent:id:*`), role `soar_role`, user `soar` with `WAZUH_API_PASSWORD` from `.env`, and link them
(`/security/policies`, `/security/roles`, `/security/users` of the Wazuh API).

## Step 6 — Rules, log collection, enrollment password, firewall

**Quick way:** `sudo bash setup.sh wazuh`. It backs up the Wazuh files, then installs:
- the rules (`/var/ossec/etc/rules/soar_rules.xml`, IDs 100110–100299, your decoy name filled in);
- for every SOAR group and `default`: Windows log collection (standard or lean profile) and the response scripts;
- the n8n integration (SOAR rules from level 7, built-in alerts from level 12 by default) and the liveness check;
- the **enrollment password** (`/var/ossec/etc/authd.pass`, `<use_password>yes` in `ossec.conf`) when `ENROLL_PASSWORD="yes"`;
- **UFW rules** when UFW is active: 1514–1515/tcp allowed, the Wazuh API (55000) and the indexer (9200) closed to the LAN;
- the `soar-sync` timer, which applies dashboard changes (groups, Wazuh settings, retention) every minute.
Wazuh validates the result; if it refuses it, every file is restored and the manager is not restarted.

Then check every rule with the real engine:

```bash
sudo bash setup.sh test-rules      # uses the 'wazuh' API password from wazuh-install-files.tar (or WAZUH_ADMIN_PASSWORD)
```

**Check:** ☐ `wazuh` ends with the group table ☐ `test-rules` reports all rule self-tests passed ☐ `systemctl status soar-sync.timer` is active.

**If it fails:** "rejected the configuration" → read the printed error (often a rule ID clash in `local_rules.xml`) ·
"cluster worker" → run on the master · `test-rules` says the samples were not decoded as Windows events → the self-test
cannot judge this Wazuh version: verify the rules with real events (step 13) · UFW inactive → apply the equivalent rules
in your firewall.

## Step 7 — Retention

**Quick way:** `sudo bash setup.sh retention 60` once (it stores the indexer password for the timer). Afterwards change
all lifetimes on the dashboard (**Settings > Retention**): alert indices, closed false-positive / low-risk cases (30 days
by default), other closed cases, actions and approvals, audit log (60 days by default), or switch retention off.
The server applies the index change within a minute (ISM policy `soar-retention`); the database is cleaned every hour.
Keep data longer by archiving it elsewhere (backups, index snapshots).

## Step 8 — Windows endpoints

**8.1 Audit policy.** Domain: two GPOs on a domain controller.

| GPO | Setting | Value |
| --- | --- | --- |
| SOAR-Audit-Baseline (all computers) | Advanced audit: Process Creation, Logon, Special Logon, Account Lockout, Security Group Management, User Account Management, Audit Policy Change, Security System Extension, Other Object Access Events (scheduled tasks) | Success (Logon, Account Lockout: Success and Failure) |
| | Include command line in process creation events | Enabled |
| | Turn on PowerShell Script Block Logging | Enabled |
| | Security event log maximum size | 512 MB |
| SOAR-Audit-DC (domain controllers) | Kerberos Service Ticket Operations, Kerberos Authentication Service, Directory Service Access | Success and Failure |

Intune-only devices: the same settings with a Settings Catalog profile (Auditing, Windows PowerShell, Event Log Service).
Workgroup machines: run the kit with `-ConfigureAudit`.

**8.2 Build the kit:** `sudo bash setup.sh windows-kit` → `/opt/soar/soar-windows-kit.zip` (server IP, groups, Wazuh
version and the enrollment password filled in — **keep the zip private**).

**8.3 Check one endpoint first** (changes nothing):

```powershell
powershell.exe -ExecutionPolicy Bypass -File Install-SoarEndpoint.ps1 -Check
```

It reports: Windows and PowerShell versions, Constrained Language Mode, AppLocker / WDAC, the agent (and whether it is
newer than the manager — not supported), connectivity to 1514/1515, Sysmon, Defender mode, other antivirus / EDR,
whether Group Policy controls the firewall (isolation would be refused), whether process-creation events are logged,
the Security log size. Exit code 0 = ready, 2 = warnings, 1 = blocking problem; report in `C:\ProgramData\SOAR-SME\precheck.json`.

**8.4 Deploy** (Administrator or SYSTEM: GPO startup script, Intune Win32 app or script, RMM):

```powershell
powershell.exe -ExecutionPolicy Bypass -File Install-SoarEndpoint.ps1 -Group client -InstallAgent
```

It installs and enrolls the agent (signature checked), Sysmon with the sysmon-modular configuration (Windows 10 / Server
2016 and later; skipped on older Windows), the response scripts and a ping rule for the server. Offline: put the agent
MSI, `Sysmon.zip` and `sysmonconfig.xml` next to the script. Log: `C:\ProgramData\SOAR-SME\install.log`.
Existing agents: `sudo bash setup.sh assign <group> <agent>...`.

**Other EDR or antivirus:** SOAR-SME runs alongside it. Add an exclusion for
`C:\Program Files (x86)\ossec-agent\active-response\bin\soar-action.*` and `...\ossec-agent\shared\soar-action.ps1`
if it blocks them. When Defender is passive (another antivirus is primary), the scan action is skipped.

**Check:** ☐ `-Check` returns 0 or only expected warnings ☐ the host appears in **Hosts & logs** with events per source.

## Step 9 — Detection traps (Active Directory)

Decoy account for rule 100110 (choose your own name, the same as `HONEYTOKEN_USER`):

```powershell
New-ADUser -Name "svc_yourname" -SamAccountName "svc_yourname" -AccountPassword (Read-Host -AsSecureString) -Enabled $true
Set-ADUser "svc_yourname" -ServicePrincipalNames @{Add="MSSQLSvc/sql-legacy.corp.local:1433"}
```

DCSync audit for rule 100130: on the domain root, auditing entry for *Everyone*, *Success*, *This object only*,
"Replicating Directory Changes" and "Replicating Directory Changes All".

## Step 10 — Notification channels and services

| Service | Needed for | How |
| --- | --- | --- |
| Telegram bot | messages, **Approve / Reject buttons** | @BotFather → token; add the bot to your group; chat id from `getUpdates` |
| Microsoft Teams | messages (no approval) | Teams > channel > Workflows > "Post to a channel when a webhook request is received" → URL |
| Slack / Discord | messages (no approval) | incoming webhook URL |
| Gemini / Claude / OpenAI-compatible | AI verdicts, cloud mode only | API key; a local model (Ollama, vLLM) needs only its base URL |
| VirusTotal / AbuseIPDB | threat intelligence, cloud mode only | API keys (free tiers: personal / non-business use terms) |

The Telegram bot is polled from the server (outbound only): no port is opened. Teams, Slack and Discord messages carry a
link to the dashboard; approvals happen there.

## Step 11 — n8n

```bash
sudo bash setup.sh n8n
```

It asks for each key or webhook (Enter = skip, `-` = turn off), stores them in `/opt/soar/keys.env` (root only),
creates 9 n8n credentials, imports and publishes the workflow (changes made in the n8n editor are replaced), sets the
channels and AI provider in the dashboard, and **asks before switching to cloud mode** (default: stay local).

**Check:** ☐ "Webhook /webhook/wazuh-alert is live" ☐ `sudo bash setup.sh test-notify` reports each channel as sent.

## Step 12 — Accounts and approvals

On the dashboard (**Users**, admins only): create one account per person with the least role needed — *viewer* (read),
*analyst* (verdicts, approvals of kills, popups / scans / evidence), *admin* (everything). New users get a temporary
password and must change it. To approve from Telegram, set each approver's **Telegram user id**. Ask approvers to turn on
two-factor sign-in (**Account**) and Telegram's own two-step verification. Forgotten passwords: the user asks from the
sign-in page, an admin resets it; if the last admin is locked out: `sudo bash setup.sh user reset <name>`.

## Step 13 — Test

Self-tests first: `setup.sh test-rules`, `setup.sh test-notify`, then on a pilot endpoint:
`setup.sh test-ar notice <agent>`, `scan <agent>`, `evidence <agent>`, `isolate-check <agent>`
(`blockip <agent> <ip>` then `unblockip`). Then the scenarios below on a pilot workstation of a `contain` group:

| Test | How (pilot machine) | Expected |
| --- | --- | --- |
| LSASS access | `procdump64.exe -ma lsass.exe` from Downloads | case TP high; kill waits for approval (or automatic in an auto-kill group); evidence collected; Telegram buttons |
| Approval | Approve in Telegram or on the dashboard | kill + Defender scan sent, result reported, message updated |
| Expiry | Do nothing for 30 minutes | request "expired", nothing done (process resumed if it was suspended) |
| Ransomware precursor | `vssadmin delete shadows /for=Z: /quiet` on a test VM | rule 100200, parent program targeted, isolation proposed if enabled |
| Malicious document | Word macro that starts `powershell.exe` | rule 100220 |
| Brute force | 11 wrong RDP passwords from one IP, then the right one | rules 100231 then 100232 |
| Outbreak | same test on 5 machines within 30 minutes | one incident, one urgent message |
| Storm | 30+ alerts in 5 minutes | one digest message, AI/TI paused |
| Exception | add a *suppress* exception for the test program path | next case closed silently |
| Pause | Settings > Pause 30 minutes, repeat a test | no automatic action, kill waits for approval |
| Isolation (test VM only) | enable isolation, approve it | only the manager reachable; lifted after 4 h or by *Lift isolation* |

## Step 14 — Go live gradually

1. **Monitor** (2–4 weeks): all groups `monitor`, local-only mode. Tune noise with exceptions and analyst verdicts.
   Move on when every endpoint reports, no events are lost and false positives are stable.
2. **Notify**: popups and messages, kills proposed for approval.
3. **Contain with approval** on a pilot group of workstations.
4. **Automatic kill** only for selected workstation groups, after the pilot shows no false kill; keep the rate limits.
5. **Isolation**: enable it only after testing on one machine per Windows build you use.
