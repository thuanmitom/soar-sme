# Dashboard guide

Address: `http://127.0.0.1:8080` through the SSH tunnel, or `https://<server-ip>:8443` when HTTPS is enabled.

## Roles

| Can… | viewer | analyst | admin |
| --- | :---: | :---: | :---: |
| See cases, approvals, actions, incidents, hosts, knowledge, exceptions, settings | ✓ | ✓ | ✓ |
| Mark TP / FP, close and reopen cases, close incidents, renew knowledge | | ✓ | ✓ |
| Approve or reject **kills** (dashboard or Telegram) | | ✓ | ✓ |
| Send popup, Defender scan, evidence collection | | ✓ | ✓ |
| Pause / resume automatic actions | | ✓ | ✓ |
| Approve isolations; kill, suspend, resume, block / unblock IP, isolate / lift manually | | | ✓ |
| Exceptions, switch knowledge off or delete it, all settings, users, audit log | | | ✓ |

## Pages

- **Cases** — overview (open cases, approvals waiting, incidents, AI agreement), filters, case detail with the reasoning,
  threat intelligence, what was done and what was *not* done and why (paused, rate limit, exception, mode…), approvals,
  actions, manual actions, and the Wazuh search query. Banners show a pause, capacity problems and notification errors.
- **Approvals** — kills and isolations waiting for a decision, with their expiry. Expired requests stay listed with the
  note "Action expired: nothing was done".
- **Actions** — everything sent to endpoints (automatic, approved, manual), results, and *Lift isolation* / *Unblock*.
- **Incidents** — the same behaviour on several hosts in a short time; *Show cases* filters the case list.
- **Hosts & logs** — agents, groups, isolation state, events and drops per log source, and *Actions…* for manual actions.
- **Knowledge** — verdicts reused for later cases. AI verdicts expire after 30 days, analyst verdicts after 90 (settings);
  *Renew* the ones you trust. A case matching an analyst false positive is closed automatically.
- **Exceptions** — known-good behaviour: by rule, scope (all hosts, a group, a host), process path (exact, or ending with `\`
  or `*`), SHA-256 or command-line text; *Suppress* (no case kept open, no message) or *No action* (case kept, never acted on);
  optional expiry. Every match is counted.
- **Users** (admin) — create accounts (temporary password shown once), change roles, reset passwords and two-factor,
  link Telegram user ids, disable, delete; *Password reset requests* from the sign-in page appear here.
- **Audit** (admin) — sign-ins, setting changes, approvals (with dashboard / Telegram / system), manual actions, user changes.
- **Settings** — grouped: Response, Agent groups (mode, auto-kill, log profile per group, fallback), Detection, Data and AI,
  Knowledge, Retention, Notifications (channels, templates), Wazuh. Viewers and analysts see them read-only.
- **Account** — change your password, set up or remove two-factor sign-in (any TOTP app).

## Approvals

1. The policy proposes a kill (or an isolation for ransomware precursors when isolation is enabled).
2. The request appears on the dashboard and in Telegram with **Approve / Reject** buttons (only users whose Telegram id is
   linked to an analyst or admin account can use them; isolations need an admin). Teams, Slack and Discord get a link.
3. Approve: the action is sent (a Defender scan follows a kill); Reject: nothing is done (a suspended process is resumed).
4. No decision before the timeout (30 minutes by default): the request expires, nothing is done, it is recorded and announced.
Every decision is in the audit log, with the channel used.

## Manual actions

| Action | Role | What happens on the endpoint |
| --- | --- | --- |
| Warn the user | analyst | popup to the signed-in users (`notice_text`, in your language) |
| Defender scan | analyst | Microsoft Defender quick scan (skipped if Defender is passive) |
| Collect evidence | analyst | processes, connections, automatic services, non-Microsoft tasks, Run keys, recent downloads → JSON in `C:\ProgramData\SOAR-SME\evidence` (summary on the dashboard) |
| Kill | admin | stops the process and its children; core Windows, Defender, Sysmon, Wazuh and EDR processes are never stopped (path and signature checked) |
| Suspend / Resume | admin | pauses or resumes the process (needs PowerShell Full Language mode) |
| Block / Unblock IP | admin | Windows Firewall rules in and out, removed automatically after `blockip_hours` |
| Isolate / Lift | admin | only the Wazuh manager and DHCP stay reachable; previous firewall settings saved and restored; lifted automatically after `isolation_hours`; refused when Group Policy controls the firewall |
