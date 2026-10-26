# Operations

## Daily

- `sudo bash setup.sh status` — Wazuh services, containers, key settings, approvals waiting, open incidents, capacity
  (agents, disk, days left, lost events), group table, sync timer, last SOAR alerts, delivery errors, liveness, disk.
- The dashboard banner shows a pause, capacity warnings and notification errors.
- `sudo bash setup.sh sync` applies dashboard changes immediately (the `soar-sync` timer does it every minute).

## Backup and restore

`sudo bash setup.sh backup` writes `/var/backups/soar/soar-backup-<date>.tar.gz` (configuration, secrets, database dump,
workflow, Wazuh files; 14 kept). It contains secrets: copy it off the server. Daily backup:
`echo '30 2 * * * root /bin/bash /opt/soar/setup.sh backup >/var/log/soar-backup.log 2>&1' | sudo tee /etc/cron.d/soar-backup`.

Restore on a new server: install Wazuh 4.x; put `soar.conf`, `keys.env`, `notify.env` in `/opt/soar/` and the saved `env`
as `/opt/soar/.env` (chmod 600); `sudo bash setup.sh install`; restore the database
(`sudo docker compose -f /opt/soar/docker-compose.yml exec -T postgres psql -U soar -d soar < soar-db.sql`);
create the n8n owner account; `sudo bash setup.sh n8n`. Test a restore once before you need it.

## Updating

1. Download the new `setup.sh` (check its SHA-256 from the release page) and run `sudo bash setup.sh install`:
   `soar.conf`, secrets and data are kept, the database schema is updated.
2. `sudo bash setup.sh n8n` to import the new workflow (changes made in the n8n editor are replaced).
3. Endpoints receive the new response script from the server automatically; run the kit again only when the release notes say so.

Wazuh: upgrade only within 4.x and deliberately (`apt-mark unhold`, Wazuh upgrade guide, hold again), then `setup.sh wazuh`.

## Accounts from the command line

`sudo bash setup.sh user list` · `user reset <name>` (temporary password, unlocks and re-enables the account) ·
`user create <name> viewer|analyst|admin` · `user totp-reset <name>` · `user disable|enable <name>`.
Use `user reset` when the last admin is locked out.

## Uninstall

`sudo bash setup.sh uninstall` removes the SOAR-SME blocks from Wazuh, restores the previous enrollment setting, removes
the UFW deny rules and the timer, and stops the containers (data kept). `uninstall --purge` also deletes `/opt/soar` and the
Docker volumes. Endpoints: run the kit with `-Remove`.

## Troubleshooting

| Symptom | Check / fix |
| --- | --- |
| No case appears | `status`: delivery errors to n8n? Workflow published (`setup.sh n8n`)? Rule level ≥ `forward_soar_level`? |
| Cases but no message | `setup.sh test-notify`; channel enabled in Settings > Notifications; risk ≥ `notify_min_risk`; storm digest instead of single messages? |
| Telegram buttons do nothing | approver's Telegram id linked on **Users**; role analyst (admin for isolation); the message is in the configured chat |
| Kill never automatic | group in *auto-kill*? high-fidelity signal? rate limit reached or pause active (see "Not done" in the case)? |
| Action "failed" | case detail shows the reason: agent disconnected, PowerShell Constrained Language Mode, AppLocker/WDAC, EDR blocking the script |
| Isolation refused | Group Policy controls the firewall (run `-Check` on the host); not supported there |
| New agents cannot enroll | the kit carries the enrollment password; agents installed otherwise need `WAZUH_REGISTRATION_PASSWORD` |
| Capacity warning | `events_dropped` / `discarded_count` > 0: server too small or event storm; lean log profile for workstations; more RAM / CPU |
| Dashboard group change not applied | `systemctl status soar-sync.timer`; `sudo bash setup.sh sync` shows the error |
| Retention change not applied | run `sudo bash setup.sh retention <days>` once so the timer knows the indexer password |
| `test-rules` fails a rule | the rule did not fire on its sample in your Wazuh version: check `local_rules.xml` overrides; report it |
