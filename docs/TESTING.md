# Testing and verification status

Honest status of version 1.0.0: what was verified, how, and what still needs your first deployment.

## Automated tests (all passing on the release build)

| Suite | Tests | Environment |
| --- | --- | --- |
| Backend (dashboard API + executor) | 25 | real FastAPI + PostgreSQL 16; mock Wazuh API, Telegram Bot API, Teams / Slack / Discord |
| n8n workflow code | 22 | the real Code-node JavaScript and IF expressions in an n8n-like harness |
| Workflow SQL | 6 | the real statements on PostgreSQL 16, untyped parameters like n8n |
| Installer (`setup.sh`) | 29 | simulated Wazuh 4.x tree, fake Docker → PostgreSQL, mock Wazuh API / logtest / indexer, real backend |
| Endpoint scripts | 28 | PowerShell 7 on Linux with mocked Windows cmdlets (firewall, tasks, CIM, Defender) |
| Dashboard UI | 19 | the real page in jsdom against the real backend |

Plus `bash -n` and `shellcheck` (no warnings) on `setup.sh`.

## What the tests found and fixed before release

A pipeline race (`grep -q` under `set -o pipefail` could make container checks fail at random),
an SQL error on failed sign-ins, untyped NULL parameters, the case detail rendering, the settings page not loading,
agent look-up picking the wrong agent, and the executor trusting an "automatic" plan without re-checking the group.

## Verification matrix

| Feature | Automated | Self-test at deployment | Not verified on real systems |
| --- | :---: | :---: | --- |
| Accounts, roles, 2FA, password resets, audit | ✓ | | |
| Approvals (dashboard, Telegram), expiry, rate limits, pause, exceptions, incidents, storm digest | ✓ | `test-notify` | real Telegram / Teams delivery |
| Triage logic, masking, AI request/response formats | ✓ | | real Gemini / Claude / OpenAI-compatible answers |
| Rules (45 definitions) | samples prepared | `test-rules` (real Wazuh engine) | matching on your Windows builds |
| Wazuh configuration (blocks, enrollment password, profiles, rollback) | ✓ (simulated) | `check`, Wazuh validation on `wazuh` | |
| Sync dashboard → Wazuh, retention (ISM) | ✓ (mock indexer) | `sync`, `status` | |
| Endpoint actions: popup, kill, scan, evidence, block IP | logic ✓ | `test-ar …` | real Windows behaviour |
| Suspend / resume, isolation | logic ✓ | `test-ar isolate-check` | real Windows behaviour — **test on one machine first** |
| Endpoint pre-check (`-Check`) | parse ✓ | run on your endpoints | |
| n8n workflow end to end | node by node | `test-flow`, step 13 test plan | real n8n runtime (could not run in the build sandbox) |
| HTTPS proxy | config generated | open the HTTPS address | |

## Field-test checklist for a new deployment

☐ `check` clean · ☐ `test-rules` all passed · ☐ `test-notify` all channels sent · ☐ `-Check` on one machine per Windows
build · ☐ `test-ar notice/scan/evidence/isolate-check` on a pilot · ☐ the step 13 scenarios of SETUP.md on a pilot
workstation · ☐ isolation on a test machine only, then lifted · ☐ two weeks in monitor mode before contain.
