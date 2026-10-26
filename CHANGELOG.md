# Changelog

## 1.0.0 — first public release

- Detection: 45 Wazuh rule definitions for Windows and Active Directory (credential theft, Kerberoasting decoy, DCSync,
  ransomware precursors, malicious documents, living-off-the-land binaries, brute force, persistence, defence evasion,
  Defender failures and exclusions).
- Triage in n8n: cases with deduplication, verdict reuse (knowledge with expiry), outbreak incidents, alert-storm digests,
  rarity; local-only by default, optional cloud mode with masking, AI providers Gemini, Claude and OpenAI-compatible APIs.
- Response through the dashboard backend: approvals on the dashboard and in Telegram with expiry, automatic kill per group
  for high-fidelity cases with rate limits, pause switch, scoped exceptions; endpoint actions popup, Defender scan, evidence,
  kill process tree, suspend / resume, block IP, isolation with automatic release; protected processes checked by path and signature.
- Dashboard: cases, approvals, actions, incidents, hosts and logs, knowledge, exceptions, users with roles and optional 2FA,
  audit log, all settings (groups, retention, notifications, Wazuh forwarding).
- Notifications: Telegram, Microsoft Teams, Slack, Discord, with editable templates.
- Installer: one file, Wazuh 4.9.1–4.14 installation, sizing check, enrollment password, UFW hardening, HTTPS on the LAN,
  Windows kit with pre-check, self-tests (`test-rules`, `test-notify`, `test-ar`), backup, retention, uninstall.
