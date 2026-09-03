# 🔒 Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| main    | ✅ Yes    |

## 🚨 Reporting a Vulnerability

This project analyzes untrusted text (prompts, retrieved documents, tool output), so
detection-bypass and evasion reports are welcome and treated as security issues, not
just bugs.

1. **Do not disclose publicly** – Do not open a public issue for a bypass technique or
   other security vulnerability.
2. **Use GitHub's private advisory flow** – Go to this repository's **Security** tab →
   **Report a vulnerability** to open a private security advisory with the maintainer.
3. **Provide a detailed description** – Include the input that bypasses detection (or
   the vulnerability details), the expected verdict, the actual verdict, and any
   suggested mitigation.
4. **Wait for a response** – Reports will be acknowledged within 48 hours and triaged
   for a fix or a corpus/pattern update.

## Scope Notes

- This library does **not** call any external API and processes text entirely offline —
  there is no network attack surface in normal use.
- Detection-bypass reports (text that should score `BLOCK`/`FLAG` but scores `ALLOW`)
  are the most valuable class of report for this project and are always in scope.
