# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.4.x   | :white_check_mark: |
| < 2.4.0   | :x:               |

Security fixes are released in the latest 2.4.x version. Users of earlier 2.4.x
versions can upgrade to the latest version free of charge.

## Reporting a Vulnerability

Please send an e-mail to support@openidc.com with a description of:

- a brief description of the vulnerability
- how the vulnerability can be observed
- optionally the type of vulnerability and any related OWASP category
- non-destructive exploitation details
- **whether you have evidence that the vulnerability is being actively exploited**
  (for example, attacker activity in server logs, or indicators of compromise).
  Please say so explicitly, even if the evidence is incomplete: it determines how
  fast we must act and whom we must notify (see below).

Alternatively, use GitHub's private vulnerability reporting on this repository.

## Followup
After submitting your vulnerability report, you will receive an acknowledgement reply usually within 24 working hours of your report being received.

The team will triage the reported vulnerability, and respond as soon as possible to let you know whether further information is required, whether the vulnerability is in or out of scope, or is a duplicate report. Priority for bug fixes or mitigations is assessed by looking at the impact severity and exploit complexity. 

When the reported vulnerability is resolved, or remediation work is scheduled, the Support team will notify you, and invite you to confirm that the solution covers the vulnerability adequately.

Fixed vulnerabilities are published as a GitHub Security Advisory with a CVE
identifier, listing the affected and fixed versions, once the fix is available.

You are particularly invited to give us feedback on the disclosure handling process, the clarity and quality of the communication relationship, and of course the effectiveness of the vulnerability resolution. This feedback will be used in strict confidence to help us improve our processes for handling reports, developing services, and resolving vulnerabilities.

Where a report qualifies, we will offer to include you on our thanks and acknowledgement page. We will ask you to confirm the details you want included before they are published.

## EU Cyber Resilience Act

OpenIDC maintains this project and also supplies commercially licensed
builds of it. Under Regulation (EU) 2024/2847 (the Cyber Resilience Act),
from 11 September 2026 OpenIDC notifies ENISA and the Dutch National Cyber
Security Centre (NCSC) of any actively exploited vulnerability in
mod_auth_openidc, and of severe incidents affecting the security of the
project's release infrastructure, through the EU single reporting platform,
and informs affected users. Reports of active exploitation sent to
support@openidc.com therefore feed directly into that process; please
include as much detail on the observed exploitation as you can.
