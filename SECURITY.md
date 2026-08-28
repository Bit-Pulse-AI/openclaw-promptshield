# Security Policy

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report suspected vulnerabilities privately to **security@promptshields.com**, or
via GitHub's [private vulnerability reporting][gh-pvr] on this repository
(Security → Report a vulnerability).

Please include:

- A description of the issue and the impact you believe it has
- Steps to reproduce, or a proof-of-concept
- The affected version, commit SHA, or deployment
- Any suggested remediation

We aim to acknowledge reports within **3 business days** and to provide a
remediation plan within **10 business days**. We will keep you updated as we work
on a fix, and we are happy to credit you in the release notes unless you prefer
otherwise.

## Supported versions

Only the latest release on the default branch receives security updates. Older
tags are provided as-is.

## Scope

In scope:

- Code in this repository
- Default configurations shipped in this repository

Out of scope:

- Findings that require a compromised host or a malicious browser extension
  already running with elevated privileges
- Denial of service through resource exhaustion on a self-hosted deployment you
  control
- Vulnerabilities in third-party dependencies — please report those upstream,
  though we appreciate a heads-up so we can bump the pin

## Handling secrets

This repository must never contain live credentials. All configuration is
supplied through environment variables or untracked local config files; see the
`*.example` / `*.template` files for the expected shape.

If you believe a credential has been committed, email
**security@promptshields.com** immediately rather than opening a pull request
that removes it — a public commit that deletes a secret advertises the secret.

[gh-pvr]: https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability
