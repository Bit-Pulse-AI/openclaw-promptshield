# Contributing to OpenClaw Prompt Shield

## Before you start

Open an issue first for anything larger than a fix. This is a security policy
layer, and a change to what it allows or denies deserves discussion before it is
written.

## Development setup

Requires Python 3.9 or later and an Azure AI Content Safety resource.

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env    # then fill in your Azure credentials
```

## Checks that must pass

There is no test suite in this repository yet. Adding one alongside a change is
the single most valuable contribution available. Until then, state in the pull
request how you exercised the shields, including the inputs you tried that
should have been blocked.

## Changing a shield

- **Default to denying.** A shield that fails open is not a control.
- **Never widen the default allowlists casually.** The shipped bash allowlist is
  a demonstration default, not a recommendation; adding an interpreter to it
  grants arbitrary execution.
- **Every decision must be logged**, allowed and blocked alike, with a reason.
  A block with no reason cannot be investigated.
- **Do not present classifier output as a guarantee.** Injection detection is
  probabilistic and will be evaded; code and documentation should both say so.

## Coding conventions

Match the surrounding code. Comment density, naming, and idiom should be
indistinguishable from what is already there. A change that reads as though it
were written by a different person is harder to review, whatever its merits.

## Never commit

- Live credentials, API keys, tokens, or connection strings with real passwords
- Customer data, real prompt text, or anything that identifies a person
- Generated artefacts, build output, or editor and OS scratch files
- Roadmap phases, customer names, pricing strategy, or other internal material.
  This repository is public.

If you believe a credential has been committed, email
**security@promptshields.com** immediately rather than opening a pull request
that removes it — a public commit that deletes a secret advertises the secret.

## Pull requests

- One logical change per pull request.
- Say what you changed and why. If you fixed a defect, say how you reproduced it.
- State what you verified, and how. "Tests pass" is only useful if you ran them.
- If a claim in the README stops being true because of your change, update the
  README in the same pull request.

By contributing you agree that your contributions are licensed under the same
terms as this repository, and you confirm you have the right to grant that
licence.

## Conduct

Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
Vulnerabilities go to [SECURITY.md](SECURITY.md), never to a public issue.
