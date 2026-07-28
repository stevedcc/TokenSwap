# Threat model

What tswap defends against, what it does not, and why the line sits where it does.

This exists because most scope questions about tswap turn out to be threat-model questions in
disguise — "should we integrate with X", "should unlock require a touch", "is this configuration
safe" — and they are much easier to settle against a written model than from first principles each
time. Read this before proposing a security feature or arguing one is missing.

## The adversary

**A helpful AI agent that gets a bit greedy.**

Not a malicious actor. Not an attacker with a foothold. An assistant the user *invited*, working on
their behalf, with legitimate access to the repository and the shell — which will do what it can to
reach the goal it was given.

**The user here is a developer or an operator.** Ops is not a secondary audience: an agent driving
`kubectl`, `terraform`, Ansible, or a deployment runbook is handling production credentials with a
far larger blast radius than a developer's local `.env`, and it is doing so on servers where nobody
is sitting at a keyboard. Ops widens the model in three specific ways, all of which the design
already has to account for:

- **Headless and remote is the norm**, not an edge case — which is why unattended operation is a
  first-class mode rather than a degraded one, and why no consent mechanism may assume a display.
- **Secrets arrive embedded in configuration** — Kubernetes manifests, Helm values, Ansible vars —
  rather than in a single `.env`. That is the `redact`/`tocomment`/`check` surface, and the
  motivation for heuristic detection in structured config (#15).
- **Access is shared across a fleet and a team**, which is what Phase 6's keyring and multi-machine
  enrolment exist for, and what makes shared storage backends (#161) more than a convenience.

That is the whole point. An agent that cannot act is useless; an agent that acts will read files,
print variables, write debug scripts, and inspect its environment, because those are the ordinary
ways to accomplish ordinary tasks. None of that is misbehaviour. It is what "helpful" looks like,
and it is exactly how secrets leak.

## The harm

**The secret enters the model's context and is remembered.**

This is the specific thing to prevent, and it is narrower and sharper than "a secret was exposed":

- Once a value is in the context window it is in the conversation history, and plausibly in
  provider-side logs.
- It can be reproduced later, somewhere the developer is not watching — a config file, a commit
  message, a comment, a summary.
- It cannot be un-seen. Rotation is the only remedy, which is why `burn` exists.

A developer should be able to hand an agent a task that *uses* credentials without acquiring a new
thing to worry about. That is the product.

## The incident this comes from

Not hypothetical. An agent was used to set up a `step-ca` server with YubiKey-backed root
certificates, and to issue a client certificate for mutual TLS in front of a Paperless-ngx
deployment. **A week later, it still knew the password for that mutual TLS certificate.**

Every element of the model is visible in that one example:

- **Nothing attacked anything.** The agent recorded the password because recording what it did is
  helpful — a runbook, a setup script, a note. Good assistant behaviour, and precisely the leak.
- **The harm was persistence, not theft.** The password was not exfiltrated. It survived the
  session, in something re-read later, and resurfaced a week on. "The agent saw it once" and "the
  agent knows it" are different problems, and the second is the one that matters.
- **The root of trust was hardware-backed and it did not help.** The CA's root keys were on a
  YubiKey — properly protected, entirely irrelevant. The leak was one layer up, in a password that
  sat in plaintext where the agent could read and repeat it. Hardware secures the vault at rest; it
  does nothing about what the agent is handed. Two different jobs (see §Where the hardware fits).
- **It was an ops task, not a dev one.** Certificate authorities, mutual TLS, a self-hosted service.

It also shows where the leak enters: **at creation**. The credential was generated during the
session, by a tool the agent was driving, and printed to output the agent could read. Redaction
cannot save a value tswap does not yet know about — which is why `create` (generate inside the
vault, so the value never exists in the agent's view) is the load-bearing primitive for
provisioning work, not an afterthought to `add`.

## What tswap guarantees

> **The agent does not learn the secret value.**

It never enters the agent's context, logs, or output — so it cannot be retained, reused, quoted
back, or shipped to a model provider.

The mechanisms:

- `{{token}}` substitution via `run` — the agent composes commands referring to secrets by name,
  and never handles the value.
- Output redaction — a subprocess that prints a secret has it filtered before the agent sees it.
- The command blocklist and pipe/redirect block — the obvious "just show me the value" paths fail
  closed.
- `redact` / `tocomment` / `apply` / `check` — secrets stay out of the files the agent reads.
- The sudo boundary — everything that deliberately reveals plaintext sits behind it, and agents are
  told not to cross it.
- `burn` — cooperative remediation when something slips through. The right shape for an adversary
  that is careless rather than hostile: the agent is told to report its own accident.

## What tswap does not guarantee

Being explicit here is what keeps the guarantee above credible.

- **It is not a sandbox.** An agent with shell access can do many things tswap does not mediate.
- **It does not prevent an authorized use from being harmful.** `tswap run -- curl -d {{token}}
  https://somewhere` passes every check by design: `curl` is a legitimate program and using a
  credential against a remote endpoint is the intended use case. tswap cannot distinguish the task
  from a mistake, and a human pressing a touch button cannot either.
- **It does not defend against a deliberately adversarial agent.** One actively trying to defeat
  mediation — building novel exfiltration channels, exploiting the substitution machinery — is out
  of scope, and designing against it would produce a different and probably unusable product.
- **It is not change control.** An ops agent given production credentials can change production.
  tswap keeps the credential out of the agent's context; it does not review, gate, or limit what
  the agent does with the access it was legitimately handed. That is a different tool.
- **It is not perfect, and does not need to be.** The bar is defence in depth against the paths a
  greedy-but-well-meaning agent actually takes.

## What follows from this

**Failure modes are ranked by how *ordinary* they are, not how clever.** The highest-value fixes
are the ones a helpful agent hits by accident:

- Writing a shell script or `bash -c '…'` to accomplish a step — completely normal behaviour, and
  it walks straight through the blocklist (**#105**). Under this model that is the single most
  valuable fix in the backlog, because the agent is not evading anything; it is just working.
- A test or tool printing a connection string in an encoded or escaped form (**#106**).
- An agent running `ps` while debugging and reading a secret out of argv (**#71**).

**Enforcement beats consent.** Because the adversary is careless rather than hostile, controls that
*prevent* leakage matter more than controls that *ask a human to approve* an action they cannot
evaluate. Presence gates are useful defence in depth for attended work, but they are not the
guarantee, and requiring them would break the automated workflows that are a legitimate and growing
share of the use case.

**Unattended is a supported mode, not a degraded one.** No human is present in CI or a background
task. The mediation layer is designed to be the control that holds without one.

**Scope discipline.** Proposals should be tested against this model rather than against a
general-purpose "make it more secure" instinct. Concretely, this is why an out-of-band GUI consent
prompt was rejected (see #164): it defends against an adversary this model does not have, at a cost
the real use case cannot pay.

## Where the hardware fits

Hardware backing (YubiKey, Secure Enclave, TPM) is not what enforces the guarantee above — the
mediation layer is. Hardware protects the vault **at rest**: disk theft, vault-file copying, a
backup ending up somewhere it shouldn't. Both matter; they are different jobs.

This is worth keeping straight because it is easy to reason as though the hardware is protecting
against the agent. It is not. The agent never touches the vault at rest.

It also decides which backend suits which machine, and the split is by *machine role*, not by
operating system:

- **Workstations** (developer or operator, human present) — a touch-required YubiKey or Secure
  Enclave, if attended defence in depth is wanted. Linux workstation users tend to own tokens
  already.
- **Servers and CI runners** — nobody can touch a token on a rack of machines or an ephemeral
  runner, so unattended operation with a TPM sealing the vault at rest is the right and only
  answer. This is the ops case, and it is a supported configuration rather than a compromise.
