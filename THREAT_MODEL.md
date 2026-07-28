# Threat model

What tswap defends against, what it does not, and why the line sits where it does.

**`README.md` §Threat Model & Non-Goals is the user-facing statement** — the protects-against and
does-not-protect-against tables, and the shallow-blocklist design rationale. Read that first; it is
authoritative on *what* the boundaries are and is not repeated here.

This document is the *why* behind those boundaries: who the adversary is, what harm is actually
being prevented, and how to settle the scope questions that keep recurring — "should we integrate
with X", "should unlock require a touch", "is this configuration safe". Those turn out to be
threat-model questions in disguise, and they are far easier to answer against a written model than
from first principles each time. Read this before proposing a security feature or arguing one is
missing.

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

It also shows where the leak enters, and the answer is narrower than it first appears. Both normal
provisioning paths are already closed: `create` when tswap generates the credential, and
`<source> | tswap ingest <name>` when an external tool does. Neither displays the value.

What remains is the case this incident actually hit: **a tool that prints the credential amid other
output**, as `step-ca` does. It cannot be piped straight into `ingest`, and extracting it means
something reads the surrounding text — which, if that something is the agent, is the leak. The
mitigations are ordering rather than filtering: `create` first and hand the value *to* the tool
(which for most ops tooling means a file path — see #165), or capture cleanly into `ingest` where
the tool can be made to emit only the secret.

## What tswap guarantees

> **The agent does not learn the secret value.**

It never enters the agent's context, logs, or output — so it cannot be retained, reused, quoted
back, or shipped to a model provider.

The mechanisms — note that these cover getting secrets *in* as well as using them, which is half the
problem and easy to overlook:

- `create` — generates a secret inside the vault and displays nothing. The agent asks for a
  credential by name and refers to it by label thereafter, never seeing the value. Non-sudo, so
  this is a normal part of an agent's workflow rather than an escape hatch.
- `ingest` — takes a value from piped stdin, stores it, displays nothing. This is the capture path
  for a credential an *external* tool generated: `<source> | tswap ingest <name>` keeps the value
  out of the agent's view even though tswap did not create it.
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

`README.md` §What tswap does NOT protect against is the full list — determined local root,
sophisticated exfiltration through legitimate programs, process memory, compromised YubiKey
firmware, network interception, offline brute force. Two additions that follow from the adversary
model rather than from the mechanics:

- **It is not change control.** An ops agent given production credentials can change production.
  tswap keeps the credential out of the agent's context; it does not review, gate, or limit what
  the agent does with the access it was legitimately handed. That is a different tool.
- **It is not perfect, and does not need to be.** The bar is defence in depth against the paths a
  greedy-but-well-meaning agent actually takes.

The distinction that matters when triaging a reported gap: the blocklist being **shallow** is
by design (README §Design rationale) — `curl`, `python` and custom binaries can exfiltrate, and
deep shell analysis is explicitly not attempted. But the blocklist **failing at its own stated
job** is a defect. `run -- bash -c 'echo $X'` is the second kind: `echo` is on the list precisely
to catch that mistake, and the interpreter walks around it (#105). "We don't sandbox" is not a
reason to leave that unfixed.

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

## Why the blocklist stays shallow — permanently

`README.md` §Design rationale states the blocklist is intentionally shallow rather than a sandbox.
The formal reason is worth recording so this is not re-proposed every year:

**Deciding whether an arbitrary command will leak a secret is undecidable.** This is Rice's
theorem — every non-trivial semantic property of a program is undecidable, and "exfiltrates the
value it was given" is exactly such a property. The halting problem is the familiar instance of the
same result. No amount of shell parsing, argument analysis or syscall inspection reaches a general
answer, because there isn't one.

So any blocklist is necessarily a **syntactic approximation of a semantic property**, and will
always have both false positives and false negatives. That is not a defect to engineer away; it is
the shape of the problem.

**The consequence is a different success metric.** The question to ask of the blocklist is not "can
it be bypassed" — it can, always, trivially — but **"does it catch the mistakes a cooperative agent
actually makes?"** Coverage of ordinary error, not resistance to a determined one.

That is what makes #105 worth fixing and a deep analyser not worth building. `run -- bash -c
'echo $X'` matters because *writing a small shell wrapper is a completely ordinary thing a helpful
agent does* — it is a coverage gap in a heuristic, not a hole in a boundary. Chasing the general
case is chasing an impossibility; closing the ordinary cases is finite, cheap, and exactly the job.

### What actually scales for cooperative agents

If the model is cooperation, the strongest controls are not restrictions:

- **Clear instructions.** `tswap prompt`'s output is arguably this project's single most important
  security artifact — more so than the blocklist. A cooperative agent does what it is told; telling
  it well is the control. Keep it specific, worked-example-heavy, and current (`prompt-hash`).
- **Make the safe path the easy path.** `create`, `ingest` and `{{token}}` substitution are all
  *easier* than handling plaintext, which is why they get used. The corollary is sharp: **anywhere
  the safe path is harder than the unsafe one is a real vulnerability under this model**, because a
  helpful agent takes the path of least resistance while trying to do its job. That is the actual
  argument for #165 — for a tool wanting `--password-file`, the safe route is currently harder than
  writing the file, so a cooperative agent will write the file.
- **Detect and remediate rather than prevent.** `burn`, `burned` and `check` accept that leaks
  happen and make them visible and recoverable. Already well built, and the right investment.

### The employee model

A useful way to hold all of this: **an agent is an employee.** A badly motivated one can do damage,
and no amount of policy prevents that. What organisations actually do instead is scope access
narrowly, separate duties, train people well, and keep records — accepting that the residual risk
is managed rather than eliminated.

That maps onto tswap almost one-to-one, and is a fair way to audit what is missing:

| Organisational control | tswap |
|---|---|
| Job roles / separation of duties | The sudo boundary — agent vs operator roles (README §Recommended Agent Permissions) ✅ |
| Handbook and training | `tswap prompt`'s skill file, kept current via `prompt-hash` ✅ |
| Incident response | `burn` / `burned` / rotate ✅ |
| Least privilege — need-to-know | **Missing.** Any agent that can `run` can use every secret in the vault (#167) |
| Access records | **Missing.** Nothing logs which secrets were used, when, or by what (#168) |

The two gaps are the two controls that matter most precisely *because* prevention is impossible:
they bound the blast radius and make what happened knowable afterwards. Neither stops a motivated
agent — that is not on offer — but together they are the difference between "assume the whole vault
is exposed" and "this project's credentials were touched on these dates."

### The one honest wrinkle

"Cooperative" is not a fixed property. A prompt-injected agent is a cooperative agent following
someone else's instructions, and the defence against it is the same as the defence against a
motivated one: there isn't one. This does not change the conclusion — it reinforces where the
investment goes. Detection and rotation are the response, not deeper blocking, because deeper
blocking is the thing Rice's theorem rules out.

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
