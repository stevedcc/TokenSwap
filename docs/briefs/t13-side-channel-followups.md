# Brief T13: side-channel review follow-ups (short-secret warning, per-socket unlock budget, zeroing, docs)

Read AGENTS.md first. One commit per item, test first (watch it fail for the right reason), a
break-it-once check per key test named in its commit message, `./runtests.sh --unit` after each
item, the full `./runtests.sh` at the end. No hardware suites, `sudo`, real YubiKeys, a real TPM
or `~/.config/tswap`: simulated services, `TSWAP_CONFIG_DIR`, temp folders and the existing broker
test fixtures only. No new NuGet packages.

## Why

On 2026-10-31 GLM and MiMo reviewed `main` (`c6d70a3`) for side channels and oracles. Neither found
a release blocker. Settled by that review, and **not** to be changed here:
- No minimum-duration decryption: no caller supplies ciphertext, and an AES-GCM tag failure leaks
  nothing about the key.
- No `FixedTimeEquals` swaps: the plain `SequenceEqual` calls either compare public or
  caller-known values (ssh blobs, session id), or compare two values tswap already holds
  (`RecordVaultStore.cs:573`, `SecretRecord`). The redactor's scan is a multi-pattern search, not
  an equality check, and its per-byte timing is far below the unlock and spawn noise.
- Template secrets never reach argv (refused at config load, `BrokerTemplatePolicy.cs:235`; env via
  `posix_spawn` envp, files via `--ro-bind-data`). `serve` is already `PR_SET_DUMPABLE 0`, and
  template children have `RLIMIT_CORE` 0.

What the review did find:
1. **Redaction confirms whole guesses.** A caller whose input comes back in a response (a template
   that echoes an argument, an upstream that reflects the request) can send a guess and see whether
   it is replaced by `[REDACTED]`. Partial matches show nothing, so this only works one complete
   guess at a time, at the unlock rate (about 20–30 a minute). That's harmless for a generated
   token, but a 4-digit PIN falls in hours.
2. One socket can use the whole global unlock budget (`BrokerUnlockGuard`, `MaxUnlocksPerMinute`
   = 30 across all sockets), so every other socket gets `503 unlock-rate`.
3. Three buffers are not zeroed: the `user:secret` bytes in `HttpBrokerForwarder.BasicComposite`
   (dropped after base64), `payload` in `SlotPayloadWrap.Unwrap` when the tag check fails, and
   `padded` in `BrokerRedactor.ForSecret` (found in the brief review).
4. Docs: items 1 and 2; the `HEAD` answer keeps the upstream's `Content-Length` from before
   redaction, which can reveal a secret's length; a template whose output or exit code depends on
   a secret's content answers yes/no questions about it; .NET strings can't be zeroed.
5. No tests pin redaction of very short secrets or overlapping forms.

## Decisions (settled here)

1. **Warn, never refuse** (owner, 2026-10-31: "Idiot proof is impossible, long enough to be safe is
   long enough to be a hassle. We don't know their pain points"). A short secret works exactly as
   before; the broker only says so.
2. **Threshold: fewer than 16 bytes**, one constant: `BrokerShortSecretWarnings.ShortSecretBytes = 16`
   in a new `TswapCore/Broker/BrokerShortSecretWarnings.cs`. The warning text interpolates the
   constant (no literal "16" in the message).
3. **Where the check runs: above the secret source, not inside it.** The test fixtures use
   `FakeBrokerSecrets`, so a check inside `VaultBrokerSecretSource` would never run in a test. Put it
   where the broker receives values from `IBrokerSecretSource`: after a successful `secrets.Read`
   for a route (`BrokerRequestHandler.cs:155`) and after a successful `secrets.ReadMany` for a
   template (`BrokerTemplateCalls.cs:195`), checking every value returned. A value the source
   refuses (missing, CR/LF/NUL for a route) is never seen, so it is never warned about; that's
   intended. ssh-agent keys load through a separate source (`VaultSshKeySource` via
   `SshAgentKeyLoader`, `SshKeys.cs:32/71`), so they are excluded structurally. Don't add any
   caller flag to the secret source interfaces.
4. **Once per secret name per `serve` process.** `BrokerShortSecretWarnings` holds a thread-safe set
   of names already warned about (`ConcurrentDictionary`, or a lock). One instance is created where
   `BrokerServer` builds the request handler (`BrokerServer.cs:133`) and shared by the route and
   template paths, so a SIGHUP reload (which swaps only the policy) doesn't reset it. It is checked
   as soon as the value arrives, so it doesn't depend on whether the request then succeeds.
5. **Output: one `event` line through `BrokerLog.Event`** (`broker.log` and the journal,
   owner-only). Nothing reaches the caller: the response is unchanged in content, status and
   timing class. The message (before `BrokerLog.Escape`, which escapes the quotes) is exactly:
   `$"secret '{name}' is shorter than {ShortSecretBytes} bytes: a caller whose input comes back in a response can test guesses against it (a match is redacted); see BROKER.md \"Redaction confirms whole guesses\""`
   The secret's length is never logged.
6. **Per-socket unlock budget:** add `BrokerLimits.MaxUnlocksPerSocketPerMinute = 20`. Keep the
   global `MaxUnlocksPerMinute = 30` unchanged: it limits how hard the hardware is hit, and it
   stays the ceiling. `BrokerUnlockGuard.Refusal(socket)` checks in this order: `locked-out`, then
   the new `socket-unlock-rate` (that socket at its own budget), then the global `unlock-rate`.
   The reason is log-only, as today: the caller gets the same uniform `503` body (routes and
   templates) or the same `SSH_AGENT_FAILURE` (ssh-agent, same guard,
   `SshAgentListener.cs:280/297`). `RecordAttempt(string socket)` counts the attempt globally and
   for that socket, whatever the outcome. It has two production call sites,
   `BrokerRequestHandler.cs:209` (routes and templates both go through `UnlockAsync`) and
   `SshAgentListener.cs:299`, plus one test call (`BrokerServerTests.cs:418`). Adding the socket
   argument there is a mechanical signature change, not an assertion change. Prune per-socket
   queues like the global one and drop empty entries. Update `Refusal`'s doc comment (the new
   reason) and the stale `MaxFailedUnlocksPerMinute` reference in `BrokerUnlockGuard`'s summary.
   The existing guard and server rate tests already use several sockets and stay valid under this
   order; if one doesn't, stop and report.
7. **Zeroing (three buffers, no behaviour change):** the `BasicComposite` array right after the
   base64 call (`try/finally`, a small helper is fine); `payload` in `SlotPayloadWrap.Unwrap`'s
   `catch` before throwing; `padded` in `BrokerRedactor.ForSecret`'s alignment loop
   (`BrokerRedactor.cs:93-100`, zeroed on every iteration, including the `continue` path).
8. **Out of reach, so not done:** `string` copies (the Latin-1 header value, the redactor's
   string-derived forms) can't be zeroed in .NET; the docs say so.

## Items

### Item 1: short-secret warning

Tests (`BrokerHarness` with `FakeBrokerSecrets`; build the expected log text from the constant and
`BrokerLog.Escape`, never by hand):
- a route whose secret is 15 bytes: the first request logs the line once; a second request to the
  same route logs nothing new;
- the same request with a 15-byte and a 16-byte secret of the same shape: identical status, an
  identical body after redaction (both `[REDACTED]` where the value was echoed), and identical
  response header names and values apart from `Date` (or the harness's clock is fixed, so `Date`
  matches too);
- a 16-byte secret: no warning line;
- a template with two secrets, one 15 bytes and one 40: one warning, naming the 15-byte one;
- two routes sharing one short secret: one warning in total (it's per secret name);
- the first request to a short-secret route whose upstream answers 500: the warning is still
  logged (decision 4);
- an ssh-agent sign: no warning (use a normal test key; the exclusion is structural, decision 3);
- with a 15-byte secret: the **message passed to `BrokerLog.Event`** (not the timestamped log line)
  contains neither the secret nor "15" (the length); use a secret name without "15" in it.

Break-it-once: (a) remove the once-only set: the "second request logs nothing new" test fails;
(b) change the comparison to `<=`: the 16-byte test fails.

### Item 2: per-socket unlock budget

Guard-level tests (injected `TimeProvider`, as the existing guard tests do):
- socket A makes 20 unlock attempts within a minute: the 21st is refused with
  `socket-unlock-rate`; socket B can still unlock at the same moment;
- A at 20 and B at 10: the next attempt on a third socket C is refused with `unlock-rate`
  (global ceiling, unchanged), **and** the next attempt on A is refused with `socket-unlock-rate`
  (pins the socket-before-global order);
- after the minute passes on the fake clock, A can unlock again;
- check order: a socket that is both locked out and at its budget reports `locked-out`.

Path-level tests (one each, through the harness):
- a route socket at its budget: uniform `503` body, byte-identical to an `unlock-rate` refusal,
  log reason `socket-unlock-rate`;
- a template socket at its budget: the same;
- an ssh-agent socket at its budget: `SSH_AGENT_FAILURE` and log reason `socket-unlock-rate`.

Break-it-once: drop the per-socket check: the first guard test fails.

Docs (item 4) state the consequence plainly: one socket alone can now unlock 20 times a minute,
not 30 (an ssh client sees `SSH_AGENT_FAILURE` beyond that). It bounds one socket's share and
doesn't promise fairness: two sockets together can still use up the global 30.

### Item 3: zeroing

The three buffers in decision 7. None of them is visible outside its method; the existing tests
pin the behaviour (header values, unwrap results, redaction). Don't add a production seam only to
observe a buffer. The commit message states that the change can't be observed by a test.

### Item 4: docs (`docs/BROKER.md`)

- Under "Threat model", after "Redaction is best-effort", a new subsection **"Redaction confirms
  whole guesses"**:
  - what a caller can learn (whether a complete guess equals the secret) and what it can't
    (anything from a partial match);
  - the rate: one guess per secret per unlock, so a template that reads several secrets allows
    one guess for each; at most 20 unlocks a minute per socket and 30 in total;
  - what that means: a generated `tswap create` value never falls; a short password or PIN can
    fall in hours to months;
  - the warning from item 1;
  - the oracle is cleanest for text-shaped secrets; see the UTF-8 note under "Redaction is
    best-effort";
  - advice: use generated values for broker routes and templates; a short value someone else
    chose still works.
- In the same place: a `HEAD` answer keeps the upstream's `Content-Length` (every other response
  is re-chunked without it), which can reveal the length of a secret the upstream echoes into the
  body.
- Under "Redaction is best-effort": the encoded forms (percent, JSON) are built from the value as
  UTF-8 text. A secret that isn't valid UTF-8 is redacted in its raw, hex and base64 forms; a
  byte-accurate percent or JSON escape of it may pass.
- "What a template author must not do": a template whose output or exit code depends on a
  secret's content (`grep`, a comparison) answers yes/no questions about it to every caller.
- The limits section: the per-socket unlock budget and the consequence stated in item 2.
- "Memory": `string` copies (the header value, the redactor's forms) can't be zeroed in .NET.
  Only root and the vault user can reach them, and both can read the vault anyway.
- A short **"Timing"** paragraph under "Threat model":
  - refusals are byte-identical and answered before any unlock;
  - an allowed request takes an unlock longer, which tells a caller only what its own allow-list
    already says;
  - there is no minimum-duration decryption, because no caller supplies ciphertext and AES-GCM
    leaks nothing on a failed tag.

Land the subsection title in item 1's commit (a stub with the final heading), so the warning never
points at a missing section; item 4 fills it in.

### Item 5: redaction tests for very short secrets and overlapping forms

Tests (`BrokerRedactor` and `BrokerTemplateOutput`, the same cases for both):
- secrets of 1, 2 and 3 bytes (e.g. `"1"`, `"11"`, `"a1"`) and one non-ASCII byte;
- **the claimed forms are pinned by hand as test data** for each secret: raw; hex upper and lower;
  base64 with and without padding, base64url, and the aligned cores where long enough; and the
  percent, form, JSON, wrapped and spaced forms where they differ from the others. Assert that
  `ForSecret(...).Forms` contains every pinned form, so dropping a claimed form fails a test;
- inputs: every pinned form (e.g. `3131` for `"11"`, a hex-only input), each alone, side by side,
  and overlapping with another form; plus hand-built overlaps (for `"11"`: `31311`, `1131`,
  `3111`); then, as extra coverage, every form in `ForSecret(...).Forms`; each split at every chunk
  boundary;
- assert that no complete pinned form survives in the output; pin the exact output for the
  hand-built overlap cases (a fragment of the caller's own input next to a redaction is fine);
- for the non-ASCII byte, cover only the forms the redactor claims; the UTF-8 limitation is
  documented (item 4), not fixed.
If a case leaves a complete form from `Forms` in the output, **stop and report** with the case;
don't change the redactor's matching rule without a ruling.

Break-it-once: remove the hex forms from `ForSecret`: the pinned-forms assertion and the `3131`
input case both fail.

## Out of scope

- Refusing short secrets, or a length check at `tswap create`/`add` time.
- Any change to the redactor's matching rule, the refusal bodies, or the global limits' values.
- `FixedTimeEquals` swaps and minimum-duration decryption (settled above).
- The connection counter order (a refused uid is closed at once; nothing to gain).
