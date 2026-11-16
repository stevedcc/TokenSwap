# Brief T28: `slot enroll --via` with prompts on the host (sudo password, vault unlock), passwordless sudo optional

Issue: https://github.com/stevedcc/TokenSwap/issues/191 (follow-up; T27 is merged as PR #330). Base: `origin/main` at
c6d2ee3. Read AGENTS.md and CLAUDE.md first, then `docs/briefs/t27-slot-enroll-ssh.md` (the design T28 extends: its
machine states, enrolment folder, failure handling and `-` forms stay as they are), `TswapCli/Commands/SlotEnroll.cs`,
`TswapCli/Ssh/ISshTransport.cs`, `TswapCli/Ssh/ProcessSshTransport.cs`, `SlotCommand.cs` (`ExecuteApprove`,
`ExecuteMerge`, the `-` forms, `ReadStdinFile`), `TswapCli/CliEnvironment.cs` (the config folder under sudo is
`SUDO_USER`'s), `TswapTests/SlotEnrollTests.cs` and its `LoopbackSshTransport`, `docs/multi-machine.md` ("Enrolling
over SSH") and `docs/security-model.md` (its T27 subsection).

One commit per task, test first, a break-it-once check per key test (name in the commit message which line you
reverted and which test failed), `./runtests.sh --unit` after each task, the full `./runtests.sh` at the end (run it
locally). No hardware suites, `ykman`, `sudo`, real YubiKeys, real `ssh` to another machine or `~/.config/tswap`:
simulated services, `TSWAP_CONFIG_DIR` and temp folders only. Commits end with
`Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, explicit-path commits, no push, merge or rebase; stop and
report when the brief can't be built as written. Never change an existing test's assertion except where this brief
sanctions it by name (say so in the commit). British spelling in new text.

**Review history.** Round 2 (both "no" on one-line points: the host fingerprint over the written buffer, not a
re-read; usage errors exit 1, not 2; the swap test's expectation; stale body text): folded, body edited in place, A14
added. Round 1 (MiMo, GLM-5.3: both "no"; design judged sound). Their findings are folded in as the
binding **Amendments** section at the end; where it differs from the text above, the amendments win.

## Why

T27 carries the request and the approve file on the SSH session's stdin and stdout (`ssh -T`), so nothing on the host
can ask a question: sudo must need no password (`sudo -n`, a sudoers rule) and the host's vault must open without a
vault password or recovery key. The owner: "Needing sudo without a password is too big of a filter." A normal host,
where a person logs in with a password or key and sudo asks for their password, can't be enrolled into today.

## The design (decided; rulings marked)

**Two modes.** The default, **interactive**, needs a terminal on the joining machine and gives the host's commands a
terminal of their own (`ssh -t`), so sudo's password, the host's vault password and a touch
prompt (done at the host) work there. `--batch` is T27's flow, unchanged (`ssh -T`, `-` forms, `sudo -n`, no prompt on the host).
`enroll` without a local terminal (stdin or stdout not a terminal) and without `--batch` refuses before anything:
``slot enroll needs a terminal here, because the host's sudo and vault may ask for a password. In a script, add
--batch (the host then must need no password: docs/multi-machine.md#enrolling-over-ssh). Nothing was changed.``

**The files travel separately from the prompts.** Interactive mode never puts a file on a terminal session. The host
keeps the files in a **staging folder** of the SSH user, `<config dir>/enrol-staged/<id>/` on the host (`<id>` = the
same 8 hex characters as the local enrolment folder; created 0700 on Unix, inside the user's config folder on
Windows), reached through new tswap subcommands, so no remote shell syntax is ever needed (the T27 rule stays: the
remote command is fixed words plus the `--remote-tswap` path, nothing quoted):
- `tswap slot stage <id> put request|receipt`: stdin to `request.json` / `receipt.json` in the staging folder
  (atomic, 0600, through the store's safe writer; refuses a terminal stdin and more than 1 MiB as the `-` forms do;
  `<id>` must match `^[0-9a-f]{8}$`). Prints nothing on stdout. No sudo; refused under sudo on Unix
  (``slot stage runs as the SSH user, not under sudo.``) so its files are the user's.
- `tswap slot stage <id> get approve`: the staged `approve.json` to stdout, nothing else on stdout. No sudo.
- `tswap slot stage <id> clean`: delete the staging folder (absent is fine). No sudo.
- `slot approve --staged <id> --expect <sha256-hex>`: reads `request.json` from the staging folder, refuses unless
  its SHA-256 is `<sha256-hex>` (``The staged request file isn't the one the joining machine sent (its SHA-256
  differs). Nothing was approved.``), approves exactly as the file form does (its prompts on the terminal, its
  fingerprint line), and writes `approve.json` into the staging folder through `WriteOutputFile` (under sudo that
  writer keeps the folder owner's ownership, so `stage get` can read it). `RequireSudo` stays first.
- `slot merge --staged <id> --expect <sha256-hex>`: the same for `receipt.json`; no `--yes` is ever passed.
- Ruling: the `--expect` hash binds what the joining machine **sends** (A1); the approve file coming back is bound
  only by a fingerprint the person compares (A3). Under sudo the staging folder is normally `SUDO_USER`'s config
  folder (`CliEnvironment`), so `put` as the user and `approve` under sudo see the same folder; A6 covers when they
  differ. On Windows (no sudo; an elevated administrator session) it is the same user's folder anyway.

**The interactive sequence**, replacing T27's steps 1, 3 and 5 (steps 2, 4 and 6 and the
machine states unchanged):
- Pre-flight: `<remote tswap> --version`, without sudo, in batch form (stdout captured).
- Step 3: `stage <id> put request` (batch form, request on stdin), then `ssh -t` `<sudo> <remote tswap> slot approve
  --staged <id> --expect <hash>` (interactive form, below), then `stage <id> get approve` (batch form, stdout is the
  approve file; same 1 MiB cap, zeroed after it is written to the local `approve.json`).
- Step 5: `stage <id> put receipt`, then `ssh -t` `<sudo> <remote tswap> slot merge --staged <id> --expect <hash>`,
  then `stage <id> clean`.
- `<sudo>` is `sudo` (no `-n`: sudo asks on the terminal), or nothing under `--no-remote-sudo`.
- After each interactive step the joining side checks the remote exit code; non-zero is that step's failure, with
  T27's messages (the hand commands now name the staged forms or the file forms; and `stage <id> clean` is added to
  them). A failure after `put` leaves the staging folder; the message names the `clean` command (A10).
- Before each interactive step print one local line, `On <destination>: <the remote command> (it may ask for your
  sudo password or the vault's unlock there).`, and after it `Back on this machine.`, so the person can tell whose
  prompt they're answering. No `[<destination>] ` prefix in the interactive step (a terminal stream can't be
  relabelled line by line); batch-form calls keep T27's prefix.

**The transport.** `ISshTransport` gains `int RunInteractive(string destination, IReadOnlyList<string> remoteArgs)`:
`ssh -t -- <destination> <joined args>` with stdin, stdout and stderr inherited (the local terminal goes to ssh), the
exit code returned. `BuildArgv` gains the interactive form `["-t", "--", destination, joined]` and, on both forms, the
connection-sharing options below.

**One SSH login per enrolment where OpenSSH allows it** (Linux and macOS clients): every call of one `enroll` run
passes `-o ControlMaster=auto -o ControlPath=<socket> -o ControlPersist=60`, and the run ends (success or failure)
with `ssh -o ControlPath=<socket> -O exit -- <destination>` (its failure ignored). `<socket>` is
`<dir>/%C` with `<dir>` = `$XDG_RUNTIME_DIR/tswap-ssh` when that variable is set, else `<temp dir>/tswap-ssh-<uid>`,
created 0700 and refused (no sharing, a one-line note) if it exists and isn't this user's 0700 folder, or if the
resulting path, with `%C`'s 40 characters, is over 100 bytes (Unix socket path limit). Windows' OpenSSH client has no
connection sharing: no options there, so each call logs in again (documented). Ruling: sharing is a convenience, never
a requirement; any doubt about the socket folder means no sharing, not a refusal.

**Docs.** `docs/multi-machine.md` "Enrolling over SSH": interactive is the default and needs no sudoers rule ("sudo
asks for your password on the host, as when you log in there"); how many prompts to expect (one SSH login on Linux and
macOS with sharing; each step logs in again from Windows; sudo asks once per interactive step, so twice, because sudo
remembers a password per terminal and approve and merge are separate sessions); the staging folder, its `clean`, and
why the hash makes it safe; `--batch` for scripts, with T27's sudoers rule and trade-off moved under it. Fedora
CoreOS's `core` (passwordless sudo, key-only SSH) sees no prompts in either mode. `docs/security-model.md`: the
staging folder and the `--expect` binding; the sudoers rule is needed only for `--batch`. The sudo table: `slot stage`
row (`no`; "Moves the enrolment files between the SSH session and the host's staging folder; refused under sudo on
Unix") with its `SudoTableDrive` driver. `Prompt.cs`: the `slot enroll` line
unchanged; one `slot stage` line added to the NEVER list beside it, "(human use only, run by `slot enroll`)".

## Task 1: `slot stage`, and `--staged/--expect` on approve and merge

Tests (`TswapTests/SlotStageTests.cs`, two `FleetMachine`s as in `SlotEnrollTests`):
- `stage <id> put request` then `approve --staged <id> --expect <hash>` (sudo-bypassed host context) then
  `stage <id> get approve`: the bytes `get` prints are one approve file (the same untrimmed round-trip as T27's
  `approve - -` test) that the joining folder's `slot accept` takes; the host's `ApprovedSlots` has the slot.
- `--expect` with another hash: refused with the message above; `ApprovedSlots` and the config bytes unchanged; no
  `approve.json` in the staging folder. The same for merge (keyring bytes unchanged).
- A swap: `put` the joining machine's request, then overwrite the staged `request.json` with a second machine's
  request, then approve with the first one's hash: refused; nothing approved.
- `stage` refusals: a bad `<id>` (`../x`, `ABCDEF12`, 7 or 9 characters), `put` on a terminal stdin, over 1 MiB, an
  unknown verb, under sudo on Unix (a context with sudo detected: return early when `Environment.IsPrivilegedProcess`
  and test A8's predicate through `CliEnvironment.Create`'s
  `getEnv`/`isPrivileged` seams).
- `approve --staged` with a host vault that needs its vault password: the password is read from the (fake) terminal
  and the approve succeeds; the same host with `approve - -` (T27) still refuses because stdin isn't a terminal. This
  is the outcome T28 exists for.
- `--staged` combined with a positional file, with `-`, or with `--recovery-key-stdin`: usage error (A4).
- Break-it-once: skip the hash comparison; the swap test fails. (A1 and A3 add two more.)

## Task 2: interactive `enroll`, `--batch`, connection sharing

Tests (`SlotEnrollTests`, extended; the `LoopbackSshTransport` gains `RunInteractive`, which runs the command in-process
against the host with a terminal-like fake console fed by the test, and records the call as interactive):
- Default mode, happy path: calls are `--version`, `stage <id> put request`, interactive `sudo tswap slot approve
  --staged <id> --expect <h1>`, `stage <id> get approve`, `stage <id> put receipt`, interactive `sudo tswap slot merge
  --staged <id> --expect <h2>`, `stage <id> clean`, in that order; `<h1>`/`<h2>` are the SHA-256 of the local
  `request.json`/`receipt.json`; no `sudo -n`, no `--yes`; both folders open with the new slot; the host's staging
  folder is gone.
- A host whose vault needs its vault password: interactive enrol succeeds (the double's terminal supplies it);
  `--batch` against the same host fails at approve with T27's message.
- `--batch`: exactly T27's calls (`sudo -n ... slot approve - -`, `slot merge -`); every existing T27 test passes
  unchanged with `--batch` added to its arguments. **Sanctioned change:** the existing `SlotEnrollTests` and the T27
  `SudoTableDrive` driver gain `--batch` in their argument lists where they assert batch behaviour (inputs, not
  assertions); say so in the commit.
- No terminal and no `--batch`: the refusal above, no SSH call, nothing written.
- Each interactive failure (approve exit 1, `get` empty, merge exit 1, `put` exit 1): T27's message for that step, the
  staging folder named with its `clean` command, local state as T27 leaves it.
- The local lines `On <destination>: ...` and `Back on this machine.` around each interactive call.
- `ProcessSshTransport.BuildArgv`: interactive form `["-t", ...sharing options..., "--", dest, joined]`, batch form
  `["-T", ...sharing options..., "--", dest, joined]`; sharing options present on Linux/macOS with a short socket
  folder, absent on Windows and when the folder is unusable (a folder of another mode; a path over 100 bytes). The
  run ends with one `-O exit` call (recorded by a stub). Unix-only stub test for `RunInteractive`: a stub program
  that records argv and exits 3 returns 3.
- Break-it-once: send `sudo -n` in the interactive approve; the happy-path call list fails. Drop the `-O exit`; the
  stub's recorded calls fail.

## Task 3: docs, help, sudo table

As in "Docs" above; `Forms`, `Description`, usage texts for `slot stage` and the new approve/merge options (as
**additional** `Forms` entries; the pinned literals stay, except the subcommand list A5 sanctions); regenerate `docs/commands.md`; the
`slot stage` sudo-table row and driver; `SlotCommand`'s and `SlotEnroll`'s doc comments; the follow-up issue #331's
docs points that this rewrite touches anyway (the label also covers ssh's own stderr in batch mode; "readable by you
only" exact on Unix, the config folder's ACLs on Windows).

## Amendments after brief review round 1 (binding)

**A1. One read, then hash, then parse (MiMo C1).** `approve --staged` and `merge --staged` read the staged file
**once** into a byte buffer, compare the buffer's SHA-256 with `--expect`, and parse **that buffer**; the path is never
read again (no `File.ReadAllText(path)` after the check). Route the staged read through a seam (in the style of
`RequestHooks`) so a test can swap the file **after** the hash check; assert the swap **changed nothing**: the run
ends exactly as the happy path does, the approved (merged) slot is the one in the bytes matching `--expect`, and the
swapped-in request's slot appears nowhere (`ApprovedSlots`, the approve file, the keyring). Task 1's break-it-once:
re-read the file after hashing; the swap-under-the-read test fails. `put` writes the stdin bytes verbatim (no newline, BOM or CRLF
normalisation), so the hash the joiner computed over what it sent matches.

**A2. `--staged` and `--expect` are a pair (MiMo I3, GLM M-5).** Both or neither, else a usage error; `--expect` must
match `^[0-9a-f]{64}$` (lower-case; the joiner sends `Convert.ToHexStringLower`), compared ordinally. Tests: `--staged`
alone, `--expect` alone, a 63-character, an upper-case and a non-hex `--expect`: each a usage error before sudo or any
read.

**A3. The approve file coming back is not bound by a hash (GLM I-1), and the ruling must say so.** `--expect` binds
what the joiner **sends**. The `approve.json` the host writes into the staging folder rests there between the approve
and `get` calls, where a same-user process on the host could replace it with one it crafted: everything `slot accept`
checks is public, and the wrap's associated data (format version, vault id, k, slot id) is public too, so a crafted
approve file can wrap an attacker-chosen key to the joiner's public key. That gives the attacker no way into the real
vault, but a joiner that then writes secrets would write them under a key the attacker knows. This is the same exposure
as the hand-carried flow, where `approve.json` sits in the user's folder too; state it so in `docs/security-model.md`
instead of "the hash makes staging safe". Proportionate binding, specified:
- `approve --staged` serialises the approve file once into a byte buffer (UTF-8 of `SerializeApprove`'s result),
  writes **that buffer** to `approve.json`, and computes its fingerprint over **that buffer**, never a re-read of the
  file. The rendering is `SlotFingerprint`'s style over the SHA-256's first 8 bytes (upper-case hex, groups of 4
  joined by `-`, e.g. `A1B2-C3D4-E5F6-0718`); one helper renders both sides, so the two lines are byte-identical when
  the files are.
- In staged mode approve's closing lines are, instead of the file form's tail (`Approve file written to`, the
  hand-carry and `slot merge <receipt-file>` lines): `✓ Approved. The joining machine collects the approve file next.`
  and, last, `Approve file fingerprint: <rendering>`. The requester-fingerprint line stays as the file form prints it.
- `enroll` computes its line over the exact bytes `get` returned, writes those bytes to the local `approve.json` and
  hands accept those bytes (no re-read either), then prints `Approve file received: <rendering>. It must match the
  approve file fingerprint the host printed above; if it doesn't, press Ctrl-C now (the host's staging folder is then
  left; remove it with '<host tswap> slot stage <id> clean').` and waits for Enter before step 4 (accept).
- Tests: the happy path pins both lines and that they agree; a seam on the host side swaps `approve.json` after it
  is written and before `get`: the two lines differ (the person would see it), and EOF at the Enter leaves the joining
  machine's pending request as T27's approve-failed state does. Break-it-once: compute the host's fingerprint from a
  re-read of the file; the swap test's lines agree and it fails.
- `--batch` has no such gate: there the approve file travels on the SSH session and never rests on the host.
- The docs frame it as `PrintFingerprint` and `SshRelay` frame theirs: a human check, not a boundary (a same-user
  process on the host can also write to the session's terminal), raising the bar from swapping a file to spoofing a
  terminal; the same exposure as the hand-carried flow.

**A4. No recovery-key prompt exists (both, MiMo I1/GLM I-2).** Drop "a recovery key prompt" from "Why" and "Two
modes", and drop the Task 1 recovery-key ruling. The recovery key stays stdin-only and refused on a terminal;
`--staged` with `--recovery-key-stdin` stays a usage error. A host whose only way in is the recovery key uses the
hand-carried flow; `docs/multi-machine.md`'s "what can't go over SSH" keeps saying so for both modes.

**A5. Sanctioned changes, by name (both, MiMo I2/GLM I-3).** Allowed, each said in the commit message:
`CommandReferenceTests.Subcommands_TokenisesBothUsageShapes`' slot list gains `stage` in `Forms`' order;
`SlotEnrollTests.BuildArgv_PutsTheDestinationAfterDoubleDash` keeps passing **unchanged** because `BuildArgv` keeps its
two-argument overload with no sharing (add the sharing and interactive forms as new overloads or a defaulted parameter,
pinned by new tests); `ProcessSshTransport_RunsTheProgram_WithStdin_AndRelaysStderr` likewise runs without sharing
(construct the transport with sharing off); `LoopbackSshTransport`'s fixed-prefix check may become a check of the
exact prefix each call should carry (`tswap` for pre-flight and `stage`, `sudo tswap` for interactive steps,
`sudo -n tswap` for `--batch`); every `ISshTransport` double may change only to compile (give the interface default
implementations for the new members where that keeps doubles untouched). `--batch`'s messages stay byte-identical to
T27's; interactive variants are new strings asserted by new tests. Argument and usage errors are checked before the
no-terminal refusal, so the existing `UsageErrors` cases pass without `--batch`.

**A6. The config folder under sudo can differ (MiMo I4).** `put` as the user resolves `TSWAP_CONFIG_DIR` /
`XDG_CONFIG_HOME`; under sudo `CliEnvironment` uses `SUDO_USER`'s home `~/.config` (sudo resets the environment).
`approve/merge --staged` with no staged file gives its own message, never the mismatch one: ``No staged <request
file|receipt> for <id> in <the resolved staging path>. If the SSH user sets TSWAP_CONFIG_DIR or XDG_CONFIG_HOME,
sudo doesn't see it: see docs/multi-machine.md#enrolling-over-ssh. Nothing was approved.`` (merge: `merged`). The docs
reuse the existing `TSWAP_CONFIG_DIR` + `sudo --preserve-env` note (security-model.md, "which vault a command under
sudo uses"). Test: a staging folder absent → this message, nothing approved.

**A7. Honest prompt counts (both, MiMo I5/GLM M-7).** The docs enumerate: SSH authentication once on Linux/macOS with
sharing, up to seven from a Windows client (pre-flight, put, approve, get, put, merge, clean); sudo twice (approve and
merge, separate terminals); the host's vault unlock twice (approve and merge each unlock: password, and a touch on the
host's own YubiKey or Secure Enclave, which someone must do **at the host**); the joining machine's own prompts
(request's, accept's); the Enter after comparing the approve fingerprint. A recovery-key-only host is not covered.

**A8. `slot stage` refuses real sudo escalation only (MiMo I6).** Refused when the process is privileged **and**
`SUDO_USER` names a non-root user (reuse `CliEnvironment`'s `CheckInvokingUser` rule; a non-privileged process ignores
`SUDO_USER`), not for every root process: a root SSH login with `--no-remote-sudo` is the SSH user
there and may stage. Tests: sudo-escalated → refused; a root process without `SUDO_USER` (seam) → runs.

**A9. Closing the shared connection, and the socket folder (both, M1/M-2).** `ISshTransport` gains `void
EndSession(string destination)` (default: nothing); `ProcessSshTransport` runs `ssh -o ControlPath=<socket> -O exit
-- <destination>` there when sharing was on, ignoring its failure; `enroll` calls it in a `finally` around the run;
the loopback double records it. The socket folder check uses `lstat` semantics: a symlink, another owner, or a mode
other than 0700 means no sharing. The folder itself is left in place (it is reused); the socket goes with `-O exit`
or after `ControlPersist=60`. `docs/security-model.md` says that during the run and up to 60 s after a crash, a
same-user process on the joining machine can reuse the connection (no sudo, no staged-file power: A1 still binds).

**A10. Messages for the new sub-steps (MiMo M3/M7, GLM M-1/M-6).**
- Pre-flight in interactive mode: `<remote tswap> --version` without sudo; its failure text is a new string: ``Couldn't
  run tswap on <destination> over SSH (`<cmd>` <reason>). Nothing was changed. Check that ssh <destination> works and
  that tswap is on the SSH session's PATH there (or give --remote-tswap its full path).`` The batch pre-flight keeps
  T27's text and `sudo -n`.
- A failed `put` or `get`: T27's approve-failed message (put of the request, get) or merge-failed message (put of the
  receipt), with `<reason>` as T27 defines it; a `get` whose output doesn't parse is `its output is not an approve
  file`. An older host answers `slot stage` or `--staged` with a usage error, exit 1 (tswap has no separate
  usage exit code). So when the pre-flight's `--version` output differs from this build's version, every interactive
  step's failure message adds `(the host runs tswap <its version>, this machine <this version>; 'slot stage' needs
  this version or newer there)`; otherwise the reason stays T27's.
- The joining machine's messages never name a host path (it can't know it); they name `<host tswap> slot stage <id>
  clean`. Host-side messages (A6) may name the host's resolved path.
- A failed `stage clean` after a successful merge: a note, ``Note: couldn't remove the host's staging folder; run
  '<host tswap> slot stage <id> clean' there.``, exit 0 (the enrolment is done).
- `--fresh`: the docs say an abandoned enrolment may leave a staging folder on the host, removed with `slot stage <old
  id> clean`.

**A11. Interactive merge on a terminal (MiMo M4).** Over `ssh -t` the host's merge has a terminal, so an unapproved slot
is asked about (Yes/No) instead of refused; `enroll` still never passes `--yes`, and with `--expect` the receipt is the
one the joiner sent. Reword the T27 sentence in `docs/security-model.md` ("refused because stdin is not a terminal")
for both modes.

**A12. Also in Task 3 (both).** AGENTS.md's privilege lists and `slot` bullet (`slot stage` no sudo, plumbing;
`--staged/--expect` on approve and merge); `docs/agent-integration.md`'s callout covers `slot stage` with `enroll`;
`Prompt.cs`: the `enroll` line unchanged, one `slot stage` line added to the NEVER list; completions only if they list
`slot` subcommands. Docs keep T27's warnings that still apply: the host shell must print nothing on stdout at login
(the batch-form calls, `get` included), and `slot stage <id> get approve` run by hand at a terminal puts the approve
file in the scrollback. `--remote-tswap`: the non-sudo calls find `tswap` on the SSH session's PATH, the sudo calls on
sudo's `secure_path`; a full path serves both.

**A14. Round-2 details (both).**
- "`RequireSudo` stays first" means first after argument parsing: usage errors (A2) come before it, as in today's
  approve.
- `LoopbackSshTransport` sets the host's sudo flag from each call's prefix (`sudo`/`sudo -n` → sudo; bare `tswap` →
  not), so `stage` calls don't trip A8. `ProcessSshTransport` takes connection sharing as a constructor parameter
  defaulting to **off** (existing tests construct it unchanged); `enroll`'s production composition turns it on.
  `ISshTransport.RunInteractive`'s default implementation throws `NotSupportedException`; `EndSession`'s does nothing.
- The joining machine's terminal in tests: `FleetMachine.RunOnTerminal` (or its equivalent) for interactive runs, the
  plain run for the no-terminal refusal.
- The Task 2 happy-path call list ends with the recorded `EndSession`.
- `docs/security-model.md`'s "the host's output is untrusted text … control characters replaced" is batch-mode
  behaviour; interactive steps are a raw terminal: scope the sentence when rewording it (A11).
- `docs/commands.md`'s `XDG_RUNTIME_DIR` row gains the socket-folder use.

**A13. Owner check before release (MiMo M7).** One real interactive `slot enroll --via` against a host whose sudo asks
for a password (and, if available, whose vault has a password slot). The Windows-host and Windows-client paths are
untested by CI; say so in the PR.

## Out of scope

A single terminal session for both approve and merge; `sudo` timestamp sharing across sessions; a password agent for
the host; the rest of #331 (its code points); FIDO2 over SSH; any change to the request, approve or receipt formats.
