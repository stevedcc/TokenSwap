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

## Why

T27 carries the request and the approve file on the SSH session's stdin and stdout (`ssh -T`), so nothing on the host
can ask a question: sudo must need no password (`sudo -n`, a sudoers rule) and the host's vault must open without a
vault password or recovery key. The owner: "Needing sudo without a password is too big of a filter." A normal host,
where a person logs in with a password or key and sudo asks for their password, can't be enrolled into today.

## The design (decided; rulings marked)

**Two modes.** The default, **interactive**, needs a terminal on the joining machine and gives the host's commands a
terminal of their own (`ssh -t`), so sudo's password, the host's vault password, a recovery key prompt or a touch
prompt all work there. `--batch` is T27's flow, unchanged (`ssh -T`, `-` forms, `sudo -n`, no prompt on the host).
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
- Ruling: the `--expect` hash is why staging is safe. Another process of the same user on the host could swap a staged
  file between `put` and `approve`; the hash, which the joining machine computed over the bytes it sent on the
  authenticated SSH channel, makes approve and merge refuse any other file. Under sudo the staging folder is
  `SUDO_USER`'s config folder (`CliEnvironment`), so `put` as the user and `approve` under sudo see the same folder.
  On Windows (no sudo; an elevated administrator session) it is the same user's folder anyway.

**The interactive sequence**, replacing T27's steps 3 and 5 (steps 1, 2, 4 and 6 and the machine states unchanged):
- Pre-flight: `<remote tswap> --version`, without sudo, in batch form (stdout captured).
- Step 3: `stage <id> put request` (batch form, request on stdin), then `ssh -t` `<sudo> <remote tswap> slot approve
  --staged <id> --expect <hash>` (interactive form, below), then `stage <id> get approve` (batch form, stdout is the
  approve file; same 1 MiB cap, zeroed after it is written to the local `approve.json`).
- Step 5: `stage <id> put receipt`, then `ssh -t` `<sudo> <remote tswap> slot merge --staged <id> --expect <hash>`,
  then `stage <id> clean`.
- `<sudo>` is `sudo` (no `-n`: sudo asks on the terminal), or nothing under `--no-remote-sudo`.
- After each interactive step the joining side checks the remote exit code; non-zero is that step's failure, with
  T27's messages (the hand commands now name the staged forms or the file forms; and `stage <id> clean` is added to
  them). A failure after `put` leaves the staging folder; the message names it and the `clean` command.
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
Unix") with its `SudoTableDrive` driver. `Prompt.cs`: no change (`slot enroll` is already human only); `slot stage` is
plumbing for `enroll` and is named in the NEVER list beside it, "(human use only, run by `slot enroll`)".

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
  and use the sudo-detection seam the other "refused under sudo" tests use, e.g. `vault move`'s).
- `approve --staged` with a host vault that needs its vault password: the password is read from the (fake) terminal
  and the approve succeeds; the same host with `approve - -` (T27) still refuses because stdin isn't a terminal. This
  is the outcome T28 exists for.
- `--staged` combined with a positional file, with `-`, or with `--recovery-key-stdin`: usage error. (Ruling: the
  recovery key over the interactive terminal is typed at its prompt as for the file form; `--recovery-key-stdin` stays
  a file-form and `-`-form option.)
- Break-it-once: skip the hash comparison; the swap test fails.

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
**additional** `Forms` entries, the pinned literals unchanged as in T27); regenerate `docs/commands.md`; the
`slot stage` sudo-table row and driver; `SlotCommand`'s and `SlotEnroll`'s doc comments; the follow-up issue #331's
docs points that this rewrite touches anyway (the label also covers ssh's own stderr in batch mode; "readable by you
only" exact on Unix, the config folder's ACLs on Windows).

## Out of scope

A single terminal session for both approve and merge; `sudo` timestamp sharing across sessions; a password agent for
the host; the rest of #331 (its code points); FIDO2 over SSH; any change to the request, approve or receipt formats.
