# Brief T27: `tswap slot enroll --via user@host`, the four enrolment steps carried over SSH

Issue: https://github.com/stevedcc/TokenSwap/issues/191. Base: `origin/main` at 2d79f79.
Read AGENTS.md and CLAUDE.md first, then `TswapCli/Commands/SlotCommand.cs` (`Execute`, `ExecuteRequest`,
`ExecuteApprove`, `ExecuteAccept`, `ExecuteMerge`, `SplitRecoveryKeyFlag`, `UnlockForKeyringChange`),
`TswapCli/CommandContext.cs` (`WriteOutputFile`, `RequireSudo`), `TswapTests/SlotCommandTests.cs` (the two-folder
`Run(dir, testKey, stdin, args)` helper), `docs/multi-machine.md` ("Joining another machine", "Remote enrolment of a
YubiKey into a TPM vault, step by step"), `docs/security-model.md` and `TswapCore/Prompt.cs`.

One commit per task, test first, a break-it-once check per key test (name in the commit message which line you
reverted and which test failed), `./runtests.sh --unit` after each task, the full `./runtests.sh` at the end (run it
locally). No hardware suites, `ykman`, `sudo`, real YubiKeys, real `ssh` to another machine or `~/.config/tswap`:
simulated services, `TSWAP_CONFIG_DIR` and temp folders only. Commits end with
`Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, explicit-path commits, no push, merge or rebase; stop and
report when the brief can't be built as written. Never change an existing test's assertion. British spelling in new
text (enrol, enrolment); existing identifiers and messages that say "enroll" stay as they are.

## Why

Adding a device to a keyring vault today is four hand-carried steps on two machines: `slot request` (joining machine),
`sudo slot approve` (vault's home), `slot accept` (joining machine, writes a receipt), `sudo slot merge <receipt>`
(vault's home). For one person with SSH between their machines, carrying the files is busywork. The owner's case: a
desk YubiKey and a wallet YubiKey joining a TPM vault on the home router (Fedora CoreOS; its `core` user has
passwordless sudo), later more TPM and Secure Enclave machines.

## The design (decided; rulings marked)

`tswap slot enroll --via <destination> [--tpm | --secure-enclave --with-touch|--no-touch] [--password|--no-password]
[--vault-dir <folder>] [--remote-tswap <path>] [--no-remote-sudo]`, run on the **joining** machine:

1. **Pre-flight** (nothing written, nothing touched): every refusal `slot request` would make with the same flags
   (a pending request, flag conflicts, `--secure-enclave` without a touch choice, ...) is made first, with its own
   message. Then one SSH call runs `<remote prefix> --version` on the host; a failure (non-zero exit, no output)
   refuses with ``Couldn't run tswap on <destination> over SSH (`<the remote command>` exited <code>). Nothing was
   changed. Check that ssh <destination> works and that the remote command runs there without a prompt
   (docs/multi-machine.md#enrolling-over-ssh); or carry the files by hand (slot request, approve, accept, merge).``
2. **Request**, locally, exactly as `slot request <file>` with the same flags (its prompts, touches and output
   unchanged), into the enrolment folder (below).
3. **Approve**, remotely: `<remote prefix> slot approve - -`, the request file on its stdin; its stdout is the approve
   file. The host's messages (its fingerprint of the requesting slot, touch prompts) arrive on the local stderr as
   they are printed.
4. **Accept**, locally, exactly as `slot accept <approve file> [--vault-dir <folder>]` (it already refuses an approve
   file whose slot id, echoed public key, backend or hardware blob differ from the pending request, and asks for the
   vault password when the slot has one); its receipt goes into the enrolment folder.
5. **Merge**, remotely: `<remote prefix> slot merge -`, the receipt on its stdin. `enroll` never passes `--yes`, so the
   host adds only a slot it approved in step 3 (the existing `ApprovedSlots` guard; anything else is refused because
   stdin is not a terminal).
6. On success: print this slot's fingerprint again (`This machine's slot: <fingerprint>`, the one step 2 printed;
   the host's view of it is above, from step 3, for the user to compare), then `✓ Enrolled: <destination>'s vault now
   opens with <device>, and this machine has its copy.`, and delete the enrolment folder.

**The remote prefix.** `sudo -n <remote tswap>`; `--no-remote-sudo` drops `sudo -n` (a Windows host, whose OpenSSH
gives an administrator an elevated session that passes `RequireSudo`; or a login as root). `--remote-tswap <path>`
(default `tswap`) names the program on the host. Ruling: the remote command is built from fixed words plus that path,
and the path must match `^[A-Za-z0-9_./:\\-]+$` and not start with `-` (refused as a usage error otherwise), so it needs
no quoting in any remote shell (POSIX sh, cmd, PowerShell). `-n` because no terminal reaches the host (step 3 and 5
use stdin for files): sudo must not wait for a password it can't read.

**Privilege on the host, documented, no password handling in tswap.** Either a sudoers rule for exactly the three
commands, for the SSH user:
`<user> ALL=(root) NOPASSWD: /usr/local/bin/tswap --version, /usr/local/bin/tswap slot approve - -, /usr/local/bin/tswap slot merge -`
(the path where tswap is installed), or a user with passwordless sudo already (Fedora CoreOS `core`), or
`--no-remote-sudo` as above. Ruling (v1): no interactive `ssh -t` mode. A pseudo-terminal carries stdin, stdout and
the prompts in one stream, so the files can't travel beside a sudo password prompt. A host that needs a password
for sudo, or a vault password or recovery key to open, uses the hand-carried flow. The docs must say plainly what
the sudoers rule gives away: any process running as that user on the host can approve a request, which hands out a
way into the vault, the same class as `export` (see `SlotCommand`'s own doc comment on why approve needs sudo).
Recommend it only for a host account that runs nothing else untrusted, or a dedicated SSH key restricted with
`command=` in `authorized_keys` is out of scope (mention it as an option the owner may prefer, one line, no recipe).

**The destination.** Passed to `ssh` as one argument after `--` (`ssh -T -- <destination> <remote command>`), so it
can never be read as an option; refused as a usage error when it is empty, starts with `-`, or contains whitespace or
a control character. No `BatchMode`: ssh asks for a key passphrase or a new host key at `/dev/tty` itself, which works
with stdin piped. `-T` (no pseudo-terminal).

**The `-` forms of approve and merge** (new, also usable by hand):
- `slot approve - <approve-file>` reads the request from stdin; `slot approve <request-file> -` writes the approve
  file to stdout; `slot approve - -` both. `slot merge -` reads the receipt from stdin.
- With an approve file of `-`, **stdout carries exactly the serialised approve file and nothing else**: every human
  line the command prints (including anything printed during the unlock: touch prompts, banners) goes to stderr.
  Build it by running approve with a console whose `Out` is its `Error`, and writing the file to the real stdout once
  at the end, after the `ApprovedSlots` save.
- A `-` input is refused together with `--recovery-key-stdin` (usage error: stdin can carry only one of them).
- A `-` input refuses when stdin is a terminal (`slot approve: '-' reads the request file from stdin, and stdin is a
  terminal here. Pipe the file in, or name it.`; the same shape for merge's receipt), and when it is longer than
  1 MiB (`... is larger than 1 MiB, so it is not a <request file|receipt>. Nothing was changed.`). The bytes are
  then parsed exactly as the file would be.
- `RequireSudo` stays the first thing approve does, before stdin is read, as for a file.

**The enrolment folder.** `<config dir>/enrol/<first 8 hex of the slot id>/` (created 0700 on Unix, inside the config
folder on Windows, which is already the user's), holding `request.json`, `approve.json` and `receipt.json` as each step
writes them. Kept on any failure, deleted on success. Ruling: inside the config folder, not the working directory,
because the approve file belongs with this machine's pending private key and must not land in a synced folder by
accident.

**Failure handling: stop at the first failed step, change nothing more, say what is left.** Exit code non-zero; the
local messages, each naming the folder's actual paths:
- approve failed (ssh non-zero, empty or unparsable stdout): `The host didn't approve the request (<reason>). This
  machine's pending request is kept; nothing was added on <destination>. Fix the cause above and run the same 'tswap
  slot enroll' again, or carry <request.json> to the host and run 'sudo tswap slot approve <request.json>
  approve.json' there, then 'tswap slot accept approve.json' here.` Ruling: running `enroll` again with a pending
  request **continues from the pending request** (it skips step 2 and sends the kept `request.json`) instead of
  refusing, when the enrolment folder for that pending slot id exists; with a pending request and no such folder it
  refuses as `slot request` does today. This keeps a retry from needing a second touch-and-request.
- accept failed: its own message (unchanged), then `The host approved this slot but its keyring is unchanged. After
  fixing that, run 'tswap slot accept <approve.json>' here, then 'sudo tswap slot merge <receipt>' on <destination>.`
- merge failed: `This machine has its copy of the vault, but <destination> didn't add the slot (<reason>), so the
  host's own keyring doesn't know it yet. Carry <receipt.json> to the host and run 'sudo tswap slot merge
  <receipt.json>' there.` (This machine's copy opens; the host's doesn't list the slot until merged.)

**Where SSH runs (the seam).** A new `ISshTransport` in `TswapCli/Ssh/`:
`SshResult Run(string destination, IReadOnlyList<string> remoteArgs, ReadOnlyMemory<byte> stdin)` returning
`record SshResult(int ExitCode, byte[] Stdout)`; the remote stderr goes straight to the local stderr (inherited, live).
`ProcessSshTransport` (the default) starts `ssh` from `PATH` (a constructor parameter for the program path, for its
own test), argv built by a pure `internal static IReadOnlyList<string> BuildArgv(string destination,
IReadOnlyList<string> remoteArgs)` = `["-T", "--", destination, string.Join(' ', remoteArgs)]`, stdin written then
closed, stdout read to the end (refused past 1 MiB, as above). `CommandContext` gets an init-only
`ISshTransport Ssh { get; init; }` defaulting to `ProcessSshTransport`; tests set it.

**Agents.** `slot enroll` is human use only: add it to `Prompt.cs`'s "must NEVER use" list beside `slot merge`, as
``- `%CMD% slot enroll --via <user@host>` — Adds this machine's key or chip to the vault on another machine over SSH
(human use only)``, and regenerate the prompt hash where tests pin it (a sanctioned change: say so in the commit).
It doesn't need local sudo (request and accept don't).

## Task 1: the `-` forms of `slot approve` and `slot merge`

Tests (`TswapTests/SlotStdioTests.cs`, two config folders as in `SlotCommandTests`):
- `approve - -` with the request bytes on stdin: exit 0; stdout is one serialised approve file with nothing before or
  after (stdout == `SerializeApprove(DeserializeApprove(stdout))`, untrimmed; the wrap is random, so it can't be
  compared with a second approve), and stderr contains the fingerprint line and `✓ Approved`. Then `slot accept` of
  those bytes (written to a file) on the joining folder succeeds.
- `approve - out.json` and `approve req.json -` each work.
- `merge -` with a receipt on stdin adds the approved slot; with a receipt holding a slot the host didn't approve it
  refuses with the existing "did not approve" message and the keyring is unchanged (assert the config bytes).
- Refusals: `-` with `--recovery-key-stdin` (usage, nothing read); a stdin over 1 MiB (message above, config bytes
  unchanged); stdin a terminal (the fake console's `IsInputRedirected == false`); `approve - -` without sudo in a
  non-bypass context refuses before stdin is read (a stdin that throws on read proves it).
- Break-it-once: write one human line to the real stdout in the `-` path; the "nothing before or after" test fails.

## Task 2: `ISshTransport`, `ProcessSshTransport` and `slot enroll --via`

Tests (`TswapTests/SlotEnrollTests.cs`): a `LoopbackSshTransport` test double that, for `remoteArgs` starting with the
expected prefix (`sudo`, `-n`, `tswap` by default), runs the rest in-process via `CliRunner.Run` against the host's
config folder and test key, with the given stdin, a sudo-bypassed context, and returns exit code and stdout; it records
every call (destination, args). Each test checks the outcome the user cares about: afterwards **both folders open with
the new slot** (the joining folder via its key, the host's keyring lists the slot id) or, on failure, exactly what is
left.
- Happy path, YubiKey (simulated): exit 0; host keyring has the new slot; joining folder unlocks and `get` of a secret
  the host added before enrolment returns it; enrolment folder gone; calls were `--version`, `slot approve - -`,
  `slot merge -` in that order; no `--yes` anywhere.
- Happy path with `--tpm` (simulated TPM) and with `--vault-dir` (a shared folder: accept joins it).
- `--no-remote-sudo` and `--remote-tswap /opt/tswap/tswap`: the args the double saw.
- Each step's failure: pre-flight fails (double returns 255): nothing written locally (no pending config, no folder);
  approve fails (double returns 1 / empty stdout / garbage): pending request and `request.json` kept, host keyring
  unchanged, message names the kept path; **retry** after that continues from the kept request (no second request:
  the simulated key's challenge counter or a recording YubiKey service shows one enrolment) and succeeds; accept fails
  (double returns an approve file for another request, made by a second pending folder): accept's own refusal, then
  the T27 line; host keyring unchanged; merge fails (double returns 1 for merge): joining folder opens, host keyring
  unchanged, `receipt.json` kept and named.
- Usage refusals: destination `-oProxyCommand=x`, `a b`, empty; `--remote-tswap 'tswap; rm'`; unknown flag; no
  `--via`. Each before any SSH call (the double saw nothing).
- `ProcessSshTransport.BuildArgv("me@host", ["sudo","-n","tswap","slot","merge","-"])` ==
  `["-T","--","me@host","sudo -n tswap slot merge -"]`; on Unix only (a first-statement platform guard as in T23), a
  stub program (a script in a temp folder that writes its argv and stdin to files and prints `ok`) proves the argv,
  that stdin arrived and was closed, and that stdout came back.
- Break-it-once: pass `--yes` to the remote merge; the unapproved-slot test (approve one request, merge a receipt for
  another) must fail. And: drop the `--` from `BuildArgv`; the argv test fails.

## Task 3: docs, help, prompt

- `docs/multi-machine.md`: a new section `## Enrolling over SSH` after "Joining another machine": the command, one
  example for the owner's case (desk YubiKey into the router's TPM vault: `tswap slot enroll --via core@router`), what
  each step does, the privilege options with the sudoers line and its trade-off (above), Windows hosts
  (`--no-remote-sudo`, OpenSSH Server is an optional feature needed only on the host), the enrolment folder and the
  retry, and "the hand-carried flow stays as the fallback". Link it from "Remote enrolment ... step by step".
- `docs/security-model.md`: one row or paragraph: what `enroll` trusts (SSH host key and user key authenticate the
  channel; the files are the same reviewed formats; the joining side still checks the approve file against its
  pending request; the host merges only what it approved) and the sudoers trade-off, linking the section above.
- `SlotCommand`'s `Forms`, `Description` and the usage text; the generated command reference (`docs/commands.md`,
  regenerated the way the repo does it, a test pins it); shell completions if `slot` subcommands are listed there.
- `Prompt.cs`: the line above.

## Out of scope

An interactive `ssh -t` mode; `--remote-config`; a FIDO2 slot over SSH (`slot add --fido2` is already local, and a
FIDO2 slot isn't made through request/approve); the broker; any change to the request, approve or receipt formats;
an `authorized_keys` `command=` recipe; automatic host discovery.
