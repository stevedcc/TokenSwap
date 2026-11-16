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

**Review history.** Round 2: GLM ready yes; MiMo no on four text slips (a leftover retry ruling, `--fresh` deleting
before the confirmation, hand commands with a bare `tswap` that sudo's `secure_path` can't find, pinned help
literals), folded with both reviewers' Minors. Round 1 (MiMo and GLM-5.3, both "Ready to implement: no", no Critical, design judged sound) found
gaps in the brief's text, all folded in below: the machine states a retry depends on (a pending request without
enrolment files, a declined overwrite, a re-run after a merge failure), the retry ignoring the new flags and having no
way to abandon it (now `--fresh` and a flag check), `--vault-dir` threading (request refuses it without `--password`),
hand-finish commands that the recommended sudoers rule would refuse (now the `-` forms), and the hand-written sudo
table, its `SudoTableDrive` driver and the pinned subcommand list in `CommandReferenceTests` (now sanctioned and
specified). Minors folded: no prompt-hash pin exists (clause dropped), failure reasons never echo remote stdout,
remote stderr lines are labelled, the ssh child is killed at the 1 MiB cap, the host's merge output is shown,
`secure_path` and the full tswap path in the docs, presence-gated hosts, abandoned folders, the guard sentence, the
sudo-refusal test conventions, and the Task 2 break-it-once.

## Why

Adding a device to a keyring vault today is four hand-carried steps on two machines: `slot request` (joining machine),
`sudo slot approve` (vault's home), `slot accept` (joining machine, writes a receipt), `sudo slot merge <receipt>`
(vault's home). For one person with SSH between their machines, carrying the files is busywork. The owner's case: a
desk YubiKey and a wallet YubiKey joining a TPM vault on the home router (Fedora CoreOS; its `core` user has
passwordless sudo), later more TPM and Secure Enclave machines.

## The design (decided; rulings marked)

`tswap slot enroll --via <destination> [--tpm | --secure-enclave --with-touch|--no-touch] [--password|--no-password]
[--vault-dir <folder>] [--remote-tswap <path>] [--no-remote-sudo] [--fresh]`, run on the **joining** machine:

**Flag threading.** `--tpm`, `--secure-enclave`, `--with-touch`/`--no-touch` and `--password`/`--no-password` go to
step 2's request. `--vault-dir` always goes to step 4's accept, and to step 2's request too only when `--password` is
given (`slot request` refuses `--vault-dir` without `--password`; `slot accept --vault-dir` joins a password-less shared
folder on its own, as `docs/multi-machine.md` "Sharing a vault folder" shows).

**Machine states, checked first** (from the config and `<config dir>/enrol/`, before any SSH call):
- **No pending request** (no config, or a complete one): step 2 runs as `slot request` does, including its
  `This machine already has a config. Overwrite and start a new slot request?` question on a complete config. A "no"
  or EOF there stops `enroll` with exit 1 and `Nothing was changed.`; nothing is sent. If step 2 fails after it
  saved the pending config but before `request.json` was written (`ExecuteRequest` saves first), `enroll` stops with
  ``The pending request was saved but its request file was not written (<reason>); the previous config was backed
  up to <backup path>. Run 'tswap slot enroll ... --fresh' to start over, or 'tswap slot request <file>' by hand.``
  (never "Nothing was changed").
- **A pending request and `<config dir>/enrol/<id>/request.json` for its slot id**: continue from it (skip step 2),
  printing first `Continuing the pending enrolment of <device> kept in <folder> (run with --fresh to start over).`
  Refused (usage-style, before any SSH call) when a backend, touch or password flag **this run names** differs from
  the pending request (`Config.Backend`; `Config.RequiresTouch` for a Secure Enclave; `Config.PendingVaultPassword`,
  or for a YubiKey its blob's password and touch marks); flags this run doesn't name don't constrain, so the plain
  retry the failure messages suggest always continues: ``This machine's pending enrolment is
  for <device>, not what this command names. Run the same command without those flags to continue it, or add
  --fresh to start over.`` A retry re-runs steps 3 to 5 against the `--via` destination given now.
- **A pending request with no such `request.json`** (a hand-made `slot request`, or the files are gone): refuse with
  ``This machine has a pending slot request that 'slot enroll' has no files for. Finish it by hand (slot approve on
  the vault's machine, then slot accept here), or run 'tswap slot enroll ... --fresh' to start over.``
- **`--fresh`**: run step 2 (which asks its overwrite question about the pending config as `slot request` does), and
  only once step 2 has written the new `request.json` delete the other `<config dir>/enrol/` folders (they may hold a
  receipt a failed merge said to keep). A "no" or EOF changes nothing, folders included. Ruling: `--fresh` never
  removes the pending request by itself; only step 2's own overwrite does, after the person says yes.
- Two `enroll` runs at once on one machine are unsupported (last writer wins through the safe writer; say so in the
  docs, nothing more).

1. **Pre-flight** (nothing written, nothing touched): every refusal `slot request` would make with the same flags
   (flag conflicts, `--secure-enclave` without a touch choice, ...) and the state checks above are made first, each
   with its own message. Then one SSH call runs `<remote prefix> --version` on the host; a failure (non-zero exit, no
   output) refuses with ``Couldn't run tswap on <destination> over SSH (`<the remote command>` exited <code>).
   Nothing was changed. Check that ssh <destination> works and that the remote command runs there without a prompt
   (docs/multi-machine.md#enrolling-over-ssh); or carry the files by hand (slot request, approve, accept, merge).``
2. **Request**, locally, exactly as `slot request <file>` with the threaded flags (its prompts, touches and output
   unchanged), into the enrolment folder (below).
3. **Approve**, remotely: `<remote prefix> slot approve - -`, the request file on its stdin; its stdout is the approve
   file. The host's messages (its fingerprint of the requesting slot, touch prompts) arrive on the local stderr as
   they are printed, each line prefixed `[<destination>] ` by the transport's relay, so the host's lines are visibly the
   host's (a label for the person, not a boundary: all host output is untrusted text).
4. **Accept**, locally, exactly as `slot accept <approve file> [--vault-dir <folder>]` (it already refuses an approve
   file whose slot id, echoed public key, backend or hardware blob differ from the pending request, and asks for the
   vault password when the slot has one); its receipt goes into the enrolment folder.
5. **Merge**, remotely: `<remote prefix> slot merge -`, the receipt on its stdin. `enroll` never passes `--yes`, so the
   host adds only a slot it approved and hasn't merged yet (the existing `ApprovedSlots` guard; anything else is
   refused because stdin is not a terminal). The host's merge output (it has no file form; it comes back on stdout:
   "Adding approved slot: ... fingerprint ...") is printed locally after a successful call, each line prefixed
   `[<destination>] `.
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
(the path where tswap is installed; give the same full path to `--remote-tswap`, because sudo's `secure_path` on
Fedora and RHEL leaves out `/usr/local/bin` and the rule matches the path and arguments exactly), or a user with
passwordless sudo already (Fedora CoreOS `core`), or `--no-remote-sudo` as above (on Windows the SSH account must be
an administrator; if its session turns out not to be elevated, approve refuses loudly with "requires an
administrator prompt" and the hand flow remains). Ruling (v1): no interactive `ssh -t` mode. A pseudo-terminal carries stdin, stdout and
the prompts in one stream, so the files can't travel beside a sudo password prompt. A host that needs a password
for sudo, a vault password or recovery key to open, or a presence check no one can answer over `ssh -T` (a
`--with-touch` Secure Enclave slot, a FIDO2-only way in) uses the hand-carried flow. The host's shell must print
nothing on stdout at login (startup files that echo would corrupt the approve file; the parse refusal catches it). The docs must say plainly what
the sudoers rule gives away: any process running as that user on the host can approve a request, which hands out a
way into the vault, the same class as `export` (see `SlotCommand`'s own doc comment on why approve needs sudo).
Recommend it only for a host account that runs nothing else untrusted, or a dedicated SSH key restricted with
`command=` in `authorized_keys` is out of scope (mention it as an option the owner may prefer, one line, no recipe).

**The destination.** Passed to `ssh` as one argument after `--` (`ssh -T -- <destination> <remote command>`), so it
can never be read as an option; refused as a usage error when it is empty, starts with `-`, or contains whitespace or
a control character. No `BatchMode`: ssh asks for a key passphrase or a new host key at `/dev/tty` itself, which works
with stdin piped. `-T` (no pseudo-terminal).

**The `-` forms of approve and merge** (new, also usable by hand). In `Forms` they are **additional entries**
(`slot approve - -`, `slot merge -`); the existing entries and help literals stay verbatim, because
`SlotHelp_MergeTakesAReceipt`, `SlotHelp_AcceptNamesVaultDir` and `SlotUsage_IsTheHelpWithThePrefix` pin them
(the help suffix keeps beginning ` (approve, merge and add take`). Check `CommandReferenceTests` with the extra
entries too:
- `slot approve - <approve-file>` reads the request from stdin; `slot approve <request-file> -` writes the approve
  file to stdout; `slot approve - -` both. `slot merge -` reads the receipt from stdin.
- With an approve file of `-`, **stdout carries exactly the serialised approve file and nothing else**: every human
  line the command prints (including anything printed during the unlock: touch prompts, banners) goes to stderr.
  Build it by running approve with `ctx with { Console = <a console whose Out is the original Error> }`, and writing
  the file to the **original `ctx.Console.Out`** (saved before the swap; never the process-global `Console.Out`, which
  the test doubles can't capture) once at the end, after the `ApprovedSlots` save. The closing line says `✓ Approved.
  Approve file written to stdout.` A named approve file is still written through `ctx.WriteOutputFile`, as today.
- A `-` input is refused together with `--recovery-key-stdin` (usage error: stdin can carry only one of them).
- A `-` input refuses when stdin is a terminal (`slot approve: '-' reads the request file from stdin, and stdin is a
  terminal here. Pipe the file in, or name it.`; the same shape for merge's receipt), and when it is longer than
  1 MiB (`... is larger than 1 MiB, so it is not a <request file|receipt>. Nothing was changed.`). The bytes are
  then parsed exactly as the file would be.
- `RequireSudo` stays the first thing approve does, before stdin is read, as for a file.

**The enrolment folder.** `<config dir>/enrol/<first 8 hex of the slot id>/` (created 0700 on Unix, inside the config
folder on Windows, which is already the user's), holding `request.json`, `approve.json` and `receipt.json` as each step
writes them. Kept on any failure, deleted on success and by `--fresh`. Ruling: inside the config folder, not the working
directory, because the approve file belongs with this machine's pending private key and must not land in a synced
folder by accident. The docs tell the person to delete `<config dir>/enrol/` folders of enrolments they abandon.

**Failure handling: stop at the first failed step, change nothing more, say what is left.** Exit code non-zero; the
local messages, each naming the folder's actual paths. A `<reason>` is the exit code, `no output` or a one-line parse
error, **never the captured bytes** (a partial approve file is a way into the vault while the pending private key is
in `config.json`). The hand commands named are the `-` forms, which the sudoers rule above allows, written with the
program this run used on the host: `sudo <--remote-tswap value>` (default `sudo tswap`; no `sudo` under
`--no-remote-sudo`), shown below as `<host tswap>`:
- approve failed (ssh non-zero, empty or unparsable stdout): `The host didn't approve the request (<reason>). This
  machine's pending request is kept; nothing was added on <destination>. Fix the cause above and run the same 'tswap
  slot enroll' again (it continues from the kept request), or carry <request.json> to the host and run '<host tswap>
  slot approve - - < request.json > approve.json' there, then 'tswap slot accept approve.json' here.` (A retry
  follows "Machine states" above: it continues iff `enrol/<id>/request.json` exists for the pending slot id.)
- accept failed: its own message (unchanged); if this machine no longer has a pending request afterwards (accept
  saves the config before writing the receipt), then `This machine has joined the vault but no receipt was written;
  run 'tswap slot enroll ... --fresh' for a new enrolment, or merge this machine's vault folder on the host with
  'vault merge'.` Otherwise `The host approved this slot but its keyring is unchanged. After fixing that, run 'tswap
  slot accept <approve.json>' here, then '<host tswap> slot merge - < receipt.json' on <destination>.`
- merge failed: `This machine has its copy of the vault, but <destination> didn't add the slot (<reason>), so the
  host's own keyring doesn't know it yet. Carry <receipt.json> to the host and run '<host tswap> slot merge -
  < receipt.json' there. Running 'slot enroll' again would start a new enrolment; the kept receipt is the way to
  finish this one.` (This machine's copy opens; the host's doesn't list the slot until merged.)

**Where SSH runs (the seam).** A new `ISshTransport` in `TswapCli/Ssh/`:
`SshResult Run(string destination, IReadOnlyList<string> remoteArgs, ReadOnlyMemory<byte> stdin, TextWriter stderr)`
returning `record SshResult(int ExitCode, byte[] Stdout)`; the remote stderr is relayed line by line, as it arrives,
to `stderr` with the `[<destination>] ` prefix (the caller passes `ctx.Console.Error`).
`ProcessSshTransport` (the default) starts `ssh` from `PATH` (a constructor parameter for the program path, for its
own test), argv built by a pure `internal static IReadOnlyList<string> BuildArgv(string destination,
IReadOnlyList<string> remoteArgs)` = `["-T", "--", destination, string.Join(' ', remoteArgs)]`, stdin written then
closed (safe because approve and merge read all of stdin before writing), stdout read to the end; past 1 MiB the ssh
child is killed (process tree) and the call refused, as above. `enroll` zeroes the captured approve bytes after
writing `approve.json`. `CommandContext` gets an init-only
`ISshTransport Ssh { get; init; }` defaulting to `ProcessSshTransport`; tests set it.

**Agents.** `slot enroll` is human use only: add it to `Prompt.cs`'s "must NEVER use" list beside `slot merge`, as
``- `%CMD% slot enroll --via <user@host>` — Adds this machine's key or chip to the vault on another machine over SSH
(human use only)`` (no test pins the prompt hash; say in the commit that the prompt changed). It doesn't need local
sudo (request and accept don't). Also name it in AGENTS.md's privilege lists. In `docs/agent-integration.md` it is **not** a row of the agent-role
table: give it the callout below that table that `init` and `agent start` have (no sudo, but human use only).

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
  non-bypass context refuses before stdin is read (proved with a small `IConsole` whose `In` throws on any read; `FakeConsole.Reads` doesn't count stream reads).
  Sudo-refusal tests follow AGENTS.md: return early on `Environment.IsPrivilegedProcess` and assert the
  platform-neutral "requires", as `SlotCommandTests`' existing ones do.
- `approve req.json -`: the closing line on stderr says `written to stdout`.
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
- Happy path with `--tpm` (simulated TPM); with `--vault-dir F` and no `--password` (F is the host's shared record
  folder, password-less: the request gets no `--vault-dir`, accept joins F, and the joining machine opens the records
  in F); and with `--password --vault-dir F` (F holds a `vault-password` file: both steps get `--vault-dir`).
- `--no-remote-sudo` and `--remote-tswap /opt/tswap/tswap`: the args the double saw.
- Remote stderr arrives prefixed `[<destination>] ` (the double writes a line to the given stderr); the host's merge
  stdout is printed locally, prefixed.
- States: a complete config and "no" to the overwrite question: exit 1, no SSH call after the pre-flight, config bytes
  unchanged; a pending request with no `enrol/<id>/request.json`: the refusal above, no SSH call; continuing with
  `--tpm` when the pending request is a YubiKey's: refused, no SSH call; `--fresh` deletes the folder and asks the
  overwrite question; a hand-made pending request plus `--fresh` and "yes": a new enrolment completes.
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
  stub program (a script in a temp folder that writes its argv and stdin to files and prints `ok`, and writes two lines to stderr) proves the argv, that stdin arrived and was closed, that stdout came
  back, and that both stderr lines reached the given writer prefixed `[me@host] `.
- Merge failure messages and every failure message: assert the captured stdout bytes (the double returns a known
  marker string as garbage) never appear in the local output.
- Break-it-once: pass `--yes` to the remote merge; the happy path's "no `--yes` anywhere" assertion must fail. Drop
  the `--` from `BuildArgv`; the argv test fails. Skip the flag check on continue; the `--tpm`-on-a-YubiKey-pending test
  fails.

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
- The hand-written sudo table in `docs/commands.md` ("Which commands need sudo"): a row
  `| slot enroll | no | Runs request and accept here; approve and merge run on the other machine over SSH, under its sudo (human use only) |`,
  and a `SudoTableDrive` driver for it that runs `slot enroll` without sudo to its own early refusal or to success
  (give `FleetMachine` a way to set `Ssh`, or drive it to the pre-flight refusal with a double that fails `--version`;
  the driver must show no sudo refusal). **Sanctioned change:** `CommandReferenceTests.Subcommands_TokenisesBothUsageShapes`
  pins the list `["request","approve","accept","merge","add"]`; add `enroll` in its place in `Forms`' order, and say
  so in the commit message.
- `docs/multi-machine.md`'s four-step section shows the `-` forms beside the file forms, with a note that the sudoers
  rule allows only the `-` forms with the exact path it names, and that `slot approve <req> -` at a terminal puts the
  approve file (a way into the vault for the requester) in the scrollback.
- `Prompt.cs`: the line above.

## Out of scope

An interactive `ssh -t` mode; `--remote-config`; a FIDO2 slot over SSH (`slot add --fido2` is already local, and a
FIDO2 slot isn't made through request/approve); the broker; any change to the request, approve or receipt formats;
an `authorized_keys` `command=` recipe; automatic host discovery.
