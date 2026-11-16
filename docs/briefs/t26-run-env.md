# Brief T26: `tswap run --env VAR={{name}}`, and the agent rule to keep values out of argv

Issue: https://github.com/stevedcc/TokenSwap/issues/71 (read its last comment, "Rewritten 2026-11-15": that is the
design; the older text describes a `bash -c` wrapper `run` no longer uses). Base: `origin/main` at f75be2b.
Read AGENTS.md and CLAUDE.md first, then `TswapCli/Commands/RunCommand.cs` (all of it), `TswapCli/CommandRegistry.cs`
(`AsksForHelp`, `HasGlobalFlagAmongOptions`), `TswapCore/Validation.cs` (`ExtractTokens`, `ThrowIfUnknownTokenSuffix`,
`SubstituteAllTokensInArgs`, `GetBlockedInvocation`, `HasPipeOrRedirect`), `BrokerTemplateValidator` in
`TswapCore/Broker/Templates/BrokerTemplatePolicy.cs` (`CodeEnvNames`/`CodeEnvPrefixes`/`EnvNameRegex` at ~:187-239,
the env loop at :355-370, the 64-entry cap at :395), `TswapCore/Prompt.cs`, `docs/security-model.md` (the "Secrets
in process memory" row, ~:132, and "What `run` masks", ~:209) and `docs/BROKER.md` ("Secrets reach the child through
env or a read-only file only", ~:623).

**Review history.** Round 1 (MiMo and GLM-5.3, both "Ready to implement: no") found two blockers each: the usage
change breaks pinned help assertions the brief forbade touching (now named below as a sanctioned change), and "an
unknown secret" can't be refused before unlock (now split: which refusals happen before unlock and which only after,
before anything starts). MiMo also showed break-it-once (2) couldn't fail, because the fingerprint matcher masks a
stored value with the same label (the masking test now prints a form only the replacements cover), and that the
prompt's first preference (a tool's file or stdin option fed by `{{@file}}`) is a pattern `run` can't do (reworded to
config files; raw password files are #165). Folded in as well: the shared name rule with its 64-character cap,
case-insensitive names for `run`, run-only refused names for macOS/Windows, the help/`-v` scan past `--env`, a
64-pair cap, env values' NUL refusal, `--env` with `{{@file}}`, a real-child argv test, tests for `--verbose`, `--env=`
and `{{@file}}`/unknown-suffix values, and per-platform docs wording.

**Dependency:** RedactingPty **1.2.0** (released 2026-11-15, stevedcc/RedactingPty PR #11) adds
`RedactionOptions.Environment` (`IReadOnlyDictionary<string,string>?`): variables set for the child only, built before
the fork, never in its argv; output redaction still applies (it doesn't mask `Environment` values by itself: `run`
does, below). Bump `TswapCli/TswapCli.csproj` from `[1.1.0]` to `[1.2.0]` in Task 1. It is on nuget.org (both
reviewers checked); some CDN copies of the version index were stale on release day, so if `dotnet restore` can't find
it, re-check with a fresh, uncached fetch before you stop and report.

One commit per task, test first, a break-it-once check per key test (name in the commit message which line you
reverted and which test failed), `./runtests.sh --unit` after each task, the full `./runtests.sh` at the end (run it
locally). No hardware suites, `ykman`, `sudo`, real YubiKeys or `~/.config/tswap`: simulated services,
`TSWAP_CONFIG_DIR` and temp folders only. Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`,
explicit-path commits, no push, merge or rebase; stop and report when the brief can't be built as written. Never change
an existing test's assertion, except the two sanctioned in Task 2 (say so in that commit message).

**Parallel work:** the #311 fields branch adds one check in `RunCommand.Execute` (a refusal of `{{NAME.FIELD}}`
tokens, near the existing `ThrowIfUnknownTokenSuffix` call), a "Fields" section after "Commands you SHOULD use" and four
rules at the end of "Key rules" in `Prompt.cs`, and regenerates the command reference. T26 keeps to its own places:
option parsing at the top of `Execute`, its own section at the **end** of `Prompt.cs` (after "Keeping secrets out of
config files"; issue #71 says "Key rules", moved here to stay clear of #311), and `run`'s `HelpUsage`/`Description`
(regenerate the reference; whichever branch merges later regenerates again).

## Why

Owner, 2026-11-15: "This sounds important." A `{{name}}` in an argument puts the plaintext in the child's argv, and on
Linux without `hidepid` every local user can read it from `/proc/<pid>/cmdline` while the child runs; process
accounting and audit logs can record it too. Checked on the owner's workstation: `/proc` has no `hidepid`, so the
`opencode` agent user can read the owner's `tswap run` command lines today (the OS side is homelab#24). A process's
environment (`/proc/<pid>/environ`) is readable only by the same user and root. The broker's command templates already
pass secrets only through env or a read-only file; `run` gets the same choice.

What it does **not** fix (the docs say so): the agent runs as the same user as the child it starts, so it can read
`/proc/<child>/environ` as easily as the command line. Against the agent itself, `--env` gains nothing; that stays the
job of output masking and of running work under another user (the broker). `--env` protects against other local users
and command-line logging.

## Round 2 clarifications (MiMo and GLM-5.3 both "Ready to implement: yes"; these close their minors)

- **Usage error (MiMo N1):** orchestrator ruling: the bare-`run` usage error shows the same usage as `HelpUsage`
  (`run [--env NAME={{name}}]... [--] <cmd> [args...]`), so the message matches the option just typed. That makes
  `CommandArgumentErrorTests` :30 a third sanctioned assertion change (same reason as `HelpTests` :153/:171: the brief
  changes `run`'s usage); name it in the commit message.
- **Who can read argv elsewhere (MiMo N2):** RedactingPty's README covers Linux only. In the docs: Linux and macOS,
  other local users can read a running process's arguments (`/proc/<pid>/cmdline`; `ps` on macOS); Windows: state only
  what you verify in Microsoft's documentation, otherwise leave the Windows argv cell out. The environment cells stay
  as the README says.
- **Two more refusal rows (MiMo N3):** `ComSpec` and `PSModulePath`, and `X=pre-{{k}}` (a literal around a token).
- **Prompt wording (MiMo N4):** preference #1 says "a config file that can carry the secret on a `# tswap:` line (YAML,
  INI, TOML, JSONC; not strict JSON)".
- **Help scan (MiMo N5):** the sentence says `--help`/`-h` among `run`'s leading options prints usage, "except in an
  `--env` value slot" (there the `--env` shape refusal wins); add a row for `run --env -h cmd`.
- **`docs/agent-integration.md` (MiMo N6):** its `run <cmd>` row (:25) gains one `--env` mention.
- **`XDG_*` (MiMo N7):** in `docs/commands.md` write the prefix as `XDG_*`, never a concrete `XDG_…`/`TSWAP_…` name the
  code doesn't read (`CommandReferenceTests.EnvironmentVariablesDocumented`).
- GLM's round-2 minors, if any, are in `~/RiderProjects/tswap-wt/tools/t26-brief-r2-glm.md`: read and fold them the same
  way (verify, fold or say why not, in the commit message).

## Task 1: `run --env`

Syntax: `tswap run [--env NAME={{name}}]... [--] <cmd> [args...]`.

- Leading `--env NAME=VALUE` pairs (also `--env=NAME=VALUE`; split at the first `=`) are taken before the command; an
  optional `--` ends the options; the first other argument is the command. `--env` after the command is part of the
  command's argv, as today. No command after the options (`run --env X={{s}}`) gives today's usage error, unchanged.
- `NAME`: the broker's `EnvNameRegex` (`\A[A-Za-z_][A-Za-z0-9_]{0,63}\z`), called from the shared place below, not
  copied. `VALUE`: **exactly one token**, `{{name}}` or `{{name:previous}}`. A literal is refused (a deliberate change
  from #71's text: a literal isn't a secret, would sit in tswap's own argv, and is set in the calling shell instead,
  where the child inherits it). `{{@file}}` is refused with its own message (a file path isn't a secret: put it in the
  command); an unknown suffix (`{{x:bogus}}`) gets `ThrowIfUnknownTokenSuffix`'s message, as in argv. At most 64 pairs
  (the broker's cap). A name given twice is refused.
- Refused names: `PATH`, `LC_ALL`, `PWD`, `LD_*`, and every name in `CodeEnvNames`/`CodeEnvPrefixes` (`BASH_ENV`,
  `GIT_SSH_COMMAND`, `PAGER`, `HOME`, …). Move the name regex, those sets and prefixes into one shared place in
  `TswapCore` (for example `ChildEnvironmentRules`) that **classifies** a name (bad shape, baseline, loader, code); each
  caller formats its own message, because the broker's (sandbox baseline, "in the sandbox") must stay byte-identical
  and don't fit `run`. `ConfigPointerEnvNames` stays broker-only. That refactor is a separate, behaviour-neutral commit
  inside Task 1, guarded by `BrokerTemplateConfigTests.ABadEnvEntry_IsRefused` and
  `BrokerTemplateProgramAndEnvTests.ANewlyDeniedEnvName_IsRefused`/`OrdinaryEnvNames_AreStillAccepted` unchanged.
  `run` adds, on its side only (adding them to the shared list would change the broker): the `DYLD_` prefix (macOS
  loader), `PATHEXT`, `ComSpec` and `PSModulePath` (Windows). `run` compares names **ignoring case** on every platform,
  for the refusals and for duplicates (Windows treats `Path` and `PATH` as one variable, and RedactingPty rejects such a
  pair only at spawn, as a raw `ArgumentException`); the broker stays ordinal.
- Every refusal of the command line happens before the vault is unlocked: everything above, the command checks below
  and "no tokens". Only these need the vault, so they happen after unlock but before any folder is written or any child
  starts, as today in argv: an unknown secret, a missing previous value, an unreadable record, and a value that is null
  or holds a NUL (refused with an env-worded `TswapException`, not the argv message and not RedactingPty's
  `ArgumentException`).
- The tokens in `--env` values count as `run`'s tokens: "no tokens found" is not raised when the only token is in an
  `--env` value; each token is resolved once with the others (`view.ResolveToken`, burned warning included), decrypting
  only what is used. Keep the env values apart from the argv tokens' values: only argv tokens go to
  `SubstituteAllTokensInArgs`, the post-substitution checks and `NameCulprit` (an env value is never in argv, so it can
  never be named as a culprit for a word in it).
- The command is checked exactly as today (blocklist, inline code, pipes/redirects, `{{@file}}` rules) on its own
  words; `env`/`printenv`/`set` as the program stay refused (they would print the environment). `--env` with a
  `{{@file}}` in the command works (`run --env PGPASSWORD={{db-pw}} -- psql -f {{@cfg}}`).
- Help and `-v`: `CommandRegistry`'s two scans stop at the first non-dash argument, so `run --env X={{s}} --help` would
  run a program called `--help`. For `run` only, both scans skip the value after a separate `--env` and stop at `--`:
  `--help`/`-h` among `run`'s leading options prints its usage, `-v` there gets the global-flag refusal, and `run --
  --help …` passes `--help` on as the program. Other commands' scans are unchanged (their tests guard it).
- The child gets the variables through `RedactionOptions.Environment`; tswap's own environment is never changed.
- Each `--env` value is masked in the output exactly like a `{{name}}` in argv today: the same `Redact(token, value,
  [])` replacements with the same `[REDACTED: <token>]` label, besides the matcher.
- `--verbose` lists the variable names set (one line, `Environment: X, Y`), never values.

Tests (`RunEnvTests`, `FleetMachine`, the simulated services and `RecordingPty`, whose child lambda can read
`pty.Options.Environment`; the Linux argv test in `EndToEndTests`, which runs the real binary and a real child):
- `RunEnv_SetsTheVariable_ValueMaskedInOutput`: the child prints the value raw and as **standard base64 with its
  padding removed**, a form the replacements cover and the matcher does not (`security-model.md`, "What `run` masks").
  Pick a value whose base64 ends in `=` and contains `+` or `/` (else it equals the unpadded base64url form, which the
  matcher covers), and assert both properties in the test's setup. Assert the output holds `[REDACTED: <token>]` and
  neither form; `Options.Environment` holds the variable.
- `RunEnv_ValueNotInArgv`: in-process on every platform, `RecordingPty.Argv` holds no value and `Options.Environment`
  holds it; on Linux also end-to-end, a script that checks `/proc/$$/cmdline` for `$X` itself and prints only
  value-free markers (`IN-ARGV`/`NOT-IN-ARGV`, then `${X:+set}`), because a value in argv would show up masked, not
  raw. Assert `NOT-IN-ARGV` and `set`.
- `RunEnv_OnlyEnvTokens_NoArgvTokens_Runs` ("no tokens" isn't raised); `RunEnv_EqualsForm_Works` (`--env=X={{s}}`);
  `RunEnv_PreviousToken_Works`; `RunEnv_WithFileToken_Works`; `RunEnv_DecryptsOnlyWhatIsUsed` (the `ValueDecrypted`
  seam, as in `RunMinimumDecryptionTests`); `RunEnv_Verbose_ListsNamesNotValues`.
- Refusals before unlock, each on a machine with **no vault** (no `init`), so a check after `LoadConfig` would give the
  not-initialised error instead; assert the exact refusal and `Starts == 0`: a literal value, two tokens in one value, a
  `{{@file}}` value, `{{x:bogus}}`, a bad name, a 65-character name, a name given twice (also `X` and `x`), 65 pairs,
  `PATH`, `Path`, `LD_PRELOAD`, `BASH_ENV`, `GIT_SSH_COMMAND`, `DYLD_INSERT_LIBRARIES`, `PATHEXT`, `--env` with no `=`,
  `--env` as the last argument; and `run --env X={{s}} -- env` (the program `env` stays refused).
- Refusals after unlock, nothing started and no folder written: an unknown secret (today's "Secret '…' not found"),
  a missing previous value, a NUL-containing value (the env-worded message).
- Help scan: `run --env X={{s}} --help` prints `run`'s usage, exit 0, nothing unlocked; `run --env X={{s}} -v cmd {{s}}`
  gets the global-flag refusal; `run -- --help {{s}}` prints no usage and starts `--help`.
- `RunEnv_AfterTheCommand_IsTheCommandsArgument` (`tswap run cmd --env X={{s}}` passes `--env` to `cmd`, substituted
  as today).
- Broker: its existing env-rule tests stay green unchanged after the move.

Break-it-once: (1) pass the value in argv instead of the environment; `RunEnv_ValueNotInArgv` fails (both forms).
(2) Skip `Redact` for env values; `RunEnv_SetsTheVariable_ValueMaskedInOutput` fails (the unpadded base64 shows).
(3) Drop the `LD_*` rule from the shared place; the `LD_PRELOAD` refusal test and the broker's
`ABadEnvEntry_IsRefused` `LD_` row fail. (4) Compare names ordinally in `run`; the `Path` refusal test fails.

## Task 2: the agent rule and the docs

- `run`'s `HelpUsage` becomes `run [--env NAME={{name}}]... [--] <cmd> [args...]` and its `Description` mentions
  `--env`; the bare-`run` usage error keeps today's text (`CommandArgumentErrorTests` stays unchanged). **Sanctioned
  assertion change:** `HelpTests.RunHelp_DirectlyAfterRun_PrintsUsage` (`Contains("run <cmd> [args...]")`, :153) and
  `RunChildCommandHelp_GoesToTheChild` (`DoesNotContain`, :171) pin the old usage line, which this brief changes; both
  take the new string (the second would otherwise pass vacuously). Regenerate the command reference
  (`TSWAP_REGENERATE_DOCS=1`, `CommandReferenceTests.CommandReferenceIsCurrent`).
- `Prompt.cs`: a new section at the end, "## Passing secrets to commands:", saying, in order of preference: when the
  tool takes a **config file** that can carry the secret on a `# tswap:` line (Helm values, a YAML/JSON/INI config),
  `{{@file}}` (only the private copy's path is in argv); `--env VAR={{name}}` for a tool that reads its secret from an
  environment variable (example: `%CMD% run --env PGPASSWORD={{db-pw}} -- psql -h db -U app`; a literal is refused, set
  non-secret variables in the shell); a `{{name}}` in an argument only when the tool offers neither. No stdin and no raw
  password-file option: `run` can't feed stdin, and a `{{@file}}` copy is never the bare secret (#165). And: on a shared
  machine argv is readable by every local user while the command runs; the environment only by the same user and root.
  Pin it with a `PromptTests` test (the section exists and names `--env` and `{{@file}}`); existing prompt tests stay
  green (they slice by heading; don't mention `apply` without `sudo`, the sweep checks every line). `prompt` and
  `prompt-hash` output change: say so in the commit message.
- `docs/security-model.md`, "Secrets in process memory": the three forms and who can read each, per platform. Linux:
  argv every local user without `hidepid`, environment the same user and root; macOS and Windows as RedactingPty
  1.2.0's README says (Windows: whoever can open the child process); a `{{@file}}` copy the same user, deleted when the
  command ends (keep the existing SIGKILL/power-loss caveat). None of them hides a value from the agent's own user.
- `docs/commands.md`: `run`'s usage and description (regenerated); one paragraph in the hand-written part on `--env`:
  a literal is refused (set it in the shell), the refused names (they knowingly include harmless ones such as
  `NODE_ENV`, `JAVA_HOME`, `XDG_*`: set those in the shell too), and the `hidepid` note (recommend
  `hidepid=invisible,gid=<group>` on multi-user machines; the broker's vault user needs the group, see
  `docs/broker-threat-model.md`, ~:186).
- README: one line in the agent section pointing at `--env`.

## Out of scope

Literal values in `--env`, removing inherited variables, `run --env` for `{{@file}}` paths (a file path isn't a
secret), raw password files (#165), changing what the broker allows, `hidepid` itself (homelab#24).
