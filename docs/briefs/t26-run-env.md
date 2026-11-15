# Brief T26: `tswap run --env VAR={{name}}`, and the agent rule to keep values out of argv

Issue: https://github.com/stevedcc/TokenSwap/issues/71 (read its last comment, "Rewritten 2026-11-15": that is the
design; the older text describes a `bash -c` wrapper `run` no longer uses). Base: `origin/main` at f75be2b.
Read AGENTS.md and CLAUDE.md first, then `TswapCli/Commands/RunCommand.cs` (all of it), `TswapCore/Validation.cs`
(`ExtractTokens`, `SubstituteAllTokensInArgs`, `GetBlockedInvocation`, `HasPipeOrRedirect`),
`TswapCore/Broker/Templates/BrokerTemplatePolicy.cs` (the env rules at :186-230 and :355-370), `TswapCore/Prompt.cs`,
`docs/security-model.md` (the "Secrets in process memory" row, ~:132) and `docs/BROKER.md` ("Secrets reach the child
through env or a read-only file only", ~:623).

**Dependency:** RedactingPty **1.2.0** (released 2026-11-15, stevedcc/RedactingPty PR #11) adds
`RedactionOptions.Environment` (`IReadOnlyDictionary<string,string>?`): variables set for the child only, built before
the fork, never in its argv; output redaction still applies. Bump `TswapCli/TswapCli.csproj` from 1.1.0 to 1.2.0 in
Task 1 (check the package is on nuget.org first; if `dotnet restore` can't find it, stop and report).

One commit per task, test first, a break-it-once check per key test (name in the commit message which line you
reverted and which test failed), `./runtests.sh --unit` after each task, the full `./runtests.sh` at the end (run it
locally). No hardware suites, `ykman`, `sudo`, real YubiKeys or `~/.config/tswap`: simulated services,
`TSWAP_CONFIG_DIR` and temp folders only. Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`,
explicit-path commits, no push, merge or rebase; stop and report when the brief can't be built as written. Never change
an existing test's assertion.

**Parallel work:** the #311 fields branch adds one check in `RunCommand.Execute` (a refusal of `{{NAME.FIELD}}`
tokens, near the existing `ThrowIfUnknownTokenSuffix` call), a "Fields" section after "Commands you SHOULD use" and four
rules at the end of "Key rules" in `Prompt.cs`, and regenerates the command reference. T26 keeps to its own places:
option parsing at the top of `Execute`, its own section at the **end** of `Prompt.cs` (after "Keeping secrets out of
config files"), and `run`'s `HelpUsage`/`Description` (regenerate the reference; whichever branch merges later
regenerates again).

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

## Task 1: `run --env`

Syntax: `tswap run [--env NAME=VALUE]... [--] <cmd> [args...]`.

- Leading `--env NAME=VALUE` pairs (also `--env=NAME=VALUE`) are taken before the command; an optional `--` ends the
  options; the first other argument is the command. `--env` after the command is part of the command's argv, as today.
- `NAME`: `^[A-Za-z_][A-Za-z0-9_]*$`. `VALUE`: **exactly one token**, `{{name}}` or `{{name:previous}}` (a literal is
  refused: a literal isn't a secret and belongs in the command; the agent can write `env`-free literals into the
  command itself). Refused names, with the broker's rules and messages style: `PATH`, `LC_ALL`, `PWD`, `LD_*`, and every
  name in `BrokerTemplatePolicy`'s code-running list and prefixes (`BASH_ENV`, `GIT_SSH_COMMAND`, `PAGER`, `HOME`, …).
  Move those rules into one shared place in `TswapCore` (for example `ChildEnvironmentRules`) that both the broker and
  `run` call; the broker's behaviour and its existing tests stay exactly as they are (that refactor is a separate
  commit inside Task 1, behaviour-neutral, with the broker tests as its guard). A name given twice is refused.
- Every refusal happens before the vault is unlocked and before anything starts.
- The tokens in `--env` values count as `run`'s tokens: "no tokens found" is not raised when the only token is in an
  `--env` value; each is resolved once with the others (`view.ResolveToken`), decrypting only what is used.
- The command is checked exactly as today (blocklist, inline code, pipes/redirects, `{{@file}}` rules) on its own
  words; `env`/`printenv`/`set` as the program stay refused (they would print the environment).
- The child gets the variables through `RedactionOptions.Environment`; tswap's own environment is never changed.
- Each `--env` value is masked in the output exactly like a `{{name}}` in argv today (it is a secret value: add it to
  the replacements / matcher the same way).
- `--verbose` lists the variable names set, never values.

Tests (`RunEnvTests`, `FleetMachine` and the simulated services; a child that prints its environment variable, via a
small test script or the existing test helpers that `run` tests use):
- `RunEnv_SetsTheVariable_ValueMaskedInOutput` (the child prints `$VAR`: stdout shows the mask, never the value).
- `RunEnv_ValueNotInArgv`: on Linux, the child (a script that prints `/proc/self/cmdline` and then the variable's
  name only) shows no value in its argv; on other platforms, assert the argv the runner was given (through the existing
  runner seam) holds no value.
- `RunEnv_OnlyEnvTokens_NoArgvTokens_Runs` ("no tokens" isn't raised).
- `RunEnv_PreviousToken_Works`.
- Refusals, each before unlock and with nothing started: a literal value, two tokens in one value, a bad name, a name
  given twice, `PATH`, `LD_PRELOAD`, `BASH_ENV`, `GIT_SSH_COMMAND`, an unknown secret, `--env` with no `=`; and
  `run --env X={{s}} -- env` (the program `env` stays refused).
- `RunEnv_AfterTheCommand_IsTheCommandsArgument` (`tswap run cmd --env X={{s}}` passes `--env` to `cmd`, substituted
  as today).
- Broker: its existing env-rule tests stay green unchanged after the move.

Break-it-once: (1) pass the value in argv instead of the environment; `RunEnv_ValueNotInArgv` fails. (2) Skip the mask
for env values; `RunEnv_SetsTheVariable_ValueMaskedInOutput` fails. (3) Drop the `LD_*` rule from the shared place; the
`LD_PRELOAD` refusal test and the broker's own `LD_` test fail.

## Task 2: the agent rule and the docs

- `Prompt.cs`: a new section at the end, "## Passing secrets to commands:", saying, in order of preference: a tool's
  own file or stdin option fed by `{{@file}}` (only the private copy's path is in argv); `--env VAR={{name}}` for a tool
  that reads its secret from an environment variable (example: `%CMD% run --env PGPASSWORD={{db-pw}} -- psql -h db -U
  app`); a `{{name}}` in an argument only when the tool offers neither. And: on a shared machine argv is readable by
  every local user while the command runs; the environment only by the same user and root. Pin it with a `PromptTests`
  test (the section exists and names `--env` and `{{@file}}`); existing prompt tests stay green (they slice by heading).
- `docs/security-model.md`, "Secrets in process memory": the three forms and who can read each (argv: every local user
  on Linux without `hidepid`; environment: same user and root; a `{{@file}}` copy: same user, deleted when the command
  ends), and that none of them hides a value from the agent's own user.
- `docs/commands.md`: `run`'s usage and description (regenerate the reference after changing `HelpUsage`/`Description`);
  one paragraph in the hand-written part on `--env`, with the `hidepid` note (recommend `hidepid=invisible,gid=<group>`
  on multi-user machines; the broker's vault user needs the group, see `docs/broker-threat-model.md`).
- README: one line in the agent section pointing at `--env`.

## Out of scope

Literal values in `--env`, removing inherited variables, `run --env` for `{{@file}}` paths (a file path isn't a
secret), changing what the broker allows, `hidepid` itself (homelab#24).
