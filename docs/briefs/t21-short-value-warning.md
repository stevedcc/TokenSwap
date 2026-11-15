# Brief T21: warn when a stored value is too short to hide

Issue: https://github.com/stevedcc/TokenSwap/issues/314 (the warning part only). Base: `origin/main` at 66042d2.
Read AGENTS.md and CLAUDE.md first, then `TswapCli/Commands/AddCommand.cs` (the trailing-whitespace warning, lines
38-45, is the model for this one), `CreateCommand.cs`, `IngestCommand.cs`, `RotateCommand.cs`,
`TswapCli/SecretRotation.cs`, `TswapCore/Validation.cs` and `docs/commands.md:106-113`.

One commit per task, test first, a break-it-once check per key test (name in the commit message which line you
reverted and which test failed), `./runtests.sh --unit` after each task, the full `./runtests.sh` at the end. No
hardware suites, `ykman`, `sudo`, real YubiKeys or `~/.config/tswap`: simulated services, `TSWAP_CONFIG_DIR` and temp
folders only. Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, explicit-path commits, no
push, merge or rebase; stop and report when the brief can't be built as written.

T20 (#315) runs at the same time and owns `Apply.cs`, `ToCommentProcessor.cs`, `SecretMatcher.ToComment`,
`Check.cs`, `CheckCommand.cs`. T21 edits none of them. In `docs/commands.md` T21 edits only the paragraph at
106-113 (T20 edits the `check` and `tocomment` text).

## Why

Redaction matches a stored value anywhere in the output, including inside longer words and numbers. A 3-digit SMTP
port stored as a "secret" turned up inside token counts in OpenCode's JSON (`65465` became `65[REDACTED: …]`, 66
times), which broke Chargehand's watcher; a username equal to a common word hid that word everywhere and had to be
burned; a flag whose value is `False` replaced Python's `False` in a test's output. Seven of the 13 entries still
burned in the owner's vault are short non-secrets burned this way.

**Owner decisions (2026-11-15):** the matching itself does not change now. Most short values are not secrets and
will move into non-secret fields (#311); whether short real secrets (PINs) then still need whole-token matching is
decided after that. For now: warn whenever a short value is stored, so it doesn't happen unnoticed.

## Task 1: one threshold, one warning text

In `TswapCore/Validation.cs`:

```csharp
public const int ShortValueLength = 8;
public static bool IsShortValue(string value) => value.Length < ShortValueLength;
```

`Length` is in UTF-16 code units, the same unit `create`'s length uses. The threshold lives only here.

A helper in the CLI (next to the trailing-whitespace text, or a small `ValueWarnings` class in `TswapCli`) writes
exactly this line to stderr:

`Warning: the value of 'NAME' is shorter than 8 characters. 'run' and 'redact' hide a value wherever it appears, also inside longer words and numbers, so a short value gets hidden in unrelated output and gives itself away. If it isn't a secret (a username, a port, a setting), it doesn't belong in tswap.`

The number in the text comes from `ShortValueLength`. The line names the secret and the reason only: never the
value, never its length (owner decision 5, as for the whitespace warning). It is a warning: the command succeeds,
the exit code and stdout don't change, nothing is refused.

## Task 2: the commands that store a value

Print the Task 1 line on stderr, after the command's success line, when the stored value is short:

| Command | When |
|---|---|
| `add` | the typed or piped value is short (also when the value was already stored, like the whitespace warning) |
| `ingest`, `ingest --rotate` | the value after `ReadBoundedStdin`'s trimming is short |
| `create NAME LEN`, `rotate NAME LEN` | `LEN < ShortValueLength` (the generated value is exactly that long) |
| `import` | not in scope (it restores a vault; no per-value warnings) |

Both warnings can appear for one `add` (whitespace first, then short).

Tests (command level, `FleetMachine`/simulated services, one test class): for each command, a value or length of 7
gives the line on stderr with the secret's name, exit 0, and the stored value intact; 8 gives no line; the value never
appears in stdout or stderr (assert on a distinctive 7-character value); `add` with a short value ending in a space
gives both lines in that order. A `create` test asserts the default length (32) prints no warning. Break-it-once:
change `<` to `<=` in `IsShortValue`; the length-8 test must fail.

## Task 3: docs and the agent prompt

- `docs/commands.md:106-113`: one paragraph after the whitespace one, saying which commands warn, the threshold, and
  why (link to [what `run` masks](security-model.md#what-run-masks)).
- `docs/security-model.md` "What `run` masks": one bullet among the limits: values are matched anywhere, including
  inside longer words and numbers; a short value is therefore hidden in unrelated output and gives itself away.
- `TswapCore/Prompt.cs`: in the key rules, one sentence: never store usernames, ports, hostnames or other
  non-secret settings as secrets; they get hidden wherever they appear and get burned for no reason. (This changes
  the prompt hash; `PromptTests` check determinism and format only.)
- Regenerate the generated command reference only if a command `Description` changed.

## Out of scope

Any change to matching or redaction (no whole-token rule, no minimum length for redaction), the broker and its
existing 16-byte log warning, `check`/`names` flagging existing short values, `import`, entropy checks (#9).
