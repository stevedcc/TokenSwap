# Brief T21: warn when a stored value is too short to hide

Issue: https://github.com/stevedcc/TokenSwap/issues/314 (the warning part only). Base: `origin/main` at 66042d2.
Read AGENTS.md and CLAUDE.md first, then `TswapCli/Commands/AddCommand.cs` (the success line at 38 and the
trailing-whitespace warning at 39-45 are the model for this one), `CreateCommand.cs`, `IngestCommand.cs`,
`RotateCommand.cs`, `TswapCli/SecretRotation.cs`, `TswapCore/Validation.cs`, `TswapTests/AddWhitespaceWarningTests.cs`
and `docs/commands.md:108-113`.

One commit per task, test first, a break-it-once check per key test (name in the commit message which line you
reverted and which test failed), `./runtests.sh --unit` after each task, the full `./runtests.sh` at the end. No
hardware suites, `ykman`, `sudo`, real YubiKeys or `~/.config/tswap`: simulated services, `TSWAP_CONFIG_DIR` and temp
folders only. Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, explicit-path commits, no
push, merge or rebase; stop and report when the brief can't be built as written.

Review history: round 1 by MiMo and DeepSeek (`~/RiderProjects/tswap-wt/tools/t21-brief-r1-{mimo,deepseek}.md`), both
"no" on the same Critical (existing whitespace-warning tests break); this version folds in every finding.

**Parallel brief T20** (#315) runs at the same time in another worktree. T20 owns `Apply.cs`,
`ToCommentProcessor.cs`, `SecretMatcher.cs`, `ToCommentCommand.cs`, `Check.cs`, `CheckCommand.cs` and their tests.
T21 edits none of them. Shared docs, by section: in `docs/commands.md` T21 adds one paragraph after line 113 (the
whitespace paragraph) and nothing else; in `docs/security-model.md` T21 edits only "What `run` masks" (from line 209
to the end of its "Limits" list), T20 only "Files with secrets" (from line 265); in `TswapCore/Prompt.cs` T21 only
appends a rule at the end of "Key rules", T20 only edits lines 39 and 41 (the `check` and `tocomment` one-liners).

## Why

Redaction matches a stored value anywhere in the output, including inside longer words and numbers. A 3-digit SMTP
port stored as a "secret" turned up inside token counts in OpenCode's JSON (`65465` became `65[REDACTED: …]`, 66
times), which broke Chargehand's watcher; a username equal to a common word hid that word everywhere and had to be
burned; a flag whose value is `False` replaced Python's `False` in a test's output. Seven of the 13 entries still
burned in the owner's vault are short non-secrets burned this way.

**Owner decisions (2026-11-15):** the matching itself does not change now. Most short values are not secrets and
will move into non-secret fields (#311); whether short real secrets (PINs) then still need whole-token matching is
decided after that. For now: warn whenever a short value is newly stored, so it doesn't happen unnoticed.

## Task 1: one threshold, one warning text

In `TswapCore/Validation.cs`:

```csharp
public const int ShortValueLength = 8;
public static bool IsShortValue(string value) => value.Length < ShortValueLength;
```

`Length` is in UTF-16 code units, the same unit `create`'s length uses. The threshold lives only here, and **every
command checks the value it stores with `IsShortValue`** (for `create` and `rotate`, the generated value), never a
separate comparison on a length argument.

A helper in the CLI (next to the trailing-whitespace text, or a small `ValueWarnings` class in `TswapCli`) writes
exactly this line to stderr:

`Warning: the value of 'NAME' is shorter than 8 characters. 'run', 'redact' and 'tocomment' match a value wherever it appears, also inside longer words and numbers, so a short value gets hidden in unrelated output and gives itself away. If it isn't a secret (a username, a port, a setting), it doesn't belong in tswap.`

The number in the text comes from `ShortValueLength`. The line names the secret and the reason only: never the
value, never its length (owner decision 5, as for the whitespace warning). It is a warning: the command succeeds,
the exit code and stdout don't change, nothing is refused.

Tests (a theory next to the existing `EndsInWhitespace` theory in `AddWhitespaceWarningTests.cs:103-112`, or in
`ValidationTests.cs`): `IsShortValue` is true for lengths 1 and 7, false for 8 and 32, and false for four astral
characters (four emoji = 8 UTF-16 code units: the unit is code units, as documented). Break-it-once: change `<` to
`<=`; the length-8 case must fail.

## Task 2: the commands that store a new value

Print the Task 1 line on stderr, after the command's success line (and after the whitespace warning, where `add`
prints one), when the stored value is short:

| Command | Value checked |
|---|---|
| `add` | the typed or piped value (also when the value was already stored, like the whitespace warning) |
| `ingest`, `ingest --rotate` | the value after `ReadBoundedStdin`'s trimming |
| `create NAME [LEN]`, `rotate NAME [LEN]` | the generated value (exactly `LEN` long; `LEN` defaults to 32) |

Not warned (they write values that were already stored, and warned about, when they were first stored):
`restore`, `import`, `vault merge`, `migrate`.

**Existing tests that change (inputs only, the assertions stay exact).** `AddWhitespaceWarningTests` asserts exact
stderr with values shorter than 8, which would now also get the short warning. Change only their **inputs** to 8 or
more characters, keeping what each test is about, and keep every `Assert.Equal` as it is (they pin the whitespace
warning's one-line shape, owner decision 5):

| Test | Input now | Input after |
|---|---|---|
| `Add_TrailingSpace_Warns_StoresAsTyped` | `"value "` | `"value123 "` |
| `Add_WhitespaceOnly_Warns` | `"   "` | `"        "` (8 spaces) |
| `Add_TrailingTab_Warns` | `"v\t"` | `"value123\t"` |
| `Add_SameValueAgain_StillWarns` | `"value "` | `"value123 "` |
| `Add_NoTrailingWhitespace_NoWarning` | `"value"`, `"in ner"` | `"value123"`, `"in ner12"` (`" leading"` is already 8) |

Say in the commit message that these inputs changed because the new rule warns on short values, and that no
assertion changed. No other existing test asserts the stderr of these commands exactly (checked in review:
`WriteCommandDecryptionTests` filters stderr by record file name; `MetadataCommandTests` covers read commands only).

New tests (command level, `FleetMachine`/simulated services, one new test class):

- For `add`, `ingest`, `ingest --rotate`, `create`, `rotate`: a value (or `LEN`) of 7 gives exactly the Task 1 line
  on stderr naming the secret, exit 0, and the stored value intact (read back with `_m.Get`); 8 gives no such line.
- `create` and `rotate` without `LEN` (default 32) print no warning.
- No leak: for `add` and `ingest`, a distinctive 7-character value (e.g. `qz7Wk2p`) appears in neither stdout nor
  stderr; for `create` and `rotate`, read the generated value back with `_m.Get` and assert it appears in neither
  stream (as `RotateTests.cs:42` does).
- `add` with a short value ending in a space (`"abc "`) prints the whitespace line, then the short line, in that
  order, each exactly.

Break-it-once, per key test:
- `IsShortValue` `<` → `<=`: the length-8 "no warning" tests fail (all five commands, since all go through it).
- Swap the order of the two warning writes in `add`: the order test fails.
- Put the value into the warning text: the no-leak tests fail.
- Warn whenever `LEN <= 32` in place of `IsShortValue`: the default-32 test fails.

## Task 3: docs and the agent prompt

- `docs/commands.md`: one paragraph after line 113 (the whitespace paragraph), saying which commands warn, the
  threshold, and why (link to [what `run` masks](security-model.md#what-run-masks)).
- `docs/security-model.md` "What `run` masks": one bullet among the limits: values are matched anywhere, including
  inside longer words and numbers; a short value is therefore hidden in unrelated output and gives itself away.
- `TswapCore/Prompt.cs`: **append** one new numbered rule at the end of "Key rules", without changing the wording of
  any existing rule: never store usernames, ports, hostnames or other non-secret settings as secrets; they get
  hidden wherever they appear and get burned for no reason. (`PromptTests` slice on the section headings and pin
  some existing clauses verbatim; appending keeps them green. The prompt hash changes; no test pins a hash.)
- No command `Description` changes, so the generated command reference is untouched.

## Out of scope

Any change to matching or redaction (no whole-token rule, no minimum length for redaction), the broker and its
existing 16-byte log warning, `check`/`names` flagging existing short values, `restore`/`import`/`vault merge`/
`migrate`, entropy checks (#9).
