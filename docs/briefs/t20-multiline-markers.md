# Brief T20: multi-line values survive `# tswap:` markers

Issue: https://github.com/stevedcc/TokenSwap/issues/315. Base: `origin/main` at 66042d2.
Read AGENTS.md and CLAUDE.md first, then `TswapCore/Apply.cs`, `TswapCore/ToCommentProcessor.cs`,
`TswapCore/SecretMatcher.cs` (`ToComment`, `SelectToComment`), `TswapCore/Check.cs`,
`TswapCli/Commands/CheckCommand.cs` and `TswapCli/Commands/RunCommand.cs` (lines 97-127, how written forms feed
redaction).

One commit per task, test first, a break-it-once check per key test (name in the commit message which line you
reverted and which test failed), `./runtests.sh --unit` after each task, the full `./runtests.sh` at the end. No
hardware suites, `ykman`, `sudo`, real YubiKeys or `~/.config/tswap`: simulated services, `TSWAP_CONFIG_DIR` and temp
folders only. Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, explicit-path commits, no
push, merge or rebase; stop and report when the brief can't be built as written.

Review history: round 1 by MiMo ("no") and DeepSeek ("yes") (`~/RiderProjects/tswap-wt/tools/t20-brief-r1-{mimo,deepseek}.md`);
this version folds in every finding.

**Parallel brief T21** (#314, a short-value warning only) runs at the same time in another worktree. It owns
`TswapCore/Validation.cs`, `AddCommand.cs`, `CreateCommand.cs`, `IngestCommand.cs`, `RotateCommand.cs`,
`SecretRotation.cs`, `AddWhitespaceWarningTests.cs` and a new test class of its own. **T20 edits none of those.** T20
owns `Apply.cs`, `ToCommentProcessor.cs`, `SecretMatcher.cs`, `ToCommentCommand.cs`, `Redact.cs`, `Check.cs`,
`CheckCommand.cs`, `CliJson.cs` (the check report) and its own new test classes (below). Shared files, by hunk: in
`docs/commands.md` T21 adds one paragraph after line 113, T20 edits only the redact/tocomment paragraph (83-89) and
nothing in the generated block unless a `Description` changes; in `docs/security-model.md` T20 edits only "Files
with secrets" (from line 265), T21 only "What `run` masks"; in `TswapCore/Prompt.cs` T20 edits only lines 39 and 41
(the `check` and `tocomment` one-liners), T21 only appends a rule at the end of "Key rules".

## Why

My vault holds 20 multi-line values (PEM keys and certificates, JSON documents, an SSH key). Filling one through a
marker corrupts it silently. `Apply.EscapeForQuote` (`Apply.cs:148-157`) escapes only `\` and `"` (or `'`), so a raw
line break goes between the quotes. YAML folds a raw line break inside a quoted scalar into a space; checked with
PyYAML on exactly what `Apply` writes for `key: ""  # tswap: x` and a 4-line PEM:

```
YAML double quotes -> '-----BEGIN KEY----- AAAA BBBB -----END KEY-----' | intact: False
YAML single quotes -> '-----BEGIN KEY----- AAAA BBBB -----END KEY-----' | intact: False
JSON               -> error: Invalid control character
```

Helm or kubectl then deploy a broken key without an error. And `tocomment` can't adopt a multi-line value from a
file: it matches line by line (`ToComment_ValueSplitAcrossMultipleLines_NoMatch`, `RedactTests.cs:501`), and its
continuation rule (`ToCommentProcessor.ContinuationLines`, `IsLikelyBase64`) fails on `-----BEGIN …-----` lines.

**Owner decision (2026-11-15): escaped strings only.** A multi-line value is written as an escaped double-quoted
string, never as a YAML block scalar (no new dependency; tswap is NativeAOT, `TswapCli.csproj:12`, and CI's AOT
publish step is the tripwire).

## Task 1: escape control characters in double quotes

`Apply.EscapeForQuote(value, "\"")`, in this order: `\` → `\\` first, then `"` → `\"`, LF → `\n`, CR → `\r`, TAB →
`\t`, and `\uXXXX` (four upper-case hex digits) for every other character below U+0020, for U+007F, and for the
three characters YAML also folds as line breaks inside double quotes: U+0085, U+2028, U+2029. Below, "a control
character" means any character in that set (LF, CR and TAB included). Both YAML double-quoted scalars and JSON
strings decode exactly these escapes. Values without a control character are written as today: every `ApplyTests`
expectation stays as it is. The multi-line `RunFileTokenTests` keep passing because their assertions are about
redaction (the raw value, or the written form, which stays in the redaction set), not about the file's bytes; run
them explicitly after this task.

The written forms `ApplySecretsReporting` returns are the escaped strings, as now; `run` already redacts written
forms (`RunCommand.cs:99-104`), so the escaped form of a multi-line value in a command's output is masked through
that path. Do not touch `Redaction.cs` (T21).

Tests (`ApplyTests`, new): for each of these values, fill `key: ""  # tswap: x`, nested `a:\n  key: ""  # tswap: x`,
and `"k": ""  # tswap: x` (JSON-ish), then parse the result **without a YAML library** (there is none and none is
added): assert the exact output line, and assert that a small test-only decoder for the double-quoted escapes above
(`\\ \" \n \r \t \uXXXX`) turns the quoted part back into the stored value byte for byte. Values: a 4-line PEM with a
trailing LF, the same without it, a CRLF PEM, `a\tb`, `quote " and back \ slash`, a literal backslash before a
letter (`C:\new\table`, which catches escaping the backslash after introducing `\n`), a multi-line JSON document
with quotes, a value with U+0001 and U+007F, and one with U+2028.
One more test parses the JSON-ish line's quoted part with `System.Text.Json` (`JsonSerializer.Deserialize<string>`
on the quoted literal) and compares. Break-it-once: drop the LF replacement; the PEM test must fail.

`RunFileTokenTests.RunFileToken_MultiLineValueRedacted` (`:317`) must still pass unchanged. In T20's own new test
class (not in `RunFileTokenTests.cs`), add a `run … {{@file}}` test whose child captures the copy it received (as
`RunFileTokenTests.cs:263` does) and assert the filled line is a single line holding the escaped form.

## Task 2: single quotes become double quotes for values with control characters

A single-quoted YAML scalar can't carry a line break or a control character. When the value has a control
character (Task 1's set) and the line's quote is `'`, write the line with double quotes and the Task 1 escaping
(`key: ''  # tswap: x` → `key: "…\n…"  # tswap: x`, same separator whitespace as now). A value without such
characters keeps single quotes and the `''` escaping (`ApplyTests.SingleQuotes`, `EscapesSingleQuotes` unchanged).
Report the written form actually used (assert it: the reported written form is the double-quote escaping).
Task 3's `KEY=` refusal is checked before this conversion, so `KEY=''` with a control character is refused, not
converted.

Tests: the PEM through `key: ''`; the plain value through `key: ''` stays single-quoted. Break-it-once: keep the
single quote for control characters; the PEM test must fail.

## Task 3: refuse a value with control characters on a `KEY=` line

Lines whose separator is `=` (`KEY=""`, `KEY=''`, `KEY=`) are .env-style. Parsers disagree on escapes there (Docker's
`--env-file` reads the quotes literally), so tswap can't write a multi-line value correctly. Decide the separator
from the last non-space character of the captured prefix (`:` or `=`), in **both** branches: `EmptyValueRegex`
(`KEY=""`, `KEY=''`, `Apply.cs:16,101`) and `UnquotedRegex` (`KEY=`, `Apply.cs:19,123-135`). When that is `=` and the value has
a control character, throw a `TswapException` naming the line and the marker, never the value:

`Line N: '# tswap: NAME' is on a KEY= line, which can't carry a value with line breaks or control characters. Use a
YAML file, or pass the value with a {{NAME}} token.`

Nothing is written: `run … {{@file}}` already fills every file in memory before writing anything
(`RunCommand.cs:108-127`); add a test that proves no copy and no child happen. `apply` (sudo) prints nothing to
stdout and exits non-zero. A value without control characters on a `KEY=` line is filled as now.

Tests (one per shape: `KEY=""`, `KEY=''`, `KEY=`): refusal through `Apply.ApplySecretsReporting` (the message names
the line and the marker and contains no part of the value), through `run … {{@file}}` (no child started, no copy left,
the message on stderr, the value nowhere in stdout or stderr), and through `apply` with `FleetMachine.Sudo = true`.
Break-it-once: remove the check; the `run` test must fail on the "no child started" assertion.

## Task 4: `tocomment` adopts a literal block scalar

A YAML literal block scalar holding a stored multi-line value:

```yaml
tls:
  key: |
    -----BEGIN PRIVATE KEY-----
    MIIB...
    -----END PRIVATE KEY-----
```

becomes `  key: ""  # tswap: NAME` (the key line's indentation and key kept, the block's lines removed).

Rules, exactly:
- The key line matches `^(\s*)([^#\s][^#]*?:)\s*\|([+-]?)\s*$` (a mapping key ending in `:`, then `|`, `|-` or `|+`,
  nothing else on the line; an indentation indicator such as `|2` is out of scope and left alone).
- The block is the following lines that are empty or indented deeper than the key line. It ends before the first
  non-empty line that isn't. The content indentation is the leading whitespace of the first non-empty block line.
- The candidate value is the block lines with that indentation removed, joined with `\n`, then chomped: `|` → exactly
  one trailing `\n`, `|-` → none, `|+` → all trailing line breaks kept.
- Building the candidate, exactly: split the file into lines (CRLF already normalised to LF); a final empty element
  from the file's last newline is not a block line. Each block line contributes its text with the content
  indentation removed, plus one `\n`. Then chomp: `|-` removes every trailing `\n`; `|` removes trailing `\n` until
  exactly one remains; `|+` keeps them all (blank block lines at the end each contributed one `\n`).
- The block ends at the first non-empty line indented **less than the content indentation**. If a non-empty line is
  indented deeper than the key but less than the content indentation, the block is not adopted and the file is left
  unchanged at that key (YAML would end the block there).
- It matches when one stored value's **plain** variant (any retained version, burned ones included as tocomment does
  today; never the base64 or whitespace-stripped variants) equals the candidate in full, or equals the candidate with
  its single trailing `\n` removed (a value ingested with `printf '%s'` has none): a hit counts only if its span is
  the whole candidate, or the whole candidate minus that trailing `\n`. Implement it as a self-contained helper in
  `SecretMatcher` that calls the index's `Scan` on the candidate directly (not `Entries`, `Select` or `Compare`).
  Nothing is decrypted.
- `--dry-run` (in `ToCommentCommand.cs`, owned by T20): the key line is shown as replaced (its "before" redacted as
  today), and every removed block line is shown **with its content suppressed**, exactly like a removed continuation
  line today (`- [removed block line]` / `+ (removed)`), never printed: a block line is a fragment of the secret and
  the redactor only masks complete occurrences.

Tests in a new `ToCommentBlockScalarTests.cs` (not in `RedactTests.cs`): the PEM under `|`, `|-` and `|+` (stored with
and without a trailing LF where the chomping allows a match); a `|+` block with two blank lines at its end; a block
with a line indented between the key and the content indentation (left unchanged); a `--dry-run` whose output
contains no line of the PEM (assert every PEM body line is absent from stdout and stderr); a block whose content is a stored value plus one extra line (no
match, file unchanged); a block at the end of the file without a final newline; two blocks in one file; a folded
`>` block and a `|2` block (left unchanged); CRLF files (normalised as today). Round trip: `tocomment` the file,
then fill it with `Apply`, then decode the quoted value (Task 1's test decoder): equal to the stored value.
Break-it-once: drop the chomping step; the `|` test must fail.

`ToComment_ValueSplitAcrossMultipleLines_NoMatch` stays: it covers a value split across lines that are not a block
scalar.

## Task 5: `check` warns about markers under `data:` in a Secret manifest

A Kubernetes Secret's `data:` holds base64; a marker there gets the raw value. `check` adds a warning when a marker
line is inside a `data:` mapping of a document that has `kind: Secret`:

- Documents are split on lines that are exactly `---`. Within one document, `kind: Secret` is a line matching
  `^kind:\s*Secret\s*$`.
- A marker line is under `data:` when, walking back and skipping blank lines and comment-only lines, the nearest
  preceding line with less indentation is `data:` (only whitespace before it; nothing after it but whitespace or a
  `#` comment).
- This is file content, so `Check.ScanFile` finds it (a flag on `MarkerRef`); `CheckMarkers` keeps deciding from the
  vault.
- One status per marker, in this precedence: `missing` > `data-not-base64` > `burned` > `ok`. Text output for the new
  one: `  ⚠ NAME (line N) — under data: in a Secret, which expects base64; use stringData:`. JSON: status
  `data-not-base64`, counted in the report's `warning` total. Exit: 1 if any marker is missing, else 2 if any warning
  (this one included), else 0.

Tests (`CheckTests` and `CommandTests` `Check_*`): the case from the issue (`paperless-ngx/step-ca-root-bundle`
shape); a blank line and a comment line between `data:` and the marker (still warned); `stringData:` (no warning);
`data:` in a `kind: ConfigMap` (no warning); two documents where only the second is a Secret; the JSON status and
counts, exit 2 when this is the only warning; a missing secret under `data:` (status `missing`, exit 1). Break-it-once: drop the `kind` check; the ConfigMap test must fail.

## Task 6: docs

- `docs/security-model.md` "Files with secrets" (around line 265-290): multi-line values are written escaped;
  `KEY=` lines refuse them.
- `docs/examples.md:76-110`: one sentence and a PEM example.
- `docs/commands.md`: only the redact/tocomment paragraph (83-89): the `tocomment` block scalar and the `check`
  warning; no new heading (a heading must not take a command's slug, `CommandReferenceCoversEveryCommand`).
  Regenerate the generated block only if a command `Description` changed
  (`TSWAP_REGENERATE_DOCS=1 dotnet test TswapTests --filter CommandReferenceIsCurrent`).
- `TswapCore/Prompt.cs` lines 39 and 41 only: `check` also exits 2 for a marker under `data:`; `tocomment` also adopts
  a literal block scalar.

## Out of scope

YAML block-scalar output, a YAML or JSON parser dependency, a `:base64` marker suffix, a JSON placeholder form, any
change to redaction matching (T21), folded `>` scalars and indentation indicators in `tocomment`.
