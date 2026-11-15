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

T21 (short-value matching, #314) runs at the same time in another worktree. It owns `SecretMatcher.Select`,
`FingerprintScanner`, `FingerprintStreamMatcher`, `Redaction.cs`, `RunCommand.cs`'s replacement list and the
value warnings in `create`/`ingest`/`add`/`rotate`. **T20 does not edit those**; T20 owns `Apply.cs`,
`ToCommentProcessor.cs`, `SecretMatcher.ToComment`/`SelectToComment`, `Check.cs` and `CheckCommand.cs`. Docs: T20
edits only the sections named in task 5.

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

`Apply.EscapeForQuote(value, "\"")`, in this order: `\` → `\\`, `"` → `\"`, LF → `\n`, CR → `\r`, TAB → `\t`, every
other character below U+0020 and U+007F → `\uXXXX` (four upper-case hex digits). Both YAML double-quoted scalars and
JSON strings decode exactly these escapes. Nothing else changes for values without control characters: every
existing `ApplyTests` and `RunFileTokenTests` expectation stays as it is (none has a control character).

The written forms `ApplySecretsReporting` returns are the escaped strings, as now; `run` already redacts written
forms (`RunCommand.cs:99-104`), so the escaped form of a multi-line value in a command's output is masked through
that path. Do not touch `Redaction.cs` (T21).

Tests (`ApplyTests`, new): for each of these values, fill `key: ""  # tswap: x`, nested `a:\n  key: ""  # tswap: x`,
and `"k": ""  # tswap: x` (JSON-ish), then parse the result **without a YAML library** (there is none and none is
added): assert the exact output line, and assert that a small test-only decoder for the double-quoted escapes above
(`\\ \" \n \r \t \uXXXX`) turns the quoted part back into the stored value byte for byte. Values: a 4-line PEM with a
trailing LF, the same without it, a CRLF PEM, `a\tb`, `quote " and back \ slash`, a value with U+0001 and U+007F.
One more test parses the JSON-ish line's quoted part with `System.Text.Json` (`JsonSerializer.Deserialize<string>`
on the quoted literal) and compares. Break-it-once: drop the LF replacement; the PEM test must fail.

`RunFileTokenTests.RunFileToken_MultiLineValueRedacted` (`:317`) must still pass unchanged; add one assertion that
the copy the child received contains no raw line break inside the quotes (the filled line is a single line).

## Task 2: single quotes become double quotes for values with control characters

A single-quoted YAML scalar can't carry a line break or a control character. When the value has any character
below U+0020 or U+007F and the line's quote is `'`, write the line with double quotes and the Task 1 escaping
(`key: ''  # tswap: x` → `key: "…\n…"  # tswap: x`, same separator whitespace as now). A value without such
characters keeps single quotes and the `''` escaping (`ApplyTests.SingleQuotes`, `EscapesSingleQuotes` unchanged).
Report the written form actually used.

Tests: the PEM through `key: ''`; the plain value through `key: ''` stays single-quoted. Break-it-once: keep the
single quote for control characters; the PEM test must fail.

## Task 3: refuse a value with control characters on a `KEY=` line

Lines whose separator is `=` (`KEY=""`, `KEY=''`, `KEY=`) are .env-style. Parsers disagree on escapes there (Docker's
`--env-file` reads the quotes literally), so tswap can't write a multi-line value correctly. Decide the separator
from the last non-space character of the prefix the regex captured (`:` or `=`). When that is `=` and the value has
a control character, throw a `TswapException` naming the line and the marker, never the value:

`Line N: '# tswap: NAME' is on a KEY= line, which can't carry a value with line breaks or control characters. Use a
YAML or JSON file, or pass the value with a {{NAME}} token.`

Nothing is written: `run … {{@file}}` already fills every file in memory before writing anything
(`RunCommand.cs:108-127`); add a test that proves no copy and no child happen. `apply` (sudo) prints nothing to
stdout and exits non-zero. A value without control characters on a `KEY=` line is filled as now.

Tests: refusal through `Apply.ApplySecretsReporting`, through `run … {{@file}}` (no child started, no copy left,
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
- It matches when one stored value (plain variant, any retained version, burned ones included as tocomment does
  today) equals the candidate **in full**, or equals it with its single trailing `\n` removed (a value ingested with
  `printf '%s'` has none). Use the same fingerprint matcher `tocomment` uses (`FingerprintRedaction.Matcher`): a hit
  counts only if its span is the whole candidate text. Nothing is decrypted.
- `--dry-run` shows the key line and every removed block line as removed, the new line as added, using the existing
  diff format; the "before" lines are redacted in one pass as today.

Tests (`RedactTests` or a new `ToCommentBlockScalarTests`): the PEM under `|`, `|-` and `|+` (stored with and without
a trailing LF where the chomping allows a match); a block whose content is a stored value plus one extra line (no
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
- A marker line is under `data:` when the nearest preceding line with less indentation is `data:` (only whitespace
  before it, nothing after it but whitespace or a comment).
- Text output: `  ⚠ NAME (line N) — under data: in a Secret, which expects base64; use stringData:`. JSON: a new
  status `data-not-base64`. It counts as a warning (exit 2), unless a marker is missing (exit 1).

Tests (`CheckTests` and `CommandTests` `Check_*`): the case from the issue (`paperless-ngx/step-ca-root-bundle`
shape); `stringData:` (no warning); `data:` in a `kind: ConfigMap` (no warning); two documents where only the second
is a Secret. Break-it-once: drop the `kind` check; the ConfigMap test must fail.

## Task 6: docs

- `docs/security-model.md` "Files with secrets" (around line 265-290): multi-line values are written escaped;
  `KEY=` lines refuse them.
- `docs/examples.md:76-110`: one sentence and a PEM example.
- `docs/commands.md`: the `check` warning and the `tocomment` block scalar; regenerate the generated block if a
  command `Description` changed (`TSWAP_REGENERATE_DOCS=1 dotnet test TswapTests --filter CommandReferenceIsCurrent`).
- `TswapCore/Prompt.cs` only if a sentence there becomes wrong (none is expected).

## Out of scope

YAML block-scalar output, a YAML or JSON parser dependency, a `:base64` marker suffix, a JSON placeholder form, any
change to redaction matching (T21), folded `>` scalars and indentation indicators in `tocomment`.
