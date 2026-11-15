# Brief T22: `tocomment` never rewrites a line inside a YAML block scalar

Issue: https://github.com/stevedcc/TokenSwap/issues/319. Base: `origin/main` at f75be2b (T20 and T21 merged).
Read AGENTS.md and CLAUDE.md first, then `TswapCore/SecretMatcher.cs` (`ToComment`, :43-79, and `SelectToComment`),
`TswapCore/ToCommentProcessor.cs` (`LiteralBlockAt`, :64-123), `TswapCli/Commands/ToCommentCommand.cs` (all of it),
`TswapTests/ToCommentBlockScalarTests.cs` and `docs/commands.md:90-94`.

One commit per task, test first, a break-it-once check per key test (name in the commit message which line you
reverted and which test failed), `./runtests.sh --unit` after each task, the full `./runtests.sh` at the end. No
hardware suites, `ykman`, `sudo`, real YubiKeys or `~/.config/tswap`: simulated services, `TSWAP_CONFIG_DIR` and temp
folders only. Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, explicit-path commits, no
push, merge or rebase; stop and report when the brief can't be built as written. Never change an existing test's
assertion.

**Parallel work:** the #311 fields branch runs at the same time. It does not touch any file named here except
`docs/commands.md`, where it edits the sudo table and the generated command reference; T22 edits only the
`tocomment` paragraph at :90-94 and the `### tocomment` section.

## Why

Found in the T20 code review. `tocomment` adopts a literal block scalar whose content is exactly one stored value
(T20). Every other line still goes through the line-by-line path, also when it lies **inside** a block scalar. Inside
a block scalar a `#` is not a comment, it is text, so the rewrite changes the content:

```yaml
key: |
    <base64 of pem's value>
```

becomes

```yaml
key: |
    ""  # tswap: pem
```

The block's text is now literally `""  # tswap: pem`. A later `run … {{@file}}` fills that marker with pem's
**plain** value where the file held its base64: a wrong value, silently. The same happens to any secret on a line of
a script or config held in a block (`script: |` with `export TOKEN=…` in it): the block's text changes.

Reproduce first: on the base, tighten nothing, but add the Task 1 test and watch it fail with the rewritten line.

**Owner rule (warnings over hard blocks):** `tocomment` does not refuse the file. It leaves such lines exactly as they
are, replaces everything else as today, and warns about each line it left, naming the line number and the secret,
never the line's text or the value.

## Task 1: detect block-scalar content and leave it alone

In `TswapCore/ToCommentProcessor.cs`, one function that says which lines of a file are block-scalar content:

```csharp
internal static bool[] BlockScalarContent(string[] lines)
```

- A **block start** is a line whose content after its indentation is a mapping key (`key:`, the same key shape as
  `LiteralBlockKey`) **or** a sequence entry (`- `, optionally followed by a key), followed by `|` or `>` with optional
  indicators (`|-`, `|+`, `>-`, `>+`, `|2`, `|2-`, `>1+`, …: one chomping indicator and/or one indentation digit 1-9,
  either order), then optional spaces and an optional `# comment`, then the end of the line.
- Its **content** is every following line that is blank or indented deeper than the block start's own indentation,
  up to the first non-blank line indented the same or less. (This is wider than `LiteralBlockAt`'s rule on purpose:
  for *leaving lines alone*, erring on the side of "inside" is safe; for *adopting*, T20's stricter walk stays.)
- A `#` inside the start line's key or after the indicator is handled as YAML does (`key: | # note` is a block start;
  `key: "|"` is not).
- Lines of a block that `LiteralBlockAt` adopts are removed as today (T20); this function only matters for the lines
  the line path would otherwise rewrite.

In `SecretMatcher.ToComment`, a line marked as block-scalar content is never rewritten by the line path, and no
continuation-line removal (`ContinuationLines`) reaches into one. When such a line holds a stored value (any variant
`SelectToComment` would have taken), record it as an **unreplaced** line instead:

```csharp
public sealed record UnreplacedLine(int LineNumber, string Token);
```

Return it beside the changes. Pick the least invasive shape that keeps every existing caller and test compiling and
their assertions unchanged, for example a third tuple element on `SecretMatcher.ToComment`/`Redact.ToComment`
(`(string Content, IReadOnlyList<LineDiff> Changes, IReadOnlyList<UnreplacedLine> Unreplaced)`) with the existing
two-element overloads kept for the tests, or a separate method. **Do not** make it a `LineDiff` subtype: the
command's dry-run printer treats every `LineDiff` with a non-empty `After` as a line to print, and this line's text
holds a secret.

Tests (in `ToCommentBlockScalarTests.cs`, new tests only; `BaseSixtyFourOfTheValue_NotAdopted` stays as it is):

- `BaseSixtyFourInABlock_LeftUnchanged_Reported`: the #319 file; result equals the input (`AssertUnchanged`-style:
  content equal, no changes) and one unreplaced line (line 2, token `pem`).
- `ScriptBlockWithASecret_LeftUnchanged_Reported`: `script: |` then `  export TOKEN=<value>` then `next: 1`; the
  block unchanged, one unreplaced line; a `token: <value>` line **after** the block (outside it) is still replaced as
  today, in the same run.
- `FoldedBlock_LeftUnchanged` (`>` and `>-`), `SequenceEntryBlock_LeftUnchanged` (`- |`), `IndentationIndicator_
  LeftUnchanged` (`|2`), `BlockStartWithComment_LeftUnchanged` (`key: | # note`).
- `QuotedPipe_NotABlock`: `key: "|"` then an indented `<value>` line is not block content (YAML: that indented line
  is a continuation of nothing, so today's behaviour applies; pin today's output exactly).
- `BlockEndsAtLessIndentedLine`: a secret on the first line after the block (indented as the key) is replaced.
- `AdoptedBlock_StillAdopted`: T20's PEM case is unaffected (same result as `Clip_PemBlockFollowedByABlankLine_Adopted`).
- A theory over `BlockScalarContent` itself with small inputs: blank lines inside count as content; the block ends
  at the first non-blank line indented the same or less; a line indented less but blank does not end it.

Break-it-once: (1) skip the block-content check in `ToComment`; `BaseSixtyFourInABlock_…` and `ScriptBlock…` fail.
(2) Treat only `|` as a block start; `FoldedBlock_LeftUnchanged` fails.

## Task 2: say so in `tocomment`'s output

In `ToCommentCommand`, for each unreplaced line, on stderr, after the change listing and before the summary line:

`Warning: line N holds the value of 'NAME' inside a YAML block scalar (key: | or key: >), where a '# tswap:' comment would become part of the text. Not replaced: move the value out of the block by hand, or put the whole block in its own secret.`

- `NAME` is the token as `tocomment` would have written it (`name` or `name:previous`).
- Never the line's text, never the value, in dry run or real run, on either stream.
- With unreplaced lines and no changes, don't print "No secrets found. File unchanged.": print the warnings, then
  `File unchanged.`; exit 0 (a warning, not a refusal; owner rule). With both, the summary counts only changed lines,
  as today.
- `--dry-run` prints the same warnings.

Tests (command level, `FleetMachine`, a new test class `ToCommentBlockScalarCommandTests` or the existing command test
class for `tocomment`): the #319 file with `--dry-run` and without: exact warning line on stderr, exit 0, file
unchanged on disk; no leak: the value, its base64 form and the original line's text appear in neither stdout nor
stderr; a file with one unreplaced and one replaced line: the replaced one is written, the summary says 1 line, the
warning is printed.

Break-it-once: (1) add the line's text to the warning; the no-leak test fails. (2) Return 1; the exit-0 test fails.

## Task 3: docs

- `docs/commands.md`, the paragraph at :90-94: one sentence after the adoption sentence: lines inside any other
  block scalar (`|` or `>`) are left as they are, with a warning naming the line and the secret, because a comment
  there would become part of the text.
- The `### tocomment` section: the same, in its own words, with the warning's first sentence.
- No command `Description` changes, so the generated command reference is untouched.

## Out of scope

Base64-variant markers (a marker that fills a value's base64 form), the `check` `data:` warning (T20), adopting a block
whose content is a value's base64, `redact` (it only masks output and is unaffected), JSON or TOML multi-line strings.
