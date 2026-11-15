# Brief T22: `tocomment` never puts a marker for an encoded value inside a YAML block scalar

Issue: https://github.com/stevedcc/TokenSwap/issues/319. Base: `origin/main` at f75be2b (T20 and T21 merged).
Read AGENTS.md and CLAUDE.md first, then `TswapCore/SecretMatcher.cs` (`ToComment`, :43-79, `SelectToComment` and
`Entries`, which carry each hit's `VariantKind`), `TswapCore/ToCommentProcessor.cs` (`LiteralBlockAt`, :64-123),
`TswapCli/Commands/ToCommentCommand.cs` (all of it), `TswapTests/ToCommentBlockScalarTests.cs` (both classes),
`TswapTests/RedactTests.cs:368-393` (`ToComment_ShortSecretValue_DoesNotMatchInsideShellEmbeddedInYaml`),
`TswapTests/RedactEngineTests.cs:95-150` and `docs/commands.md:90-94`.

One commit per task, test first, a break-it-once check per key test (name in the commit message which line you
reverted and which test failed), `./runtests.sh --unit` after each task, the full `./runtests.sh` at the end. No
hardware suites, `ykman`, `sudo`, real YubiKeys or `~/.config/tswap`: simulated services, `TSWAP_CONFIG_DIR` and temp
folders only. Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, explicit-path commits, no
push, merge or rebase; stop and report when the brief can't be built as written. Never change an existing test's
assertion; no existing test should need it under this brief (see "Existing tests").

**Parallel work:** the #311 fields branch runs at the same time. It does not touch any file named here except
`docs/commands.md`, where it edits the sudo table and the generated command reference; T22 edits only the
hand-written paragraph at :90-94.

**Review history:** round 1 (MiMo, GLM-5.3: `~/RiderProjects/tswap-wt/tools/t22-brief-r1-*.md`) said "no". The
round-1 design left **every** line inside a block scalar alone; both reviewers found it would break
`ToComment_ShortSecretValue_DoesNotMatchInsideShellEmbeddedInYaml`, which pins a working case (a shell script
inside a Butane/Ignition `inline: |` block, where the marker's `#` is a shell comment and `run` fills the value back
correctly). The design is narrowed to #319's actual fault (below); MiMo's sequence-entry finding, both reviewers'
oracle, docs and class-name findings and the minors are folded in.

## Why

Found in the T20 code review. A `# tswap:` marker is always filled with the stored value's **plain** form. Inside a
YAML block scalar, `tocomment`'s line-by-line path still replaces a stored value's **encoded** form (base64,
base64url, or the whitespace-stripped form) with a marker:

```yaml
key: |
    <base64 of pem's value>
```

becomes

```yaml
key: |
    ""  # tswap: pem
```

A later `run … {{@file}}` fills that marker with pem's **plain** value where the file held its base64: a wrong value,
silently. Outside a block, the same replacement is visible to `check` (T20 warns about `data:` in a Secret); inside a
block nothing notices.

A **plain** value on a line inside a block keeps today's behaviour: the line becomes `… ""  # tswap: NAME`, and `run`
fills the plain value back, which is right for the shell scripts and configs people keep in blocks (the pinned Butane
case). Whether a `#` comment is valid in the block's language (JSON is the case where it isn't) is a known limit,
documented in Task 3, not changed here.

**Owner rule (warnings over hard blocks):** `tocomment` does not refuse the file. It leaves each such line exactly as
it is, replaces everything else as today, and warns about each line it left, naming the line number and the secret,
never the line's text or the value.

Reproduce first: on the base, add `BaseSixtyFourInABlock_LeftUnchanged_Reported` (Task 1) and watch it fail with the
rewritten line.

## Round 2 clarifications (MiMo and GLM-5.3 both "Ready to implement: yes"; these close their minors)

- **Which hits count (MiMo N6):** "a line holds an encoded hit" means an encoded hit the line path **would have
  replaced** (selection level, after `SelectToComment`'s boundary rules), not any scan hit. A content line whose only
  encoded occurrence is boundary-blocked is treated as today.
- **Node properties (GLM 1):** an anchor or tag is followed by whitespace before `|`/`>`; `key: &a|` and
  `key: !!binary|` are not block starts (YAML reads `a|` and `!!binary|` as the property).
- **The warning's NAME (MiMo N2)** is the `Token`, so `name:previous` for a previous version (a keyword, not a value).
  Pin one `name:previous` case in the command tests.
- **Output when only unreplaced lines exist (MiMo N3, GLM 3):** the warnings, then `File unchanged.`, in both the real
  run and `--dry-run` (no "(dry run) 0 line(s)…" line). The #319 command test asserts `File unchanged.` and that
  "No secrets found" does not appear.
- **No write without changes (MiMo N4):** when nothing was replaced the file is not written at all (as today's early
  return), so a CRLF file keeps its line ends. Add the #319 case with CRLF line ends to the command test: bytes on
  disk unchanged.
- **`RedactEngineTests` doc comment (MiMo N1):** update the class and corpus doc comments to name the engine-only
  differences now (T20's block adoption and T22's encoded lines in block content left alone); a comment only, the
  oracle and the corpus stay as they are.
- **More known gaps (MiMo N5, GLM 2), added to Out of scope:** `- - |` and `- - key: |` (nested sequence entries),
  `: |` (empty key); the rule over-marks a few YAML-valid non-block lines (a plain scalar `key:|`, a comment line
  between the node column and the content indent; safe: warned, not rewritten) and under-marks the gap between a
  sequence entry's dash and its key (broken YAML only; today's behaviour).
- `UnreplacedLine` lives beside `LineDiff` (implementer's choice of file).

## Task 1: find block-scalar content; leave encoded matches there alone

In `TswapCore/ToCommentProcessor.cs`, one function that says which lines of a file are block-scalar content:

```csharp
internal static bool[] BlockScalarContent(string[] lines)
```

- **A block start** is a line whose content, after its indentation, is
  - a mapping key (the `LiteralBlockKey` key shape), or
  - a sequence entry `- ` (one or more spaces after the dash), optionally followed by such a key,

  then optional node properties (an anchor `&name` and/or a tag `!…`, e.g. `key: !!binary |`, `key: &a >-`), then `|`
  or `>` with optional indicators (one chomping indicator `-`/`+` and/or one indentation digit 1-9, either order:
  `|-`, `|+`, `>2`, `|2-`, `>-1`), then optional spaces and an optional ` # comment`, then the end of the line.
  `key: "|"` is not a block start (quoted).
- **The node column** of a block start is the column of its key (for `key: |` and `- key: |`: skip the indentation,
  and for a sequence entry the dash and its spaces) or, for a bare `- |`, the dash's column.
- **Its content** is every following line that is blank, or whose indentation is **greater than the node column**, up
  to (not including) the first non-blank line indented at or less than the node column. (Example, MiMo round 1: in
  `- command: |` at indent 8 with `command` at column 10, a following `env:` at indent 10 is **not** content.)
- The result is the **union** of all blocks' content. A block start found inside content is content too, and neither
  ends the outer block nor starts a new region (one pass, outer block first).
- `lines` is the file split on LF (CRLF already normalised); a trailing empty element after the final LF is not a line
  of the file and is never content.

In `SecretMatcher.ToComment`, for a line marked as content:

- **Plain** hits keep today's behaviour exactly (the line path and `ContinuationLines` as now).
- **Encoded** hits (`VariantKind` other than `Plain`) are never replaced. If a line holds any encoded hit, the whole
  line is left unchanged (no partial rewrite) and each encoded hit is recorded as an **unreplaced** line:

  ```csharp
  public sealed record UnreplacedLine(int LineNumber, string Token);
  ```

  One record per `(LineNumber, Token)` (deduplicated), ordered by line number, then by token ordinally. `Token` is the
  token `tocomment` would have written (`name` or `name:previous`).
- `ContinuationLines` never removes a content line that holds an encoded hit.
- **Adoption (T20)** is unchanged, also for a block start nested inside another block's content: T20 adopts only a
  block whose whole content is a value's **plain** form, which `run` fills back correctly. (MiMo round 1 I1 asked to
  fence adoption inside content; with the narrowed rule a nested adoption is a plain fill, the case that works, so it
  stays. Say so in the commit message.)

**API shape (GLM round 1 M1):** keep every existing signature (`SecretMatcher.ToComment(string)`,
`Redact.ToComment(string, SecretMatcher)`, `Redact.ToComment(string, SecretsDb)`, all returning
`(string Content, IReadOnlyList<LineDiff> Changes)`) so no existing caller or test changes. Add one new method on each
of those three, `ToCommentReporting`, returning `(string Content, IReadOnlyList<LineDiff> Changes,
IReadOnlyList<UnreplacedLine> Unreplaced)`; the old ones call it and drop the third element. `UnreplacedLine` is
**not** a `LineDiff` subtype (the command's dry-run printer would print its text).

Tests (in `ToCommentBlockScalarTests`, the unit class, new tests only; `BaseSixtyFourOfTheValue_NotAdopted` stays as it
is). In every fixture the value sits **on a content line**, not as the whole block:

- `BaseSixtyFourInABlock_LeftUnchanged_Reported`: the #319 file; content equals the input, no changes, one unreplaced
  line (line 2, token `pem`).
- `PlainValueInAScriptBlock_StillReplaced`: `script: |` then `  export TOKEN=<value>` then `next: 1`: the line is
  rewritten exactly as today (`  export TOKEN=""  # tswap: tok`), no unreplaced line. (The Butane test in
  `RedactTests` pins the same; this one names the rule.)
- `Base64InAScriptBlock_LineLeftUnchanged`: `script: |` then `  echo <base64 of value> | base64 -d` then a top-level
  `token: <value>` line: the script line unchanged and reported, the top-level line replaced as today, in the same run.
- `MixedLine_PlainAndEncoded_LeftWhole`: one content line holding a plain value and another value's base64: unchanged,
  one unreplaced record (the encoded one).
- `FoldedBlock_Encoded_LeftUnchanged` (`>` and `>-`), `SequenceEntryBlock_Encoded_LeftUnchanged` (`- |`),
  `IndentationIndicator_Encoded_LeftUnchanged` (`|2`), `BlockStartWithComment_Encoded_LeftUnchanged`
  (`key: | # note`), `TaggedBlock_Encoded_LeftUnchanged` (`key: !!binary |`, the base64 case that matters most).
- `CompactSequenceEntry_SiblingKeyNotContent`: `- command: |` + a content line + a sibling `env:`/`token: <base64 of
  value>` at the key's column: the sibling's value is **replaced** as today (it is not block content).
- `QuotedPipe_NotABlock`: `key: "|"` then an indented `<base64>` line: today's output exactly (not content; don't
  add multi-line quoted-scalar handling).
- `BlockEndsAtNodeColumn`: an encoded value on the first line after the block, indented as the key: replaced.
- `TwoValuesOnOneContentLine_TwoRecords` and `SameValueTwiceOnALine_OneRecord`.
- A theory over `BlockScalarContent`: blank lines inside count as content; the block ends at the first non-blank line
  at or below the node column; a blank line indented less does not end it; a nested block start is content; the
  trailing empty element is not content.

Break-it-once: (1) skip the content check; `BaseSixtyFourInABlock_…` and `Base64InAScriptBlock_…` fail. (2) Use the
line's indentation instead of the node column; `CompactSequenceEntry_SiblingKeyNotContent` fails. (3) Treat only `|`
as a block start; `FoldedBlock_Encoded_LeftUnchanged` fails.

**Existing tests (verify, don't edit):** `RedactTests.ToComment_ShortSecretValue_DoesNotMatchInsideShellEmbeddedInYaml`
stays green unchanged (a plain hit in a block). `RedactEngineTests.Engine_MatchesOracle_OnRandomCorpus` compares the
engine with the frozen `PlaintextRedactOracle`, which is never edited: the corpus can in principle generate a
`key: |+` line followed by a deeper line holding an encoded form. Expected: the fixed seed produces none, and the test
stays green (check it in the Task 1 `--unit` run). If it fails, stop and report the round and the lines; do not edit
the oracle, the corpus or the seed.

## Task 2: say so in `tocomment`'s output

`ToCommentCommand` switches to `ToCommentReporting`. For each unreplaced line, on stderr, after the change listing and
before the summary line, in the order above:

`Warning: line N holds an encoded form (base64 or similar) of the value of 'NAME' inside a YAML block scalar. A '# tswap:' marker is filled with the plain value, so it was not replaced: move the value out of the block by hand, or keep the block as a whole secret.`

- Never the line's text, never the value or its encoded form, in dry run or real run, on either stream.
- Only unreplaced lines, no changes: print the warnings, then `File unchanged.` (not "No secrets found."); exit 0 (a
  warning, not a refusal). Both: the summary counts only changed lines, as today. Neither: today's
  `No secrets found. File unchanged.`, exactly (pin it in a test: nothing pins it today).
- `--dry-run` prints the same warnings.

Tests: add them to the **existing** `ToCommentBlockScalarCommandTests` class (in `ToCommentBlockScalarTests.cs`; a new
class of that name would not compile): the #319 file with and without `--dry-run`: the exact warning on stderr, exit
0, the file on disk byte for byte unchanged; no leak: the value, its base64 form and the original line's text appear in
neither stdout nor stderr, for both modes; one unreplaced and one replaced line in one file: the replaced one written,
the summary says 1 line, the warning printed; a file with no secrets: `No secrets found. File unchanged.`

Break-it-once: (1) add the line's text to the warning; the no-leak test fails. (2) Return 1 when a line was left; the
exit-0 test fails.

## Task 3: docs

- `docs/commands.md`, the hand-written paragraph at :90-94 only (the `### tocomment` heading at :237 is inside the
  generated command reference, which `CommandReferenceIsCurrent` pins; don't touch it): after the adoption sentence,
  add that inside a block scalar a line holding an **encoded** form of a value (base64 and similar) is left as it is,
  with a warning naming the line and the secret, because a marker is filled with the plain value; and that a plain
  value inside a block is still replaced by a marker whose `#` becomes part of the block's text, which suits shell
  scripts and YAML but not JSON.
- No command `Description` changes, no `Prompt.cs` change (the agent sees the warning). Release notes are written at
  release time.

## Out of scope

Encoded matches outside block scalars (`check`'s `data:` warning covers the common case), markers that fill an encoded
form, adopting a block whose content is a value's base64, keys containing `#` or explicit `? key` entries as block
starts (known gaps: they keep today's behaviour), `redact` (unaffected), JSON or TOML multi-line strings.
