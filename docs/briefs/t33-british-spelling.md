# Brief T33: British spelling throughout (#254)

Issue: https://github.com/stevedcc/TokenSwap/issues/254 (owner decision 2026-11-05: tswap uses British English).
Base: `origin/main` after T29 (#342) and T30 (#344) have merged; the controller merges main into `brief/t33` before
you start. Read AGENTS.md and CLAUDE.md first, then `TswapCli/Commands/SlotCommand.cs` (`Execute`'s sub-command switch,
`Forms`, `Description`), `TswapCli/Commands/SlotEnroll.cs`, `TswapCore/Prompt.cs`, `TswapTests/Docs/CommandReference.cs`
and `CommandReferenceTests.cs` (how `docs/commands.md` is generated and checked), and `TswapTests/SlotEnrollTests.cs`.

One commit per task, test first, a break-it-once check per key test (name in the commit message which line you
reverted and which test failed), `./runtests.sh --unit` after each task, the full `./runtests.sh` at the end (run it
locally). No hardware suites, `ykman`, `sudo`, real YubiKeys or `~/.config/tswap`. Commits end with
`Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, explicit-path commits (renamed files: `git mv`, then list
both paths), no push, merge or rebase; stop and report when the brief can't be built as written.

**Changed test inputs, sanctioned.** Tests that assert a printed string containing a US form change with it (owner
decision, the issue's own words: "an input change by owner decision, not an assertion weakened"). Say so in each
commit message and list those tests in the report. Known ones, all sanctioned the same way:
`CommandReferenceTests.Subcommands_TokenisesBothUsageShapes` (its expected list holds `"enroll"`, which becomes
`"enrol"`), `CommandReferenceTests.SudoTableDrive` (its `results["slot enroll"]` key and its
`g.Run("", "slot", "enroll", "--via", ...)` call), `SlotEnrollTests.UsageErrors` (the input rows and the
`Usage: tswap slot enroll ...` text), and the `SlotEnrollTests` message assertions that quote the command
(`slot enroll needs a terminal here...`, `'tswap slot enroll ... --fresh'`, `Running 'slot enroll' again...`). Any other
changed assertion must be a printed string whose only change is a respelling; anything else is not sanctioned.
Also sanctioned:
- every test invocation of the command (`SlotEnrollTests`' `Enroll`/`EnrollOnTerminal` helpers, which pass
  `["slot", "enroll", ...]`, and its direct calls) renames with it, apart from the synonym test;
- the simulated hardware seam's call name: `SimulatedHardwareService` reports `nameof(Enroll)` to its `CallObserver`,
  so renaming `Enroll` changes the observed `"Enroll"` to `"Enrol"` in `SecureEnclaveOwnerScopeTests` (lines 174, 186,
  199, 234 and 481 at bdda149) and `GuidedInitTests` (line 785). `"Unlock"` is unaffected.
List all of these in the report.

**Review history.** Round 1 (MiMo): C1 (the guard scanned its own allowlist and word list), I1 (the
confirmation check covered JSON members only), I2 (`docs/commands.md` is only partly generated), I3 (gaps in the
word list), M1-M5. All folded in. GLM's round-1 session ended without a review. Round 2 (GLM): I1 (the seam's
call-name assertions were not sanctioned) and M1-M8, all folded in.

**Parallel briefs.** None: T33 runs last, alone, because it touches most files.

## What changes and what stays

British forms: **enrol, enrols, enrolment, enrolments**. **enrolled** and **enrolling** are the same in both
spellings and stay. US forms to remove: **enroll, enrolls, enrollment, enrollments**, also inside identifiers
(`EnrollSerial`, `SlotEnrollment`, `IHardwareEnrollmentService`, `ExecuteEnroll`, `SlotEnrollTests`, ...). In short,
every `[Ee]nroll` not followed by `ed` or `ing`.

What changes:
- printed strings, help text and prompt text (`TswapCore/Prompt.cs`). This changes `tswap prompt-hash`, which is
  expected; say so in the report.
- `docs/commands.md`: the block between the `BEGIN GENERATED` / `END GENERATED` markers is regenerated
  (`TSWAP_REGENERATE_DOCS=1`, as `CommandReferenceTests` says), never hand-edited. The rest of the page is hand-written
  and edited as usual, including the "Which commands need sudo" table's `| slot enroll |` row, which becomes
  `slot enrol` together with `SudoTableDrive` (above). Then every other doc, README and the other top-level `.md` files,
  code comments, `evals/`, `contrib/`;
- identifiers and file names, renamed so a search finds one spelling. A mechanical change with no behaviour change:
  use the IDE-style rename (every reference), and `git mv` for the files: `TswapCli/Commands/SlotEnroll.cs`,
  `TswapCli/Fido2SlotEnrollment.cs`, `TswapCli/YubiKeySlotEnrollment.cs`, `TswapCore/Keyring/SlotEnrollmentFile.cs`,
  `TswapCore/Vault/IHardwareEnrollmentService.cs`, `TswapTests/HardwareEnrollmentSeamTests.cs`,
  `TswapTests/SlotEnrollTests.cs`, `TswapTests/SlotEnrollmentFileCodecTests.cs`, `TswapTests/SlotEnrollmentFileTests.cs`.

What stays:
- **Records:** `docs/briefs/**`, `docs/superpowers/**` and `docs/release-notes/**` (notes of released versions) are
  historical records. Do not edit them, and the guard below skips them. Links into them keep working, because their
  file names don't change.
- **Released anchors:** an anchor that a released version's docs had (`git show v0.3.0:<file>`), or that is listed in
  `TswapTests/Docs/old-*-anchors.txt`, keeps working. When its heading is respelt, put `<a id="<old-anchor>"></a>`
  right before the heading (an inline redirect; `DocLinkTests` accepts it). Those old ids, and the entries in the
  `old-*-anchors.txt` lists, are names released links own: they go in the allowlist with the reason
  "released anchor". Check every heading you respell against v0.3.0, not only the listed anchors. For example,
  `docs/design/refactoring-plan.md#where-shamir-does-earn-its-complexity-the-enrollment-authority` is in no list but
  was released.
- **On-disk and wire formats, and tswap's own interface names:** the controller and the brief reviewer found no
  JSON member, environment variable, flag, file or folder name spelt `enroll`. The enrolment folders are already
  `enrol/` and `enrol-staged/`, and the carried files are `request.json`, `approve.json` and `receipt.json`. The
  JSON contexts are source-generated, so their names come from members. Still, **triage every guard hit before
  respelling it**: a member of a type that is serialised (`TswapJsonContext`, `CliJsonContext`, `JsonPropertyName`),
  an environment variable name (`GetEnvironmentVariable` and the `CommandReference.EnvironmentVariablesRead` table),
  a `--flag` literal, or a file or folder name constant is part of tswap's interface. If you find one spelt `enroll`,
  stop and report it: renaming it would break files, scripts or older releases.
- **Names other software owns:** .NET and library APIs (`JsonSerializer.Serialize`, `OperationCanceledException`,
  `ConsoleColor`, `Initialize...` members you override or call, HTTP `Authorization`), the names of external tools'
  functions and options, and text quoted verbatim from another tool's output. These keep their spelling.

## Task 1: the enrol family, with a guard

**The guard (red first).** Add `TswapTests/Docs/SpellingTests.cs` with
`NoUsEnrolSpellings_InTrackedText`:
- it lists the repository's tracked files with `git ls-files`, the way the docs tests find files (reuse their helper
  if one exists);
- it reads the text files (`.cs`, `.md`, `.sh`, `.ps1`, `.yml`, `.yaml`, `.json`, `.json5`, `.txt`, `.te`, `.fc`,
  `.service`, `.socket`, `.xml`, `.csproj`, `.slnx`, `.c`, `.h`, `.swift`, `.py`, `.cil`, `.html`, and files with no extension, where a
  name starting with `.`, such as `.gitignore`, counts as having no extension), with line endings normalised to `\n`
  (read through `MarkdownLinks`' reader if it does this, so a CRLF checkout on Windows matches the same lines);
- it skips `docs/briefs/`, `docs/superpowers/`, `docs/release-notes/` and the allowlist file itself
  (`TswapTests/Docs/us-spellings-allowed.txt`, whose entries necessarily quote the US forms);
- it finds every match of `[Ee][Nn][Rr][Oo][Ll][Ll](?![Ee][Dd]|[Ii][Nn][Gg])`;
- it fails listing each hit as `path:line: text`, except the hits in an allowlist file
  `TswapTests/Docs/us-spellings-allowed.txt`. One entry per line: `path<TAB>exact line text<TAB>reason`, split on
  the first and the last tab (so the line text may itself contain tabs; the reason may not). Blank lines and lines
  starting with `#` are ignored. An entry matches when the path and the whole trimmed line text are equal, so an
  edited line falls out of the allowlist.
  A second test, `UsSpellingAllowlist_HasNoStaleEntries`, fails on an entry that matches no line any more.

Run it before the sweep and record the red count in the report: about 1,000 hits, the controller's rough count on
main at bdda149: about 700 hit lines in scope (about 1,000 counting the skipped record folders).

A respelt British identifier whose next word starts with `L` (`EnrolList`, `enrolLookup`) still matches the regex.
Don't respell it back to a US form. Choose another name or allowlist it with the reason "British spelling, camelCase
word break".

**The command word.** `slot enroll` was added after v0.3.0 (T27, unreleased), so it is renamed outright to
`slot enrol`: usage, `Forms`, `Description`, `Prompt.cs`, the docs and the hints that name it. Keep `enroll` as a
synonym that runs the same command, so someone typing the US form isn't refused. It is not shown in help,
`docs/commands.md` or the prompt. For the command word, its one literal in the dispatch and the test that pins it
are the only allowlist entries. Other entries are expected too: released anchors, external names such as
`ykpersonalize`, quoted tool errors (for example `Tpm2ArgvTests.cs`), Apple's `customize="never"` in
`contrib/packaging/macos/distribution.xml`, and camelCase breaks. Tests, written first:
- `SlotEnrol_UsSpelling_RunsTheSameCommand`: `slot enroll --via <user@host> --batch ...` behaves as `slot enrol`
  does. Reuse `SlotEnrollTests`' harness (renamed `SlotEnrolTests`), assert the same outcome as the existing batch
  happy-path test, and leave the host's vault with the new slot merged.
- `SlotHelp_NamesOnlyEnrol`: `tswap slot` usage and `tswap help slot` contain `slot enrol`, and no match of the
  guard's regex (so `enrolled` and `enrolling` may appear there).
- Break-it-once: delete the synonym arm, and `SlotEnrol_UsSpelling_RunsTheSameCommand` must fail. Put
  `slot enroll` back into `Forms`, and `SlotHelp_NamesOnlyEnrol` must fail.

**The sweep.** Rename and re-spell everything the guard finds, outside the "What stays" list. Regenerate
`docs/commands.md` the way `CommandReferenceTests` says. Check anchors: a heading respelt from `...enrollment...`
changes its anchor. Point every link in the repository at the new anchor, including the `docs/...#anchor` literals the
program prints (`ProgramText_DocPathsExist` checks those). Keep released anchors as "What stays" says.
`DocLinkTests` stays green.

Break-it-once for the guard: put `enrollment` back into one comment, and `NoUsEnrolSpellings_InTrackedText` must
fail naming that line.

## Task 2: the other US forms

Extend `SpellingTests` with `NoOtherUsSpellings_InProse`. It covers the same files and skips the same records, and
matches these **lowercase whole words only** (case-sensitive, a word boundary each side). PascalCase framework
identifiers such as `Serialize(` or `OperationCanceledException` never match, and a capitalised word at the start
of a sentence is out of scope. The test builds its patterns from stems and suffixes, so no US word appears whole in
`SpellingTests.cs`. Where one has to (a doc comment giving examples), allowlist that line. The test's doc comment
says that `-ize` is also a valid British (Oxford) spelling, and that the owner chose `-ise` for tswap. The words:
- `behavior`, `behaviors`, `behavioral`, `behaviorally`, `color`, `colors`, `colored`, `honor`, `favor`, `favorite`,
  `center`, `centered`, `gray`, `canceled`, `canceling`, `defense`, `offense`, `acknowledgment`, `acknowledgments`,
  `fulfill`, `fulfills`, `fulfillment`, `traveled`, `traveling`, `labeled`, `labeling`, `modeled`, `modeling`;
- the `-ize` family of `recogn`, `organ`, `author`, `final`, `normal`, `initial`, `summar`, `minim`, `maxim`,
  `custom`, `priorit`, `synchron`, `optim`, `serial`, `deserial`, `sanit`, `material`, `util`, `real`, `standard`,
  `special`, `general`, `local`, `visual`, `emphas`, `random`, `canonical`, `token`, `stabil`, `categor`,
  `character`, `modern`, `item`, `memor`, `legitim`, `penal`, `apolog`, `digit`, `notar`, `personal`, `unrecogn`,
  `reinitial`, `parallel`: each stem followed by `ize`, `izes`, `ized`, `izing`, `ization`,
  `izations`, `izer`, `izers`. Plus `analyze`, `analyzes`, `analyzed`, `analyzing`, `analyzer`, `analyzers`.

Lowercase hits in tswap's own code are respelt like prose. That includes identifiers such as a `color` parameter
across `IConsole` and its implementations, or `sanitized` and `normalized` locals. tswap's own PascalCase identifiers
are out of Task 2's reach and stay as they are. The British forms are `-our`, `centre`, `grey`, `cancelled/cancelling`, `-ise/-isation/-iser` and `analyse/-yser`.
Before the sweep, run a catch-all once, `\b[a-z]+iz(e|es|ed|ing|ation|ations|er|ers)\b` over the same files. Add
every further `-ize` stem it shows to the list (ignore `size`, `prize`, `seize`, `capsize` and the like, which have no
`-ise` form), and list the added stems in the report. Same allowlist file and same rules as Task 1. A lowercase hit that is a name other software owns, such as a JSON
field a library writes, a CLI option of another tool or a quoted error message, goes in the allowlist with its
reason. Never rename an external name. The red count goes in the report. Break-it-once: put `behavior` into one doc
line, and the test must fail naming it.

Do not touch other pairs: `license`/`licence`, `program`, `dialog`, `catalog`, `artifact`, `check`, `disk`. The
verb `license` is British too, and the rest are the accepted computing forms.

## Report

Write `t33-report.md` at the worktree's parent folder (`../t33-report.md`). It contains:
- the commits;
- the red counts;
- the renamed files and public identifiers, old → new;
- the allowlist entries with reasons;
- the tests whose asserted strings changed (sanctioned inputs);
- anchors renamed or kept;
- that `prompt-hash` changed;
- the full `./runtests.sh` summary lines;
- anything left undone.

## Out of scope

- behaviour changes of any kind apart from the `slot enrol` command word and its synonym;
- on-disk or wire format names;
- `docs/briefs/**`, `docs/superpowers/**` and `docs/release-notes/**`;
- spelling pairs not listed above;
- grammar or wording edits beyond the respelling.
