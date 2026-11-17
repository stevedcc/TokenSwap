# Brief T40: British spelling follow-up: capitals, all caps, more word families (#352)

Issue: https://github.com/stevedcc/TokenSwap/issues/352 (left over from T33/#254, from both code reviews; milestone
0.3.1). Base: `origin/main` at 35edf93. Read AGENTS.md and CLAUDE.md first, then `docs/briefs/t33-british-spelling.md`
(the rules this brief extends: "What changes and what stays", the allowlist format, released anchors), and
`TswapTests/Docs/SpellingTests.cs`, `TswapTests/Docs/us-spellings-allowed.txt`, `TswapTests/Docs/MarkdownLinks.cs`
(`AllTracked`).

One commit per task, test first, a break-it-once check per key test (name in the commit message which line you
changed and which test failed), `./runtests.sh --unit` after each task, the full `./runtests.sh` at the end. No
hardware suites, `ykman`, `sudo`, real YubiKeys or `~/.config/tswap`. Commits end with
`Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, explicit-path commits, no push, merge or rebase; stop and
report when the brief can't be built as written.

**What the issue says is already done.** The init banners it quotes were respelt before this brief
(`TswapCli/Commands/InitCommand.cs` prints `Initialisation` and `INITIALISATION COMPLETE` at 35edf93). The rest is
open.

**No existing assertion changes.** Several tests assert that a US form is *absent* from output
(`Assert.DoesNotContain("Reinitialize?", stdout)` and the `"Initialization"` / `"INITIALIZATION"` checks in
`BannerAlignmentTests`, `GuidedInitTests`, `CommandTests`, `InitRecordVaultTests`). They guard earlier respellings;
leave them exactly as they are and allowlist each line (reason below). No other test's assertions or logic change:
`SpellingTests.cs` and the allowlist change, and comments in test files are respelt as part of the sweep (A3).

**Review history.** Round 1 (GLM, 480f902): ready; every count and line verified against 35edf93 (26 cased lines,
2 ALL-CAPS, 1 lowercase; zero false positives). Minors folded in as A1 (ALL-CAPS `Authoriz…` excluded too), A2 (own
identifiers in uncovered shapes), A3 (test-file comments are part of the sweep), A4 (`OtherUsWords`' comment named,
stems-and-suffixes clause kept, failure message extended), A5 (cased catch-all), A6 (Task 2 names the existing
scratch exemptions).

## Task 1: capitalised and ALL-CAPS forms, and the missing word families

### The guard (red first)

In `SpellingTests.cs`:

1. **Word families.** Change `OtherUsWords` so the `-or` and `-er` families use full suffix sets, and add the missing
   families. The list after the change (stems and suffixes; every `-ize` stem row stays as it is):
   - `behavi`: `or`, `ors`, `oral`, `orally` (unchanged)
   - `col`: `or`, `ors`, `ored`, `oring`
   - `hon`: `or`, `ors`, `ored`, `oring`
   - `fav`: `or`, `ors`, `ored`, `oring`, `orite`, `orites`
   - `neighb`: `or`, `ors`, `oring`, `orhood`, `orhoods`
   - `rum`: `or`, `ors`, `ored`
   - `endeav`: `or`, `ors`, `ored`, `oring`
   - `cent`: `er`, `ers`, `ered`, `ering`
   - `lit`: `er`, `ers`
   - `defen`: `se`, `ses`; `offen`: `se`, `ses`
   - `judg`: `ment`, `ments` (British `judgement`, `judgements`)
   - the other rows (`gr`, `cancel`, `acknowledg`, `fulfil`, `travel`, `label`, `model`, `analy`) unchanged.

   In `OtherUsWords`' doc comment (not the class comment), replace the first sentence's opening so it says the scope
   is deliberate, keeping its clause about stems and suffixes (A4): "Brief T33 task 2 and T40: the US forms tswap has
   used or is likely to use, not every US spelling; the list is deliberate and grows when a review finds a new one.
   The words are lowercase whole words (case-sensitive, a word boundary each side), built from stems and suffixes so
   that no US word appears whole in this file." Keep the rest, including the `-ize` sentence. Extend
   `NoOtherUsSpellings_InProse`' failure message with the new British forms (neighbour, rumour, endeavour, litre,
   judgement); its assertion is unchanged.

2. **Cased forms.** Add `internal static readonly Regex CasedUsForm`, built from the same `OtherUsWords` (so a family
   added later is guarded in all cases at once). For each word `w` it matches, as a whole word (`\b` each side,
   case-sensitive), the capitalised form (first letter upper, the rest as in `w`) and the ALL-CAPS form, with two
   exclusions:
   - **code, not prose:** not when the word directly follows a `.` (member access and namespaces:
     `JsonSerializer.Serialize`, `System.Text.Json.Serialization`) and not when it is directly followed by `(` or `<`
     (a call, a declaration, a generic: `Normalize(SecretRecord record)`, `Deserialize<T>`). Use a lookbehind
     `(?<!\.)` and a lookahead `(?![(<])`.
   - **`Authorization`:** the capitalised and the ALL-CAPS `Authoriz…` forms are not matched at all (A1). `Authorization` is the HTTP
     header name (RFC 9110), which other software owns, and tswap names it in code, docs and tests; the lowercase
     forms stay guarded. The doc comment says so.

   tswap's own PascalCase identifiers stay as they are, as in T33 (a member named `Normalize` is code; the
   exclusions above keep it out). The doc comment says: "Capitalised and ALL-CAPS forms (#352): a sentence start, a
   heading, a banner. Code is left alone: a word after a `.` or before `(` or `<`."

3. **Tests**, written first:
   - `NoUsSpellings_CapitalisedOrAllCaps`: the same files, records and allowlist as `NoOtherUsSpellings_InProse`
     (use `Offenders(CasedUsForm.IsMatch)`), with a failure message in the same shape naming the British forms.
   - `CasedUsForm_MatchesProseNotCode`, built from parts like `OtherUsForm_MatchesLowercaseWholeWordsOnly` so the file
     holds no US word whole. It asserts, at least:
     - matches: `"Serial" + "izes the config"`, `"✓ INITIAL" + "IZATION COMPLETE"`, `"### Code Organ" + "ization"`,
       `"Hon" + "ored here"`, `"NEIGHB" + "OR"`;
     - no match: `"JsonSerializer." + "Serial" + "ize(x)"`, `"System.Text.Json." + "Serial" + "ization;"`,
       `"Normal" + "ize(record)"`, `"Deserial" + "ize<T>"`, `"Author" + "ization: Bearer x"`,
       `"Proxy-Author" + "ization"`, `"AUTHORIZ" + "ATION"`, and the British forms `"Serialises, Initialisation, INITIALISATION, Honoured"`;
     - lowercase is not this regex's job: `"serial" + "izes"` does not match `CasedUsForm`.
   - Extend `OtherUsForm_MatchesLowercaseWholeWordsOnly` with matches for one new word of each added family
     (`"hon" + "ored"`, `"neighb" + "or"`, `"rum" + "or"`, `"endeav" + "or"`, `"lit" + "ers"`, `"defen" + "ses"`,
     `"judg" + "ment"`, `"col" + "oring"`, `"cent" + "ering"`). These are added asserts; the existing ones stay.

Run both guards before the sweep and record the red counts in the report. At 35edf93, measured by the controller
with an equivalent scan: about 25 cased hit lines outside the exclusions (the `Authoriz…` lines removed), 2 ALL-CAPS
lines (both `DoesNotContain` assertions), and 1 lowercase hit of the added families (`judgment` in
`docs/agent-integration.md`).

### The sweep

Respell every hit outside the "keeps its form" list below, with the right British form (`Serialises`, `Serialised`,
`Initialise`, `Unrecognised`, `Randomising`, `Organisation`, `Normalise`, `Sanitise`, `judgement`, ...). Known hits at
35edf93 that change (check each against the guard, the list is not exhaustive):
`.gitattributes:1` (comment), `AGENTS.md:272` (heading, see anchors), `TswapCli/Commands/GuidedInit.cs:99` (a comment
quoting the old prompt: respell to the current prompt text `Reinitialise?`), `TswapCore/Broker/BrokerPolicy.cs:120`,
`TswapCore/ExportCrypto.cs:92`, `TswapCore/Keyring/FilenameHasher.cs:15`, `TswapCore/Keyring/SlotEnrolmentFile.cs:128`
(`Serializes/deserialises`, the issue's example), `TswapCore/Models.cs:7, 30, 337`, `TswapTests/CommandTests.cs:1089`
(comment), `TswapTests/ValidationTests.cs:283` (comment), `docs/agent-integration.md` (`judgment`).

**Keeps its form** (allowlist, one entry per line, `path<TAB>exact line text<TAB>reason`):
- the `DoesNotContain` assertions of a US form named above: reason "asserts the US form is gone";
- Apple's tool output quoted verbatim: `source=Notarized Developer ID` (`contrib/packaging/package-pkg.sh` :104 and
  :105, `TswapTests/MacFakeTools.cs:286`, `TswapTests/MacPkgScriptTests.cs:331`) and pkgutil's `Notarization:` line
  (`TswapTests/MacPkgScriptTests.cs:52`): reason "Apple's tool output, quoted verbatim";
- the released anchor below: reason "released anchor";
- anything else the guard finds that is a name another tool owns, tswap's own identifier in a shape the exclusions
  don't cover (`nameof(...)`, a method group, a `cref`; out of scope as in T33), or text quoted from another tool:
  list it in the report with your reasoning and allowlist it only if it clearly is one of those, with the matching
  reason ("name another tool owns", "tswap identifier, out of scope", "quoted tool output"). Otherwise stop and report.
  Never rename an external name (A2).

**Catch-all, once, before the sweep (A5).** Run `\b[A-Z][a-z]+iz(e|es|ed|ing|ation|ations|er|ers)\b` and its ALL-CAPS
variant over the same files. Add any further stem it shows to `OtherUsWords` (ignore `Size`, `Prize`, `Seize` and words
the same in both spellings) and list the result, even "none", in the report. The brief reviewer found none at 35edf93.

**Anchors.** `AGENTS.md`'s heading `### Code Organization (TswapCli)` was released in v0.3.0
(`git show v0.3.0:AGENTS.md`), so respelling it changes a released anchor. Respell the heading and put
`<a id="code-organization-tswapcli"></a>` on the line right before it (the inline redirect T33 used; `DocLinkTests`
accepts it); allowlist that `<a id=...>` line as "released anchor". Check any other respelt heading against v0.3.0 the
same way. Point every link in the repository at the new anchor (at 35edf93 nothing links to it).

Break-it-once: put `Serial` + `izes` back into one doc comment, and `NoUsSpellings_CapitalisedOrAllCaps` must fail
naming that line; remove the `(?![(<])` lookahead, and `CasedUsForm_MatchesProseNotCode` must fail.

## Task 2: AGENTS.md says the guards also read untracked files

`MarkdownLinks.AllTracked()` and `AllMarkdown()` list files with `git ls-files --cached --others --exclude-standard`,
so the spelling guards and the doc-link guards also read untracked files that `.gitignore` doesn't exclude. A stray
local note (a report, a scratch file) can fail the unit suite. Add one paragraph to AGENTS.md, after the
"Sudo-refusal tests" paragraph:

> **Docs and spelling guards** (`TswapTests/Docs/`): the doc-link tests and the British-spelling tests
> (`SpellingTests`, allowlist `TswapTests/Docs/us-spellings-allowed.txt`) read every file git tracks *or would
> track*: untracked files that `.gitignore` doesn't exclude count too. A stray local note with a US spelling or a
> broken link fails the unit suite; keep such notes outside the repository or in an ignored path (the
> both guards already skip `wip-*.md` notes and build output).

No test for this task (documentation only); say so in the commit message.

## Report

Write `t40-report.md` at the worktree's parent folder (`../t40-report.md`). It contains: the commits; the red counts
(cased, ALL-CAPS, lowercase new families); every respelt line (path:line, old → new word); the allowlist entries added,
with reasons; anchors kept or renamed; the break-it-once results; the full `./runtests.sh` summary lines; anything left
undone or doubtful.

## Out of scope

- tswap's PascalCase identifiers (types, members), as in T33;
- `docs/briefs/**`, `docs/superpowers/**`, `docs/release-notes/**`;
- spelling pairs not listed here, and T33's "do not touch" pairs (`license`, `program`, `dialog`, `catalog`,
  `artifact`, `check`, `disk`);
- any behaviour change; any change to an existing test assertion;
- grammar or wording edits beyond the respelling.
