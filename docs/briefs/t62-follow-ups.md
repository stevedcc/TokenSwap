# Brief T62: small 0.3.3 follow-ups from T54, T55, T57, T59 and the Renovate pin (#425, #427, #429, #430, #432)

Milestone 0.3.3. Base: `origin/main` at dcc4c04 (this brief's branch, `brief/t62`, starts there). Read AGENTS.md and
CLAUDE.md first, then the five issues (`gh issue view <n> -R stevedcc/TokenSwap --comments`), and:
`TswapCore/Fingerprints/SecretVariants.cs` (from `IsCurrent`'s doc comment, `:116`, to the end);
`RecordVaultStore.PrepareV3` (`TswapCore/RecordVaultStore.cs:2056-2084`) and `MergeRecords` (`:1895-1936`);
`TswapTests/VaultReindexTests.cs:182-206`; `docs/security-model.md:765-772`; `TswapCore/MsysTarget.cs` (all);
`TswapTests/MsysQuotingTests.cs` (the class summary, `MsysSpellings`, the R1 tests); `docs/scripts.md:46-64`;
`docs/briefs/t55-git-bash-msys2-quoting.md:145-160` (amendment 16); `TswapTests/Build/DependencyPinningTests.cs`
(the summary, `:283-300`, `:380-624`); `.github/workflows/ci.yml:270-290` (the `lock-files` job);
`TswapTests/ReleasePackagingTests.cs:1794-1830` and `:1958-2060`; `TswapTests/SignWindowsScriptTests.cs` (the
summary, the fakes, `Sign_PollBadJson_IsNotRetried`); `contrib/packaging/sign-windows.sh:108-140`.

One commit per task, test first, break-it-once per key test (name in the commit message which line you changed and
which test failed), `./runtests.sh --unit` after each task, the full `./runtests.sh` at the end. No hardware suites,
`ykman`, `sudo`, real YubiKeys or `~/.config/tswap`. Commits end with
`Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, explicit-path commits, no push, merge or rebase; stop and
report when the brief can't be built as written. **No existing test's assertion changes except the two Task 4 names**
(`SignWindows_ReplacesTheArtifact`, `VerifyWindows_StepsInOrder`: #430 asks for exactly that change). **That change is
pending owner sanction, and Task 4 waits for it**: build Tasks 1, 2, 3 and 5 first, and start Task 4 only when the
controller passes on the owner's yes. Tasks 3 and 5 add assertions to existing tests and change none; if any other existing test
fails on an assertion, stop and list it.

**One task per issue; each commit closes its issue** (`Closes #n` in the message), so each task carries its own docs.
The tasks are independent: any order. **File ownership.** Parallel brief T58 (PR #433, unmerged) owns `RunCommand`,
`Validation`, `Apply`, `VaultView`, `RecordVaultStore`, `RotateCommand`, `NamesCommand`, `TswapCore/Prompt.cs`, the
csproj and lock files, `RecordWritesTests`, `EndToEndTests` and several docs; T60 and T61 will own the record store
and merge code. This brief changes none of their source files. The only shared file is `docs/security-model.md`:
T58 edits it at lines 179, 212, 230 and 383, Task 1 only at 765-772, so either merge order is a clean text merge.
Task 1's new tests drive `PrepareV3` and `vault merge` without changing them: if T60 or T61 lands first and changes
either, re-run Task 1's tests after that merge (expected order: T58, T62, then T60/T61, but nothing here depends on
it).

## Checked at dcc4c04: nothing is done yet, one part is dropped

| Item | State at dcc4c04 | Evidence |
|---|---|---|
| #425.1 `IsCurrent` doc | open | `SecretVariants.cs:116-135`: two `<summary>` blocks in a row above `LacksFormsOf` (the first is `IsCurrent`'s); `IsCurrent` (`:158`) has none |
| #425.2 G1 test | open | the only test of the clause is `Reindex_AVersionTwoSetWithoutItsFormEntries_IsRecomputed` (`VaultReindexTests.cs:188`), a reindex; no test calls `PrepareV3(..., recomputeOlderSets: false)` with a base-only set |
| #425.3 docs | open | `security-model.md:770` still says "recognises only the stored spelling" |
| #427 all parts | open | `MsysTarget.cs:144` calls `ChangesGlobOption` before `Any(GlobCharacter)`; `:183-191` is the cubic loop; `:171-179`, amendment 16 (`t55…md:152`) and `:160-161` as the issue quotes; `scripts.md:55-56` lists the spellings without "such as", `:58` is 143 characters; `MsysQuotingTests.cs:7-11` lists R1-R3; `MsysSpellings`' summary (`:132-137`) names amendment 14 only |
| #429 test parts | open | `DependencyPinningTests.cs:511-513` sums every row; `:558-560` matches `exit 1` anywhere after the `if`; `:290` has no `-S`/`--split-string` |
| #429 ruleset part | **dropped** | done by the owner: issue comment "lock-files is now a required status check in ruleset 27270067" |
| #430 | open | `ReleasePackagingTests.cs:1962-1963` and `:2040`, `:2042` match `@v4` verbatim (the issue's line numbers have moved) |
| #432 | open | `Sign_PollBadJson_IsNotRetried` (`SignWindowsScriptTests.cs:424-436`) has neither `Posted()` nor `AssertNoSecretsLeaked`; `ReleasePackagingTests.cs:1826` and `:1797` as the issue says |
| #426 | **not in this brief** | see "Out of scope" |

## What is wrong (evidence)

- **#425.** See the table. On item 3: .NET 11.0.100 with `DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1` returns
  `"Jos\u00e9".Normalize(FormD)` unchanged (length 4, checked by the brief writer), so such a machine computes no form
  variant itself. But `redact`, `tocomment`, `run`'s masking of the vault (`FingerprintStreamMatcher`,
  `RunCommand.cs:311`) and the field check scan the **stored** fingerprint sets, and a set an ICU machine wrote holds
  the NFC and NFD entries; only what it computes from a value (a set it writes, `run`'s own tokens through
  `Redaction.Variants`, the broker's `BrokerRedactor.ForSecret`) has the stored spelling alone. The doc says it
  "recognises only the stored spelling", which is too strong.
- **#427.** `WordChangesGlobOption` concatenates every run of pieces (`MsysTarget.cs:186-188`): O(k³) characters for k
  quotes, and `Refusal` runs it for any `MSYS` before it looks at the arguments (`:144`). The issue's proposed "walk
  forward and stop when the shape can't match" is still quadratic: in `-"-"-"…` every run is still a possible prefix.
  Parser-first (msys2-runtime branch `msys2-3.6.12`, 50c44b7c03c8, `winsup/cygwin/environ.cc`):
  - `strbrk` (`:141-177`) skips spaces and tabs. A token whose first `"` comes before its first space or tab is quoted:
    the opening `"` is removed, and the token ends at the next `"` not preceded by `\`. A `\"` inside is unescaped
    (`:163-168`), so a quoted token can span spaces. The text after the closing `"` starts the next token.
  - **With no closing `"`, `sep` is the string's NUL (`:162`) and `buf = sep + 1` (`:171`) points past the end of the
    copy, so the next call reads memory after the string.** What comes next is undefined, so the glob option may end
    up off.
  - `parse_options` (`:218-224`) strips at most one `no` or one `-` prefix, then splits at the first `=`, or else the
    first `:`.
  - The real rule is narrower than the model, so the model over-refuses. So "every run is a token `strbrk` can
    produce" (the code comment, amendment 16) is false. What is true: every token that changes the option begins
    with a run of the model that changes it too. That run is the part up to the separator; it lies in one
    space-separated word, starts at the word's start or after a `"`, and ends at a `"` or the word's end, or reaches
    the separator.
  - R4's numbers come from `glob.cc`: `MAXPATHLEN` 8192 (`:102`), `bufend = bufnext + MAXPATHLEN - 1` (`:242`), and
    the copy loops `while (bufend - bufnext >= MB_CUR_MAX)` (`:245`, `:257`). That stores 8192 − MB_CUR_MAX
    characters: 8,186 in UTF-8 (the measurement, so MB_CUR_MAX is 6 there) and 8,191 in C.
  - `globify` runs only when globbing is on (`dcrt0.cc:367`, `:923` `&& allow_glob`), so only then is a long quoted
    word cut.
- **#429.** As the issue and the T57 round-6 reviews (`tswap-wt/tools/t57-code-r6-{mimo,glm}.md`) say. GNU env
  (coreutils 9.10, checked here) re-parses `-S`'s string as options: `env -S'-i sh -c "env | wc -l"'` prints 3, and
  so does `env -vS-i true` (its `--debug` output shows `cleaning environ`). getopt_long takes unambiguous prefixes:
  `env --ignore-e …` starts from an empty environment, and `env --ig` fails with "option '--ig' is ambiguous;
  possibilities: '--ignore-environment' '--ignore-signal'". The row's option walk has no digits (`-0 -i` misses) and
  no abbreviations (`--un FOO -i` misses).
- **#430.** `helpers:pinGitHubActionDigests` (`renovate.json5:9`) has a pending "Pin dependencies" branch (dashboard
  #390, line 28). It rewrites `uses: actions/download-artifact@v4` to `uses: actions/download-artifact@<40 hex> # v4`.
  The four literals in the table would then fail.
- **#432.** `SIGN_WAIT_SECONDS` is `0` in the tests (`SignWindowsScriptTests.cs` constructor). So a `next_code` that
  swallowed jq's parse error would time out on its first turn: one GET, no sleep, no ssign, no delete, exit 1, and
  `Timed out waiting for a code; the run fails.` posted. Every assertion of the test still holds. **The issue's
  break-it-once is the wrong one.** Removing `|| return` (`sign-windows.sh:131`) only matters when `poll_comments`
  fails. With bad JSON the GET succeeds and jq fails, so the test passes with or without `|| return`. (Removing it is
  already caught by `Sign_PollFailsEveryTime_FailsClearly`'s `Assert.Empty(Posted())`.) Use the break below.

## Task 1 (#425): `IsCurrent`'s doc comment, the G1 write-path test, the invariant-mode wording

- **Doc comment.** In `SecretVariants.cs`, move `LacksFormsOf` and `IsKnownVersion` (each with its own doc comment)
  below `IsCurrent`, so the block at `:116-127` sits directly above `IsCurrent` and `LacksFormsOf` has one `<summary>`.
  No code changes.
- **Tests** (in `VaultReindexTests`, beside `Reindex_AVersionTwoSetWithoutItsFormEntries_IsRecomputed`; the
  base-only set is built the way that test builds it):

  | Test | Setup | Outcome |
  |---|---|---|
  | `PrepareV3_AnOrdinaryWrite_RecomputesAVersionTwoSetWithoutItsFormEntries` | a `SecretRecord` with value `caf\u00e9-value` whose `Fingerprints` is the base-only v2 set; `RecordVaultStore.PrepareV3(record, keys, recomputeOlderSets: false)` | result's `Fingerprints` equals `Fingerprints(_key, Encoding.UTF8.GetBytes("caf\u00e9-value"))` (the full set) |
  | same test, an ASCII value `ascii-value` with its own (already full) set | same call | the set comes back unchanged (`Assert.Same`) |
  | `Merge_AVersionTwoSetWithoutItsFormEntries_IsRecomputedHere` | `WriteMarker(_m)`; `_m` ingests `c` = `caf\u00e9-value`; `CopyVault(_m, _other)`; `_other` runs `ingest --rotate c` with `caf\u00e9-other`; on `_other`, rewrite `c`'s record with a base-only set for the current value (as the existing test does, `SecretRecordCodec.Encode(..., 3)`), standing in for a machine without ICU; then `_m` runs `vault merge <other vault>` | exit 0; `_m`'s record `c` has value `caf\u00e9-other` and `Fingerprints` equal to `Fingerprints(_key, Encoding.UTF8.GetBytes("caf\u00e9-other"))` |

  Key test: the merge row. Break it once: in `PrepareV3`, gate the `LacksFormsOf` clause on `recomputeOlderSets`. Both
  the merge row and the first `PrepareV3` row must fail. If the merge row passes, the merge rebuilt the set some
  other way: stop and report. Don't rewrite the test into a different path.
- **Docs.** In `docs/security-model.md`, replace the sentence at `:769-772`, from "A machine without a Unicode
  library" to "on a machine with one.", with:

  > A machine without a Unicode library (.NET's invariant mode: no ICU, as in a musl image without `icu-libs`)
  > computes no other spelling itself and stretches the vault password as typed. The fingerprint checks (`redact`,
  > `tocomment`, `run`'s masking of the vault's values, and this check) still find every spelling a record's
  > fingerprints hold, so a record fingerprinted on a machine with a Unicode library is recognised in its NFC and NFD
  > spellings there too. What it computes from a value has the stored spelling alone: the fingerprints of a record it
  > writes, `run`'s plaintext masking of the values it substitutes (their fingerprints are still scanned), and the
  > broker's masking of the secret it injects. A record it writes gets the other spellings at the next `vault reindex`
  > on a machine with one.

## Task 2 (#427): a linear R1 scan, an unclosed quote in `MSYS`, accurate comments

**Order.** In `Refusal`, R1 first checks `Any(GlobCharacter)`, and only then `MSYS`. With no `\` or `"` in any
argument, `MSYS` is not scanned at all.

**The linear scan.** Replace `WordChangesGlobOption` and `RunChangesGlobOption` with the following. It must give
exactly today's verdict for every word:

1. Walk the word once. Build `s`, the word without its `"` characters, and `boundary[0..s.Length]`. `boundary[i]` is
   true for 0, for `s.Length`, and wherever a `"` stood (consecutive quotes mark one position).
2. Right to left, `P[x]` is the length of the greedy run of `no` (OrdinalIgnoreCase, as today) and `-` units at `x`:
   - `s[x] == '-'` gives `1 + P[x + 1]`;
   - `s[x..x+2]` equal to `no` gives `2 + P[x + 2]`;
   - otherwise `0`, with `P[s.Length] = 0`.
3. For each `a` with `boundary[a]`: let `g = a + P[a]`. Skip this `a` unless `s[g..g+4]` is `glob`
   (OrdinalIgnoreCase). Then, with `e = g + 4`, the word changes the option when either holds:
   - `P[a] > 0` and (`boundary[e]`, or `s[e]` is `:` or `=`);
   - `P[a] == 0`, `s[e]` is `:` or `=`, and `boundary[e + 1]`.

Why it is the same rule: a run is `s[a..b]` for two boundaries `a ≤ b`. Greedy stripping is deterministic, and
`glob` starts with neither `n` nor `-`. A prefixed run with a separator can always be extended to `b = s.Length`, so
only its start matters. The writer checked this against the current code on all 402,234 words of up to five tokens
from `no NO - glob GLOB gl ob : = " x n o`, with no mismatch.

For the tests, add `internal static bool ChangesGlobOption(string? msys, Action? step)`. It calls `step` once per
position visited in steps 2 and 3. The private call passes `null`.

**An unclosed quote** (fail closed, my call: the next token is undefined, so the glob option may be off).

- Add `internal static bool HasUnclosedQuote(string? msys)`, a port of `strbrk`'s quote handling, linear:
  - From `i`, skip spaces and tabs; at the end, return false.
  - Find the first of `"`, space or tab from `i`. None: return false. A space or tab: `i` = after it.
  - A `"` at `q`: search for the next `"` after `q`. None: return **true**. Preceded by `\`: search on from it.
    Otherwise: `i` = after it.
  - Do not use a parity count: `"a\"` has two quotes and is unclosed, and `"a\"b"` has three and is closed.
- R1 refuses, after the glob check and before R2, when an argument holds `\` or `"` and `HasUnclosedQuote(MSYS)`:

  ```
  Refused: MSYS holds a double quote that is never closed, after which Git Bash (MSYS2) reads past the end of MSYS and may turn the glob option off, and an argument holds a backslash or double quote, so tswap can't pass {What(GlobCharacter)} exactly. Close the quote in MSYS for this command, or pass {EnvironmentWay}
  ```

**Comments.**

- Above the scan: state the rule and the three facts from "What is wrong": `strbrk`'s quote and `\"` handling;
  `parse_options`' single prefix and `=`-before-`:` split; and that every token that changes the option begins with
  a changing run. Keep the over-refusal list.
- `Refusal`'s summary names the unclosed-quote case under R1.
- R4's comment (`:160-161`) cites `glob.cc` (`MAXPATHLEN` 8192 and `while (bufend - bufnext >= MB_CUR_MAX)`, so
  8192 − MB_CUR_MAX characters: 8,186 and 8,191) and `dcrt0.cc` (only while globbing is on). It adds that R4 refuses
  whatever `MSYS` says, which over-refuses when globbing is off (fail closed).
- Amendment 16 in `docs/briefs/t55-git-bash-msys2-quoting.md:152`: replace "**Why every run:** every token `strbrk`
  can produce is such a run." with "**Why every run:** every token `strbrk` produces that changes the option begins
  with such a run that changes it too (the converse does not hold, so some runs are over-refused)." Keep the rest of
  the sentence.

**Tests** (`MsysQuotingTests`). Every refusal row uses the argument `a\b`, and is also checked with `abc` (no
refusal).

| Test | Input | Outcome |
|---|---|---|
| `ChangesGlobOption_AgreesWithTheRunModel` | every word of up to five tokens from `no`, `NO`, `-`, `glob`, `GLOB`, `gl`, `ob`, `:`, `=`, `"`, `x`, `n`, `o` | equals an oracle: today's `WordChangesGlobOption` and `RunChangesGlobOption`, copied verbatim into the test class from dcc4c04 `MsysTarget.cs:183-215`; a mismatch names the word |
| `ChangesGlobOption_IsLinear` (theory) | `"` × 10,000; `-"` × 5,000; `no"` × 3,333; `glob:"` × 2,000; 10,000 characters drawn from `no-glob:="x ` with `new Random(62)` | steps ≤ `4 * (msys.Length + 1)`; for the first four rows also the verdict: false, false, false, true (`glob:` is a run ending at a quote) |
| `Refusal_R1_AnUnclosedQuoteInMsys` (theory) | `"winsymlinks:native`, `winsymlinks:native "x`, `x"`, `\"`, `"a b`, `a "b`, `"a\"`, `"\\"` | starts with `Refused: MSYS holds a double quote that is never closed` |
| same theory | `"a\"b"`, `"a"`, `""`, `a"b"c`, `"a b"`, unset, `winsymlinks:native` | `null` |
| `Refusal_R1_GlobBeforeUnclosedQuote` | `"noglob` | starts with today's `R1Start` |

`MsysSpellings` and the existing R1 to R4 tests keep passing unchanged. That includes `"glob:"":x`, whose second
token is unclosed: the glob check refuses it first.

Key tests, each with its own break:

- the linear row `-"` × 5,000. Break it once by scanning from every boundary until the shape can't match (the
  issue's walk, calling `step` per character); it must exceed the bound.
- the equivalence test. Break it once by stripping one prefix only (as `parse_options` does); it must fail on
  `nonoglob`.
- the unclosed-quote theory. Break it once with a parity count; `"a\"` and `"a\"b"` must fail.

**Docs.**

- `docs/scripts.md:55-56`: "(such as `noglob`, `-glob`, or an empty `glob:` or `glob=`, also cut at a quote)". Add
  "or holds a double quote it never closes" to the same refusal.
- Re-wrap `:58` and `:60` to at most 120 columns.
- `MsysQuotingTests`' class summary: "R1 the glob option (and an unclosed quote in `MSYS`), R2 …, R3 …, R4 an argument
  over 8,000 bytes".
- `MsysSpellings`' summary: "and amendment 16's rows (a word cut at a quote)".

## Task 3 (#429): the pinning guard's remaining Minors

In `DependencyPinningTests` only:

- **`ForceEvaluateAllowance_IsOnlyCiYmlsLockFilesJob`** (MiMo M1): keep the sum, and add
  `Assert.True(ForbiddenForms.Single(f => f.Name == "--force-evaluate outside lock-files").Find(otherJob).Any(), …)`.
- **`LockFilesJob_ReResolvesAndComparesOnLinuxX64`** (MiMo M2, GLM M1):
  - Keep the order check, and add that `lines[untrackedFails + 1]`, `+ 2` and `+ 3` are exactly
    `echo "::error::lock files that no commit has: $untracked" >&2`, `exit 1` and `fi`.
  - Add that no non-comment line of the job, after stripping `- `, starts with `if:` or `continue-on-error:`.
  - Read `ci.yml` once, and let `BuildUses` use `Step`.
  - `BuildUses` first asserts that `build-test-publish` has lines: `"{ci.yml} has no build-test-publish job"`.
- **The `env -i` row** (MiMo M3, GLM nit), parser-first from GNU env's options (`env --help`, coreutils 9.10):
  `-a/--argv0=ARG`, `-i/--ignore-environment`, `-0/--null`, `-u/--unset=NAME`, `-C/--chdir=DIR`,
  `-S/--split-string=S`, `--block-signal[=SIG]`, `--default-signal[=SIG]`, `--ignore-signal[=SIG]`,
  `--list-signal-handling`, `-v/--debug`, a lone `-`.
  - Short options cluster, and a value-taking one takes the rest of its token or the next token.
  - Long options take any unambiguous prefix, with `=` or a separate value.
  - `-S` re-parses its string as options, so **any `env -S` or `--split-string` is a hit, whatever it holds** (fail
    closed; no workflow uses it).
  - Rebuild `EnvIgnoreEnvironment()` to return a `static readonly Regex` (IgnoreCase) built once from this pattern.
    `Prefixes(option)` is the alternation of every prefix of `option` (length 1 up), longest first, each
    `Regex.Escape`d:

  ```
  (?<![\w{.$:-])env
  (?:\s+(?:-[a-z0-9]*[Cua]\s*\S+
         |--(?:{Prefixes("chdir")}|{Prefixes("unset")}|{Prefixes("argv0")})(?:=|\s+)\S+
         |-[a-z0-9-]+(?:=\S*)?
         |[A-Za-z_]\w*=\S*))*?
  \s+(?:-[a-z0-9]*i[a-z0-9]*
       |-[a-z0-9]*S\S*
       |--(?:{Prefixes("ignore-environment")}|{Prefixes("split-string")})(?:=\S*)?
       |-)(?=\s|$|`)
  ```

  (written on one line, without the layout whitespace). The ambiguous `--i` to `--ignore-` count as hits: they fail
  today, and counting them fails closed.
  - Add to `EnvIgnoreEnvironment_FindsEachForm`: `env -0 -i x`, `env -0i x`, `env -S '-i dotnet restore'`,
    `env -S'-i dotnet restore'`, `env -vS-i dotnet restore`, `env --split-string='-i x'`, `env --split-string '-i x'`,
    `env --sp '-i x'`, `env --ignore-e x`, `env --ignore-env x`, `env --un FOO -i x`, `env --ch /tmp -i x`,
    `env -a name -i x`, `env --argv0=name -i x`, `env -v0C /tmp -i x`.
  - New theory `EnvIgnoreEnvironment_LeavesEachNearMiss` (the regex must not match): `env --sx x`,
    `env --ignore-signal x`, `env --ignore-environments x`, `env FOO=1 dotnet test -S x`, `env -u FOO dotnet test`,
    `env --chdir=/tmp dotnet test`, `env --argv0 name dotnet test`.
  - The row's own hit and near-miss samples stay as they are and keep their outcomes; `Workflows_NeverCacheOrUnlockNuGet`
    stays green.
- **Labels** (GLM M3):
  - Rename the row `export -n CI / printf -v CI` to `CI unexported or overwritten (export -n, +x, printf -v)`.
  - The class summary's row list names `+x`, `env -S`, and long options by any unambiguous prefix.
  - The residual list keeps "shell quoting" and names what it covers here: shell-quoted options (`env "-i" x`,
    `--chdir "/My Dir"`, `bash -c "env -i"`) and shell line continuations (`env \` then `-i x` on the next line).
    Both really empty the environment and stay residual.
  - It adds one over-refusal line (fail closed): value-attached clusters (`env -ai x`, `env -Ci x`, where the `i` is
    the value), `env -- -i x`, and an assignment before `-i` (`env FOO=1 -i x`: GNU env's `shortopts` start with
    `+`, so getopt stops at the first `NAME=VALUE` and `-i` is the program). The `-0` rows (`env -0 -i x`) hit too,
    although env refuses `-0` with a command.
  - `EnvIgnoreEnvironment_FindsEachForm`'s summary becomes "Each spelling of `env`'s options this scan knows, one line
    each."

Break-it-once, one per assertion (GLM M2):

- in `ForceEvaluateOutsideLockFilesJob` only, treat every line as in `lock-files` (replace `jobs[line - 1]` with
  `"lock-files"`; `JobOfEachLine` itself unchanged): the new single-row assertion and the other-job sum fail, and
  nothing else. (Changing `JobOfEachLine` instead would also fail `LockFilesJob_ReResolvesAndComparesOnLinuxX64`'s
  once-each assertion, since `JobLines(…, "lock-files")` would then hold every line of ci.yml.)
- move `exit 1` after `fi` in a scratch copy of the job text: the adjacency assertion fails;
- add a second `setup-dotnet` step to `lock-files`: the once-each assertion fails;
- give `build-test-publish` a second `checkout` version: `BuildUses` fails;
- drop the `-[a-z0-9]*S\S*` alternative: the `-S` rows fail.

Apply the workflow edits to a copy of the text in the test run, or revert them before committing: no workflow
changes in the commit.

## Task 4 (#430): the workflow tests accept Renovate's SHA pin

**Parser-first: what `uses:` accepts** (GitHub's workflow syntax, `jobs.<id>.steps[*].uses` and `jobs.<id>.uses`):

- `{owner}/{repo}@{ref}` and `{owner}/{repo}/{path}@{ref}`. The ref is a commit SHA, a tag or a branch.
- `./{path}`: a local action, versioned with the repository, no ref.
- `docker://{image}:{tag}` or `docker://{image}@sha256:{digest}`.
- For reusable workflows: `{owner}/{repo}/.github/workflows/{file}@{ref}` and `./.github/workflows/{file}`.

Only a full 40-hex commit SHA is immutable. A tag or branch floats, and so does a short SHA. YAML lets the value be
plain, single- or double-quoted, or in a flow mapping. A comment needs whitespace before `#`:
`@<sha># v4` makes `#` part of the ref. Renovate's pin writes `uses: {action}@{40 lowercase hex} # {the old ref}`,
and later digest updates may write a fuller version in the comment (as `actions/attest`'s `# v4.2.2`, release.yml:713).

**The helper.** Add to `ReleasePackagingTests`:

- `internal static bool UsesAction(string line, string action, int major)`.
- It is true only for a line matching
  `^\s*(?:-\s+)?uses: {Regex.Escape(action)}@(?:v{major}|[0-9a-f]{40} # v{major}(?:\.\d+){0,2})$` (ordinal, case as
  written). That is today's form, or Renovate's pin with a version comment of the same major.
- Everything else is false, so a test needing v4 fails on it: a branch, another tag form, a short or uppercase SHA, a
  SHA without a comment or with another major, a quoted value, a trailing comment on the tag form, another action, an
  action path, `docker://`, `./`, and a commented-out line.

Use it in the two tests (pending owner sanction; see the rules paragraph):

- `SignWindows_ReplacesTheArtifact`: the two `Assert.Single(steps, …)` predicates become
  `step.Split('\n').Any(line => UsesAction(line, "actions/download-artifact", 4))` (and `upload-artifact`).
- `VerifyWindows_StepsInOrder`: the two `uses:` entries are found by the start index of the first line in `steps`
  for which `UsesAction(line, "actions/checkout", 4)` (and `download-artifact`) holds. The other entries keep
  `IndexOf`, and the order check is unchanged.

`Attest_PinnedBySha_WithMinimalPermissions` stays exact. `softprops/action-gh-release@` and the `actions/attest@`
`IndexOf` already accept both forms.

**Tests.** `UsesAction` theory (action `actions/checkout`, major 4):

| Line | Result |
|---|---|
| `      - uses: actions/checkout@v4`, `        uses: actions/checkout@v4` | true |
| `        uses: actions/checkout@0123456789abcdef0123456789abcdef01234567 # v4` (and `# v4.2`, `# v4.2.2`) | true |
| the same SHA with `# v5`; `@v5`; `@main`; `@v4.2.2`; `@v4 # pinned`; `@0123456` (short); the SHA uppercased; the SHA with no comment; the SHA then `# v4` with no space before `#`; `'actions/checkout@v4'` quoted; `uses: actions/checkout-x@v4`; `uses: actions/checkout/sub@v4`; `# uses: actions/checkout@v4`; `uses: docker://alpine:3` | false |

**The real check (key).** In the worktree, apply Renovate's rewrite to both workflows:
`sed -E -i 's#(uses: [^ @]+)@(v[0-9]+)$#\1@0123456789abcdef0123456789abcdef01234567 \# \2#'
.github/workflows/ci.yml .github/workflows/release.yml`. Then run `ReleasePackagingTests` and
`DependencyPinningTests`, then the whole unit suite (`./runtests.sh --unit`), all on the rewritten workflows: all pass.
With the rewrite applied, also grep the whole test tree once (`grep -rnE 'uses:|@v[0-9]' TswapTests --include=*.cs`)
and check that every hit is one this task handles, a prefix match (`softprops/action-gh-release@`, `actions/attest@`),
the exact attest pin, or forbidden-form sample data in `DependencyPinningTests`. Restore the files
(`git checkout -- .github/workflows`). Record the commands, the grep result and the totals in the commit message.

- Break it once: with the rewritten workflows, make `UsesAction` accept only `@v{major}`. The two tests must fail.
- If any other test fails on the rewritten workflows, fix it the same way if it is an exact `uses:` match. Otherwise
  stop and list it.

The workflows themselves are not changed in this commit. The owner approves Renovate's "Pin dependencies" item once
this merges.

## Task 5 (#432): `Sign_PollBadJson_IsNotRetried` and three comment nits

- `Sign_PollBadJson_IsNotRetried` gains `Assert.Empty(Posted());` and `AssertNoSecretsLeaked(run);`.
  - **Key test.** Break it once by making `next_code` swallow jq's failure: append `|| true` after the jq command
    (`sign-windows.sh:133-137`). The test must fail on `Assert.Empty(Posted())` (the timeout post).
  - Removing `|| return` (`:131`), as #432 suggests, does not reach this test, for the reason under "What is wrong".
    Say so in the commit message.
- `SsignManagerRegex`' summary (`ReleasePackagingTests.cs:1826`) becomes: "The ssign manager's `matchStrings` entry:
  the regex Renovate runs, compiled here as a .NET `Regex` (JSON5's `\\` is one `\`)."
- `SignWindowsScriptTests`' class summary names the fake `sleep` that is always installed (it logs its argument and
  returns at once). It also names the `get-fails` switch (the next N GETs fail after a truncated page) and the
  `post-fails` switch (every POST fails with `gh: HTTP 502`).
- `SignWindows_PinsSsignBySha`: use `SsignCargoLine()` instead of its own copy of the selector (`:1797`); the
  assertions are unchanged.

## Out of scope

- **#426 (a native program beside `msys-2.0.dll` gets MSYS2 quoting): its own brief.** It isn't small:
  - It needs a list of the native executables Git for Windows and MSYS2 ship beside the DLL, which only a Windows
    install or CI run can give.
  - It needs a parser-first decision between PE imports (a PE import-table reader: tswap has none, and it would read
    a file `run` is about to start) and a name list.
  - It needs a Windows E2E test.
  - Its call site is `RunCommand.cs:276`, a T58 file.
  - Proposed: brief T6x, spike first on Windows CI (list the files, read their imports), then the rule and the
    `docs/scripts.md` limit note.
- #429's ruleset item (done by the owner).
- Changing the workflows' `uses:` lines (Renovate's PR does that) and approving the dashboard item (owner).
- Modelling `strbrk` exactly for the glob rule (the run model stays, with its over-refusals); R4 when globbing is
  off.
- `PrepareV3`, `MergeRecords`, the record store and every T58, T60 and T61 source file.

In your report, give one 0.3.3 release-note line per issue (#425, #427, #429, #430, #432), or "none" where the
change is test-only.

## Amendment history

- **Round 1 (MiMo r1, ready to implement; controller rulings).**
  - M1: Task 3's first break-it-once is scoped to `ForceEvaluateOutsideLockFilesJob`. The blunt `JobOfEachLine`
    mutation would also fail the once-each assertion.
  - M2: shell-quoted options and line continuations are named as residuals. The over-refusals (`-ai`, `-Ci`,
    `env --`, an assignment before `-i`, `-0`) are named, and the theory summary is softened.
  - M3: Task 4's real check also runs the whole unit suite and greps the test tree on the rewritten workflows.
  - M4: the test bytes are written as `Encoding.UTF8.GetBytes`.
  - Rulings:
    - The #430 matcher widening is pending owner sanction, and Task 4 waits for it.
    - The unclosed-quote R1 refusal stays.
    - `|| true` after jq is #432's break (the controller notes it on the issue).
    - The #426 brief adds its docs note.
    - The owner approves Renovate's "Pin dependencies" item.
