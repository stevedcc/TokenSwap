# T16 Stage 3: `run` decrypts only what it substitutes and masks every vault secret (issues #220, #106)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans, task by task, TDD per task (superpowers:test-driven-development).

**Plan review round 1** (GLM, MiMo: request changes). All findings addressed in place:
contract gate and fingerprint-set source aligned with Stage 2's approved plan (3457dbc: tasks 1-4,
S7, `SplitsASurrogatePair`, `UnreadableRecordException`); the Linux probe accepts a read on
`/dev/tty` when the process's controlling terminal is our PTY (MiMo B1: `getpass` reads fd 5 =
`/dev/tty`); unreadable records split into fail (named) vs warn (unnamed), as today; Stage 2's
format 2 warning in `run`; fail-closed redactor errors; the general residual-limit wording; the
hold-back analysed as a timing channel and quantised ("Hold-back as a timing channel"); T6 amends the
spec; the minors folded in. Two not taken as written, with evidence: MiMo M7's nested-token leak
does not happen on the 1.0 path (`StreamRedactor.cs:37` sorts longest `Find` first, so the outer
value is replaced before the inner one), but the overlapping case it points at is real on both paths,
so overlapping occurrences now merge into one mask; MiMo M15 is already fixed in Stage 2's table
("Stage 3 calls it, never edits the file"). macOS's ICANON condition (GLM I4, MiMo I7) is marked
**pending owner confirmation**.

**Goal.** `tswap run` decrypts only the value sections it substitutes (`{{name}}`, `{{name:previous}}`,
and the markers of its `{{@file}}` files), and its streaming redaction masks every other value version
in the vault by keyed fingerprint. Target: **v0.3.0**.

**Why.** Owner, 2026-11-07 (binding): "unlocking all secrets is bad practice". Today `run` calls
`ctx.LoadSecrets(key)` (`TswapCli/Commands/RunCommand.cs:72`), which decrypts every value and previous
value of the vault into strings that live for the whole child run, and it masks only its own tokens'
forms (`RunCommand.cs:87-96`, `:180-186`). Spec Goal 2 and Stage 3
(`docs/superpowers/specs/2026-11-01-import-story-design.md:51-54`, `:240-262`); it also closes #106
(`run` misses encoded forms of secrets it didn't substitute).

**Repos and bases.**
- RedactingPty: `/home/stevecrawford/RiderProjects/redactingpty-wt`, a new worktree from `main`
  b4fda29 (R1 merged, untagged: `git describe` = `v1.0.2-14-gb4fda29`). `brief/r2` (3 commits, .NET 11
  SDK, test targets `net10.0;net11.0`, CI) is unmerged and waits for .NET 11 GA; it changes no library
  code, so 1.1 does not wait for it. Whichever merges second merges `main` in (conflicts at most in
  `README.md` and the workflows).
- tswap: `origin/main` once #251 (`feat/apply-sudo-run-file`, contained in this branch's ddd4ca3) has
  merged, plus Stage 2's store contract (its tasks 1-4, "Shared with Stage 2" below), merged in
  (`git merge --no-edit`; this project never rebases).

## Facts checked against the code

| Fact | Where |
|---|---|
| `run` decrypts the whole vault, then resolves tokens and fills files from that `SecretsDb` | `RunCommand.cs:72`, `:78-85`, `:110` |
| `run`'s own forms: raw, escaped (files), base64/base64url padded and unpadded, `\r\n`, `\n` and ONLCR (`\r\r\n`) forms of multi-line values, and their encodings | `TswapCore/Redaction.cs:19-40`, `Apply.cs:40-138` |
| Stored fingerprint variants: plain, whitespace-stripped (CR, LF, space, tab removed), base64 **padded only**, base64url **unpadded only** | `TswapCore/Fingerprints/SecretVariants.cs:40-59` |
| `FingerprintIndex.Scan` slides one rolling hash per distinct stored length over the whole text, then confirms on the HMAC | `FingerprintIndex.cs:67-97` |
| `LoadMetadata` reads metadata sections only; `VaultMetadata.Records` (public since Stage 1) lists every merged record's `RecordMetadata`, whose `RetainedVersions()` yields each version's `FingerprintSet`; `IsFullyFingerprinted` = no un-fingerprinted and no unreadable record | `RecordVaultStore.cs:1148`, `VaultMetadata.cs:22-32`, `Keyring/RecordMetadata.cs:36-43` |
| `ReadSecretValue(name, key, previous)` decrypts one record: on format 3 only its metadata and the one value section; on format 2 the whole record (current and previous) | `RecordVaultStore.cs:531`, `:574`, `:601` |
| Test seams: `RecordDecrypted` (metadata/payload), `ValueDecrypted` (record, version stamp) | `RecordVaultStore.cs:132`, `:138` |
| `apply`'s fill looks up only the **first** marker per line, checks existence via `db.Secrets.ContainsKey` | `Apply.cs:59`, `:69`, `:75`, `:80-81` |
| Burn state of current and previous version | `RecordVaultStore.cs:673-692` (`ToSecret`), `Models.cs:254`, `:267`, `:302` |
| `run {{s}}` on an unreadable `s` must fail naming the hashed file (`ATruncatedMainRecord_FailsClosed`); today an unreadable record `run` doesn't name is only warned about (`LoadSecrets`' warning) and `run` goes on | `TswapTests/RecordConflictTests.cs:222-241`; `Models.cs:267-310` |
| RedactingPty: one public runner method; redactor overlap = longest Find − 1; replacements applied by successive `string.Replace` | `IPtyRunner.cs:16`; `StreamRedactor.cs:37-40`, `:47-90`, `:102-110` |
| The redactor is built before the fork in `UnixPty.Run` (parent code), per call in `WindowsPty` and per stream in `FallbackPty` (stdout and stderr drained **on two threads**) | `UnixPty.cs:148`; `WindowsPty.cs:284`; `FallbackPty.cs:60-61`, `:82` |
| Frozen fork-child spans include `UnixPty.Run`'s attribute and **signature** (lines 100-104 at 5d9a8fa) and 150-180 | `docs/briefs/r1-dotnet10-idioms.md:45-58` |
| Package validation baseline 1.0.0; a `v*` tag publishes to nuget.org (OIDC) | `RedactingPty.csproj:36`; `.github/workflows/publish.yml:8-10` |
| tswap consumes RedactingPty 1.0.2; the only test fake runner is `FakePty` | `TswapCli/TswapCli.csproj:21`; `TswapTests/RunFileTokenTests.cs:105-131` |
| Plaintext redactor throughput (i7-6700K, 4 KB chunks): 854 / 475 / 140 / 28.6 Mchars/s at 1 / 10 / 50 / 200 replacements | `redactingpty-wt/r1-report.md:311-339` |

**Pre-plan probe (scratch, Release, this machine, not committed).** `FingerprintIndex.Scan` over
4096-char windows plus overlap, log-like text, no hits: 200 secrets of 16-64 chars (66 distinct
lengths) **1.35 Mchars/s**; 200 × 32 chars (3 lengths) 31.7; 2,000 × 16-128 (146 lengths) **0.61**;
200 × 16-5,000 (502 lengths, longest variant 6,576) **0.09**. A prototype with prefix hashes, the
character-class pruning of Task T1 and a bitset prefilter (its whitespace-count rule a stand-in), on
log text: 200 × 16-64 **24**, 2,000 × 16-128 **7.1**, 200 × 16-5,000 **12.7** Mchars/s (the 200 × 32
case was not rerun); on base64-heavy text, 200 × 16-64: **1.3**. Stage 1's scanner is unusable in a stream; T1
builds the fast one.

## Out of scope

- Any variant-set change (hex, URL-encoding, JSON escapes, unpadded base64, wrapped base64,
  re-indented multi-line values): a format change, a later variant-set version (spec `:252-254`).
- Stage 2's commands (`redact`, `tocomment`, `apply`, `check`, `get`) and `FingerprintIndex.cs`.
- The broker's own redactor (`TswapCore/Broker/BrokerRedactor.cs`).
- Prefix fingerprints for smarter hold-back: **rejected**, they would let a `run` child learn a
  secret's first characters one at a time by watching what is held back.
- Zeroing the vault key inside `run`, ConPTY's re-rendering of long lines (pre-existing), classic
  vaults (already refused: `ICliCommand.WorksOnClassicVault`).

## Owner decisions (2026-11-07)

- **D1, partly fingerprinted vault: approved.** `run` masks its own tokens **and every record that
  has fingerprints**; the same warning before and after the child; it keeps working. (The spec's
  "only its own tokens", `:247-251`, is overruled.)
- **D2, hold-back: interactive prompts are detected (owner design).** To catch a match split across
  reads, the redactor holds back the end of the output. With `PendingFrom` and tswap's character
  classes, single-line secrets hold only the trailing word (less than today's longest form − 1). A
  **multi-line** vault secret (PEM, kubeconfig) may contain any text, so up to its raw length is held
  on every pause, which would hide prompts. Therefore:
  - When the redactor holds a non-empty tail and the output has been quiet for ~50 ms, the relay
    checks the child's state, then re-checks every ~100 ms while output stays quiet. **Time alone
    never releases held text; only a positive check does.**
  - **Linux:** release when the PTY's foreground process group (`tcgetpgrp` on the master) waits for
    terminal input: no thread of any process in that group is running
    (`/proc/<pid>/task/*/syscall`), and at least one is blocked in `read()` on our terminal: an fd on
    the PTY slave itself, or on `/dev/tty` while that process's controlling terminal is the slave
    (coordinator, after MiMo B1: `getpass` reads fd 5 = `/dev/tty`). Any running thread, or anything
    unreadable: keep holding.
  - **macOS:** no `/proc`; release when the terminal's ECHO flag is off (password and passphrase
    prompts: ssh, sudo, gpg), and (my call, **pending owner confirmation**) ICANON on. A plain `y/N`
    prompt behind a held multi-line tail stays hidden until more output or exit.
  - **Windows (ConPTY), and `FallbackPty` (no terminal):** no signal; hold, no timer.
  - Released text goes through the matchers and replacements first, like `Flush`: only text that no
    complete secret occupies is released.
  - **Residual limit, general form** (documented with the other limits): only *complete* occurrences
    are recognised; recognising prefixes is deliberately not done (it would be a prefix oracle). So
    text that lies in no complete occurrence is emitted, when it leaves the hold window, at a D2
    release, or at exit: a secret printed only in part (cut short, split by an input wait, completed
    later by another thread or a background job, or split between stdout and stderr under
    `FallbackPty`) shows that part. Today's plaintext path behaves the same; not a regression.
- **D3, throughput targets: approved.** Realistic vault on log text ≥ 20 Mchars/s, 2,000 secrets ≥ 5,
  base64-heavy output ≥ 1 (Task T5). A miss is reported, never loosened by the builder.
- **D4, release order: approved.** Tag RedactingPty `v1.0.3` from b4fda29 (R1's refactor alone), then
  `v1.1.0`; both are owner gates.

## Outward gates (owner)

- **G1** Merge the RedactingPty PR (CI: 9 legs green).
- **G2** Tags `v1.0.3`, then `v1.1.0` (D4): each publishes to nuget.org. tswap's PR CI can't pass
  until 1.1.0 is there.
- **G3** Merge the tswap PR (`Closes #106`, `Refs #220`).
- **G4** v0.3.0 tag, with the rest of v0.3.0.

External reviews as for every brief: plan review, then code review (GLM + MiMo) per repo.

## Shared with Stage 2

Stage 2's approved plan (`docs/superpowers/plans/2026-11-07-t16-stage2-redact-without-decrypting.md`
at 3457dbc, "The store API") is the contract; **Stage 3 proposes no other API**: `ctx.OpenVault(key)`
(Stage 2 task 4) → `VaultView : ISecretLookup` (`Contains`, `HasPreviousValue`, `IsBurnedToken`,
`ResolveToken` decrypting one version once, `ThrowIfUnreadable`), `LoadAll(FormatTwoRecords.Skip)` →
`VaultMetadata`, `FormatTwoDecoded`, `Apply.ApplySecretsReporting(content, ISecretLookup, warnings)`,
the format 2 warning texts in `FingerprintTexts`, and `FingerprintIndex.SplitsASurrogatePair`
(internal, same assembly). It is lazy, so `run`'s error order stays as today. What `run` relies on
(Stage 2's plan states how each is met):

- **S1** `name` decrypts only the current value section, `name:previous` only the previous one;
  format 2 decrypts that one record whole, counted in `FormatTwoDecoded`.
- **S2** Messages identical to `SecretsDb.ResolveToken` / `ThrowIfUnreadable`: `VaultView` turns
  `UnreadableRecordException` into the text naming the hashed file
  (`RecordConflictTests.ATruncatedMainRecord_FailsClosed`).
- **S3** Burn state from metadata equals `ToSecret`'s (`SecretInfo.From`).
- **S4** `Contains`, `IsBurnedToken`, `ThrowIfUnreadable` and `LoadAll(Skip)` decrypt no value.
- **S5** Conflicted copies folded as `ReadSecretValue` folds them.
- **S6** Value bytes zeroed after conversion; `VaultView.Dispose` zeroes what it holds.
- **S7** `LoadAll(Skip).Records` keeps every record Stage 2's `BuildIndex` scope covers (every
  non-tombstone record, `Value` and `Burned`), each with `RetainedVersions()` and its
  `FingerprintSet`s, and `LoadAll` writes the full load's warning texts (Stage 2's diagnostics
  parity). Stage 3's scanner is built from exactly that; it does not use `BuildIndex`.

**`run`'s stderr, in order:** `LoadAll(Skip)`'s warnings (unreadable records naming their hashed
file, conflicted copies, far-future stamps; once); the coverage warning (T4); burned-value warnings
(as today); then the child's output; after the child exits: the coverage warning again, then Stage
2's `get`/`apply` format 2 text (`Warning: {n} of the records used here are stored in the old record
format 2, …`) when `FormatTwoDecoded > 0`, counting only records `run` named.

**Unreadable records, one rule (agrees with Stage 2 and today):** a token or file marker naming an
unreadable record **fails** before any child starts, with the text naming the hashed file (S2;
`ATruncatedMainRecord_FailsClosed`'s `run` line stays as it is). An unreadable record nobody named
is **warned** about (`LoadAll`'s line naming its file, as today's `LoadSecrets` warning) and counted
in the coverage warning's `<m>`; `run` goes on. No test input changes.

**File ownership** (agrees with Stage 2's table).
- Stage 2: `RecordVaultStore.cs`, `VaultMetadata.cs`, `SecretEntry.cs`, `SecretInfo.cs`,
  `ISecretLookup.cs`, `VaultView.cs`, `Models.cs`, `Apply.cs`, `Check.cs`, `CommandContext.cs`,
  `FingerprintIndex.cs`, `FleetMachine.cs`, its commands and docs sections.
- Stage 3: `TswapCli/Commands/RunCommand.cs`, `TswapCli/FingerprintStreamMatcher.cs` (new),
  `TswapCli/RunCoverage.cs` (new), `TswapCli/TswapCli.csproj` (RedactingPty version),
  `TswapCore/Fingerprints/FingerprintScanner.cs` (new), `FakePty` in `TswapTests/RunFileTokenTests.cs`,
  its new test files; docs: the `run` row and limits in `docs/security-model.md`, `run` in
  `docs/commands.md`, its section of `docs/release-notes/v0.3.0.md`. `Redaction.cs` and
  `FilledFiles*.cs` are Stage 3's but stay unchanged.

**Order.** RedactingPty R1-R3 and tswap T1-T2 start at once, in parallel with Stage 2; T1's
surrogate check calls `FingerprintIndex.SplitsASurrogatePair` once Stage 2's task 1 is merged in
(before that, T1 is written against the predicate's documented contract and its test). **T3 onwards
start when Stage 2's tasks 1-4 (the contract; task 4 adds `ctx.OpenVault`) are pushed**; Stage 3
merges them in (`git merge --no-edit`), never edits their files.

## RedactingPty 1.1

### API (new public types; nothing existing changes)

```csharp
namespace RedactingPty;

/// Finds matches in the redactor's window. Called with the held tail + the new chunk, and on Flush
/// with the tail; must be stateless per call and thread-safe (FallbackPty drains stdout and stderr
/// on two threads with one matcher).
public interface IStreamMatcher
{
    /// Longest match FindMatches can report, in UTF-16 code units; read once; >= 1.
    int MaxMatchLength { get; }

    /// Adds every match lying entirely inside window.
    void FindMatches(ReadOnlySpan<char> window, ICollection<StreamMatch> matches);

    /// Smallest index from which a match could still start and end past the window; the redactor
    /// may emit everything before it. window.Length when none can.
    int PendingFrom(ReadOnlySpan<char> window) => Math.Max(0, window.Length - (MaxMatchLength - 1));
}

public readonly record struct StreamMatch(int Start, int Length, string Replacement);

public sealed class StreamRedactor
{
    public StreamRedactor(IReadOnlyList<StreamReplacement> replacements);             // unchanged
    public StreamRedactor(IReadOnlyList<StreamReplacement> replacements,
                          IReadOnlyList<IStreamMatcher> matchers);                    // new
    public bool HasHeld { get; }      // a non-empty tail is held back
    public string Release();          // resolves the tail like Flush (complete matches masked) and
                                      // returns it; the redactor stays usable
}

public sealed record RedactionOptions
{
    public IReadOnlyList<IStreamMatcher> Matchers { get; init; } = [];
    /// Release held text when the child waits for terminal input (D2): Linux and macOS PTYs only;
    /// ignored by WindowsPty and FallbackPty. Off by default.
    public bool ReleaseWhenAwaitingInput { get; init; }
}

public interface IPtyRunner
{
    int Run(string[] argv, IReadOnlyList<StreamReplacement> replacements);            // unchanged
    int Run(string[] argv, IReadOnlyList<StreamReplacement> replacements,
            RedactionOptions options)                                                 // new, default:
        => options.Matchers.Count == 0 && !options.ReleaseWhenAwaitingInput
            ? Run(argv, replacements)
            : throw new NotSupportedException("This IPtyRunner does not support RedactionOptions.");
}
```

`RedactionOptions` rather than a matcher list parameter (my call: one more setting already exists,
and later ones need no new overload).

`ICollection<StreamMatch>` rather than a return value (my call): spans can't be captured by an
iterator, and matches are rare, so the interface call costs nothing. The default overload throws
rather than drops matchers: a third-party runner must not silently redact less.

### Semantics

- **No matchers** (`[]`, or the 1.0 constructor): today's algorithm, unchanged code path. The existing
  `StreamRedactorTests` stay untouched.
- **With matchers**, per `ProcessChunk`: window = tail + chunk; collect spans once: every occurrence
  of every `Find` (overlapping ones included) and every matcher's matches (validated: inside the
  window, `1 <= Length <= MaxMatchLength`, else `InvalidOperationException` whose message carries
  indices, lengths and the matcher's type only, never window or match text). Hold point =
  the minimum of each matcher's `PendingFrom` and the plaintext pending point (the smallest `i` whose
  `window[i..]` is a proper prefix of some `Find`, exact). Then today's straddler pull-back over all
  spans, until stable, and the surrogate guard. In the emitted part, spans are chosen **longest first,
  then leftmost, then plaintext before matcher, then list order**, never overlapping, and replaced in
  one pass, so replacement text is never matched again. Occurrences that overlap a chosen one (not
  nested in it) are merged into its mask (my call, after MiMo M7: no character of any complete
  occurrence is emitted; the 1.0 path's successive `Replace` shows the non-overlapping tail of the
  second). Equal spans: one mask, the first by the tie order (for tswap's matcher: name ordinal,
  current before previous, then kind). `Flush` resolves the tail the same way.
  Overlap = max(longest `Find`, every `MaxMatchLength`) − 1.
- Truncation after the 30 s drain timeout still discards the tail (unchanged).
- **Failure is closed** (MiMo I1). If a matcher or the redactor throws in the relay, the runner
  discards the held tail and everything of that chunk, writes `[output truncated: redaction failed]`,
  keeps draining the master and discarding its bytes (so the child never blocks on a full PTY), and
  after the child exits rethrows the exception (text as above). Nothing after the failure point is
  ever written. tswap prints that message, which contains no output text. Normal exit and tswap's
  signal path end at EOF and `Flush` as today (complete occurrences masked).
- `Release()` masks complete matches in the tail and emits the rest, including a partial match
  (D2's residual limit); the next chunk starts with an empty tail; on an empty tail it returns `""`.

### Input-wait release (D2), inside RedactingPty

**Where (my call): RedactingPty.** It owns the relay loop, its timing and the PTY master; tswap sees
neither (it gets one `Run` call). The platform probes are internal, not public API: only the runners
hold the master fd; the public surface is `RedactionOptions.ReleaseWhenAwaitingInput` plus
`HasHeld`/`Release` for custom runners.

- `internal interface IInputWaitProbe { bool ChildAwaitsInput(); }`, built by the runner in the
  **parent** after `forkpty` returns (never in the child):
  - `LinuxInputWaitProbe(masterFd, slavePath, IProcFs procFs)`: `slavePath` from `ptsname` of the
    master and the slave's `st_rdev` (`stat`, once, in the parent); `tcgetpgrp(masterFd)` (failure →
    false); members of the group from `/proc/[0-9]*/stat`, parsed after the **last** `)` (the command
    name may contain `)` and spaces; any parse anomaly → false): the pgrp field, and `tty_nr` (the
    controlling terminal). For each thread of each member, `/proc/<pid>/task/<tid>/syscall`:
    `running` → false; true only if every thread is blocked and at least one is in `read` (syscall
    number per architecture: x86-64 0, arm64 63; any other architecture: no probe) on an fd (its first
    argument) that is **our terminal**: `stat` on the `/proc/<pid>/fd/<n>` magic link gives the slave's
    `st_rdev` (the slave by any path, `dup`ed), **or** it gives `/dev/tty`'s (5, 0) and that process's
    `tty_nr` decodes to the slave's major and minor. Another terminal, a pipe or a file → not ours.
    Any read error (a process exiting mid-scan, Yama `ptrace_scope` ≥ 2, `hidepid`) → false.
    `IProcFs` (read a file, list a folder, `stat` a path) is the seam the fake-tree tests use.
  - `MacInputWaitProbe(masterFd)`: `tcgetattr` on the master; true when ECHO is off and (my call,
    **pending owner confirmation**, GLM I4 / MiMo I7) ICANON is on: password prompts are expected to
    keep canonical mode, while raw-mode programs such as `vim` or `less` clear both and would otherwise
    release on every pause; without it, D2 as written (ECHO off alone). R2b checks that `tcgetattr` on
    the master reports the slave's flags on macOS; if not, the parent opens `slavePath` with
    `O_NOCTTY`, uses it for `tcgetattr` only and closes it when `Run` returns, and the report says so.
  - `WindowsPty`, `FallbackPty`: no probe.
- `internal sealed class HoldReleaser(TimeProvider time, IInputWaitProbe? probe)`: tracks quiet time
  since the last output; with `HasHeld` and a probe, a first check at 50 ms of quiet, then every
  100 ms; `Release()` only when the check returns true. No probe, no held text, or the option off: no
  checks. An internal `Checked` event (each check and its result) is the test seam: the test host
  (`InternalsVisibleTo`) appends one line per check to a file named by its arguments, and the
  real-PTY tests wait for N lines (a concrete condition), never for time.
- `UnixPty`'s read loop (parent code after the fork, outside the frozen spans) takes its `poll`
  timeout from the releaser (50 / 100 ms while holding, 200 ms otherwise, as today) and on a timeout
  asks it whether to write `redactor.Release()`. The options travel to the frozen `Run` in the same
  internal carrier as the matchers.
- Measured 2026-11-07 on Linux x86-64 with a real PTY (the same probe as D2's): `python3 input()`
  waits in `read` on fd 0 and `getpass` in `read` on fd 5 (`/dev/tty`), both detected; an
  interactive `bash --norc -i` (readline) waits in `pselect6` (syscall 270), not detected: a bash
  prompt behind a held multi-line tail stays hidden until more output. Accepted as a safe-side miss
  (agents run commands, not shells); telling which descriptors a `pselect6` waits on would mean
  reading the process's memory, out of scope.
- Known misses, all on the safe side (held, not released): programs that wait in `poll`/`select`/
  `epoll` on the terminal instead of `read` (R2b reports which of `bash`, `python3 input()`,
  `getpass`, `ssh`, `sudo`, `gpg` are detected, Linux and macOS); terminal output from processes
  outside the foreground group is not checked (a background job printing part of a secret while the
  foreground waits is released: part of the residual limit).
- Cost: while holding and quiet, at most one foreground-group scan per 100 ms (T5 reports it).

### Hold-back as a timing channel (MiMo I6, GLM M7)

What a `run` child (and the agent reading `run`'s output) can observe is **when** output bytes appear,
so how much is held at any moment. The hold point is the minimum of:
- the plaintext pending point: an exact prefix test against `run`'s own forms, i.e. values the child
  was handed (inside `run`'s documented exception, nothing new);
- the matcher's `PendingFrom`: in T1's design a function of the text's characters and of per-class
  aggregates only (`MaxRawLength` per class, `W_max`), never of a rolling hash, bitset or HMAC;
- complete matches (straddler pull-back): a complete occurrence is the full-value guess oracle
  `redact` already offers (accepted, spec "Guessing oracle").

So a guess that shares a secret's prefix holds exactly like any other word of its class: no prefix
oracle. What the aggregates would reveal, by printing runs of growing length and watching when they
appear: the exact longest stored variant per class and the largest whitespace count of a multi-line
value. **Designed out (my call):** each per-class cap and `W_max` is rounded **up** to a multiple of
256 characters (holding more is always sound). What is left: a 256-character bucket of the longest
value per class, and whether some value contains whitespace. The agent, running as the vault's user,
can already list the vault folder, whose record files are padded to 256-byte buckets
(`SecretRecordCodec`, spec "Constraints"), and read secret names with `names`; the bucket adds
nothing finer. Interactive cost: up to 255 characters of a trailing word held instead of the longest
secret's length. T1 pins it (`PendingFrom_IndependentOfValues`, `PendingFrom_CapsQuantised`); the
docs state the channel.

### Runners, without touching the frozen spans

`UnixPty.Run(argv, replacements)` keeps its frozen signature. The new overload wraps the replacements
and the options in an internal `MatcherCarrier : IReadOnlyList<StreamReplacement>` (it enumerates the replacements) and calls
the frozen `Run`; the one parent-code line `UnixPty.cs:148` becomes `StreamRedactor.ForRunner(replacements)`
(internal: unwraps a carrier, else the 1.0 constructor). Same in `WindowsPty.cs:284` and
`FallbackPty.Drain` (`:82`). (My call: no instance state, so concurrent `Run` calls stay safe, and the
frozen-span diff stays empty.)

### Release

Version 1.1.0; `PackageValidationBaselineVersion` **1.0.3** (MiMo M1: D4 publishes 1.0.3 first, so
that is the latest release; strictly stronger than 1.0.2); README gets "Custom matchers" (contract, thread safety, hold-back) and "Releasing
held output at a prompt" (per platform, the residual limit); "Fork safety" unchanged. If package validation flags the default interface member (expected not to: it has a
body), fall back to a public `IMatchingPtyRunner : IPtyRunner` implemented by the built-in runners,
and report it.

## tswap changes per file

- `TswapCore/Fingerprints/FingerprintScanner.cs` (new): the stream scanner (Task T1).
- `TswapCli/FingerprintStreamMatcher.cs` (new): `IStreamMatcher` over the scanner; replacement
  `[REDACTED: name]`, or `[REDACTED: name:previous]` for a previous value; one label for every kind,
  as `run` labels its own forms today (my call; `redact`'s `(base64)` suffixes are a file concern).
- `TswapCli/RunCoverage.cs` (new): the coverage warning text from a `VaultMetadata`; the format 2
  line comes from Stage 2's `FingerprintTexts`.
- `TswapCli/Commands/RunCommand.cs`: `ctx.OpenVault(key)` replaces `LoadSecrets` (`:72`); tokens (`:78-85`)
  and files (`:110`) resolve through it; `LoadAll(Skip)` → scanner → matcher; warnings before and after
  the child; `runner.Run(argv, replacements, new RedactionOptions { Matchers = [matcher],
  ReleaseWhenAwaitingInput = true })` (`:186`), always with the matcher (empty index:
  `MaxMatchLength` 1, no matches), so `run` uses one resolution path. The plaintext list (`:87-96`) is
  unchanged. After `runner.Run` returns (its `Flush` done): the warnings, then `FingerprintKeys` and
  the `VaultView` are disposed (`finally`).
- `TswapCli/TswapCli.csproj`: RedactingPty 1.1.0. Before G2, develop against
  `1.1.0-local.N` from a local pack (`-p:RestoreAdditionalProjectSources=<dir>`), never a local
  `1.1.0` (it would shadow the real one in the NuGet cache); the last task sets 1.1.0.
- `TswapTests/RunFileTokenTests.cs`: `FakePty` also implements the `RedactionOptions` overload
  (`new StreamRedactor(replacements, options.Matchers)`); no assertion changes.
- Docs (Task T6).

## What `run` masks, before and after

| Output contains | Today | After |
|---|---|---|
| A substituted value's forms (raw, escaped, base64/base64url ±padding, `\r\n`/`\n`/ONLCR and their encodings) | yes | yes (plaintext, same forms; with a matcher present, overlapping occurrences merge into one mask, a fix) |
| Another vault value (current or previous, burned included): verbatim, single line | no | yes |
| … whitespace-stripped, base64 padded, base64url unpadded | no | yes |
| … base64url padded | no | the unpadded core; the `=` stay visible |
| … base64 with its `=` padding removed | no | **no** (not a stored variant) |
| … multi-line, stored line endings kept (pipes, `FallbackPty`) | no | yes |
| … multi-line through a PTY (`\n` → `\r\n`; `\r\n` → `\r\r\n`) | no | yes, by folding `\r\n` to `\n` before matching (my call, no format change) |
| … `\r\n` value printed with `\n` only; wrapped base64; re-indented PEM (YAML block); JSON/URL/hex encodings; inside a larger base64 blob | no | **no** (later variant set) |
| Records not fully fingerprinted (format 2, replayed, a version without a set) or unreadable | no | no; warned twice (D1) |
| Secrets added while the child runs | no | no (index built at start) |
| A prefix of a secret never completed (cut short), or one split by an input wait (Linux, macOS), another thread or a background job | emitted (at the latest at exit) | emitted, unmasked (residual limit) |
| A secret split between stdout and stderr (`FallbackPty` redacts each stream alone) | no | no |
| Values in memory during the child run | every value of the vault | substituted values + fingerprints + `K_fp` |

A `run` child can now test guesses against any vault secret by printing them; `redact` (no sudo)
already offers that oracle (spec "Guessing oracle (not new)"), so the agent gains nothing. Hit labels
show secret names, which `names` already lists. The hold-back timing channel: section above.

**#106:** it asks that `run` match the encoded variants `redact` matches (`BuildMatchList`: plain,
whitespace-stripped, base64, base64url), or else document the gap. After this stage `run` matches
those for every vault secret and documents what is left (the table), so `Closes #106` holds.

## Tasks

Every task: failing test first, watch it fail for the stated reason, then the code. Each test below
says what production change makes it fail.

### RedactingPty (brief R3; one commit per task)

**R1. Matcher API and the redactor's matcher path.** Files: `RedactingPty/IStreamMatcher.cs`,
`StreamMatch.cs` (new), `StreamRedactor.cs`; test `RedactingPty.Tests/StreamRedactorMatcherTests.cs`.
- `Matcher_SplitAtEveryPosition_Masked` (40-char match, every split): fails if the overlap ignores
  `MaxMatchLength`.
- `Matcher_PemSized5000Chars_AcrossChunks_Masked` (4096-char chunks): fails with any cap below 5000.
- `Matcher_OverlapsPlaintext_LongestWins`, `Matcher_EqualLength_PlaintextWins`,
  `Matcher_Nested_LongerWins`, `Matcher_Disjoint_AllMasked`: fail if spans are applied in source
  order or by successive `Replace`.
- `Matcher_ReplacementTextNotRescanned`: fails if `string.Replace` runs after the span pass.
- `Matcher_Straddler_NeverEmittedInPart` (asserts every emitted piece): fails if the pull-back ignores
  matcher spans.
- `Matcher_PendingFromWindowLength_EmitsAtOnce` and `Plaintext_NewPath_HoldsOnlyARealPrefix`: fail if
  the hold point stays `window.Length − overlap`.
- `Matcher_InvalidMatch_Throws` (theory: negative start, past the window, empty, longer than
  `MaxMatchLength`; the message contains no window text), `Matcher_MaxMatchLengthBelowOne_Throws`,
  `Matcher_PendingFromOutOfRange_Throws`: fail if bad spans are clamped or the window is quoted.
- `Matcher_OverlappingOccurrences_UnionMasked` (`abcd` and `cdef` in `abcdef`): fails with plain
  non-overlapping selection; `Matcher_EqualSpans_OneMaskByTieOrder`.
- `Matcher_Flush_Masks`, `Matcher_SurrogatePairNotSplit`.
- `Release_MasksCompleteMatchesInTail` (fails if `Release` skips resolution),
  `Release_PartialPrefixReleasedUnmasked` (pins the residual limit), `Release_ThenNextChunk_Continues`,
  `Release_EmptyTail_ReturnsEmpty`, `Flush_AfterRelease`, `HasHeld_TracksTail`.
- `NoMatchers_SameAsOneDotZero` (random finds, texts, chunkings: every emitted piece identical to the
  1.0 constructor's): fails if `[]` takes the new path.

**R2. Runners.** Files: `IPtyRunner.cs`, `UnixPty.cs` (new overload + line 148 only), `WindowsPty.cs`,
`FallbackPty.cs`, `MatcherCarrier.cs` (new, internal), `RedactingPty.TestHost/Program.cs` (a test
matcher mode); tests in `PtyRunnerTests.cs`, `FallbackPtyTests.cs`. The `RedactionOptions` overload
on every runner.
- `Run_WithMatcher_MasksChildOutput` (each real runner through the test host, and `FallbackPty`):
  fails if an overload calls `Run(argv, replacements)` without the carrier.
- `Fallback_OneMatcher_StdoutAndStderr_BothMasked`: fails if only one stream gets the matcher.
- `Run_MatcherThrows_NothingAfterFailure_MessageHasNoText` (`UnixPty` through the test host, and
  `FallbackPty`; a matcher that throws on the second chunk, the child still printing): no byte of the
  second chunk or later reaches the output, the child is reaped, the rethrown message holds no output
  text. Fails if the tail is flushed on error or the relay stops draining.
- `CustomRunner_DefaultOverload_EmptyDelegates` / `_WithMatchersThrows`: fail if the default ignores
  matchers.
- Report: R1's frozen-span diff against 5d9a8fa, empty (`docs/briefs/r1-dotnet10-idioms.md:45-65`).

**R2b. Input-wait release (D2).** Files: `HoldReleaser.cs`, `IInputWaitProbe.cs`,
`LinuxInputWaitProbe.cs`, `MacInputWaitProbe.cs` (new, internal), `UnixPty.cs` (read loop, after the
fork only), `LinuxPty.cs`/`MacOSPty.cs` untouched; TestHost child modes (`prompt`, `password`, `busy`,
`two-threads`); tests `HoldReleaserTests.cs`, `InputWaitProbeTests.cs`, `PtyRunnerTests.cs`.
- `HoldReleaser`, fake clock and probe: `NoHeldText_NoCheck`, `FirstCheckAt50msQuiet_ThenEvery100ms`,
  `OutputResetsQuiet`, `OptionOff_NoCheck`, `ProbeFalse_NeverReleases` (fails if a timeout releases:
  the option (d) the owner rejected).
- `LinuxInputWaitProbe` over a fake `IProcFs`: `AllThreadsBlockedInReadOnSlave_True`,
  `ReadOnDevTty_ControllingTerminalIsSlave_True` (fails with a readlink-only rule),
  `ReadOnDevTty_OtherControllingTerminal_False`, `ReadOnAnotherPts_False`, `ReadOnAPipe_False`,
  `OneThreadRunning_False`, `SleepingInClockNanosleep_False`, `UnreadableSyscallFile_False`,
  `CommandNameWithParenAndSpaces_ParsedAfterLastParen`, `MalformedStat_False`,
  `TcgetpgrpFailure_False`, `NotInForegroundGroup_Ignored`, `UnknownArchitecture_NoProbe`.
- Real PTY through the test host, a matcher with `MaxMatchLength` 5000 and `PendingFrom` 0 standing in
  for a multi-line vault secret (tests wait on concrete conditions: text in the output, a check count,
  a `/proc` state; a deadline only fails the test):
  - `RealPty_YesNoPrompt_ReachesOutput` (Linux): `Continue? [y/N] ` appears before any input is sent;
    fails without the release.
  - `RealPty_PasswordPrompt_ReachesOutput` (Linux, macOS): `stty -echo; read`.
  - `RealPty_GetpassOnDevTty_ReachesOutput` (Linux, macOS): a test-host mode that opens `/dev/tty`,
    turns echo off and reads it, as `getpass` does (fd ≠ 0); fails on Linux with a slave-path-only
    rule. (The R2b report adds `python3 -c 'import getpass; getpass.getpass()'` where `python3` exists.)
  - `RealPty_BusyChildPaused_TailHeld` (Linux): after the child is in `clock_nanosleep` and 3 check
    lines are in the check file, the held text is absent; fails if quiet time alone releases.
  - `RealPty_TwoThreads_OneReadsTtyOneRuns_Held` (Linux): fails if one blocked reader suffices.
  - `RealPty_MacOS_YesNoPrompt_StaysHeld` (macOS, pins the stated limit), and
    `WindowsPty_NoProbe_HeldUntilExit` (Windows).
- Report: the frozen-span diff, empty; which of `bash`, `python3 input()`, `getpass`, `ssh`, `sudo`,
  `gpg` prompts are detected on Linux and macOS (and so whether ICANON is right for them).

**R3. Package.** Baseline 1.0.3 (after G2's first tag), `dotnet pack` output (validation passes), NativeAOT publish of the
test host with 0 warnings, README section, CI's nine legs green. Then G1, G2.

### tswap (one commit per task)

**T1. `FingerprintScanner`.** File `TswapCore/Fingerprints/FingerprintScanner.cs`; test
`TswapTests/FingerprintScannerTests.cs`.

```csharp
public sealed class FingerprintScanner
{
    public static FingerprintScanner Build(IEnumerable<(string Name, bool IsPrevious, FingerprintSet Set)> sets, FingerprintKeys keys);
    public int MaxRawLength { get; }                             // see below
    public void Scan(ReadOnlySpan<char> text, List<FingerprintHit> hits);   // text coordinates, deduped
    public int PendingFrom(ReadOnlySpan<char> text);
}
```

Design: prefix hashes over the text (window hash `H[i+L] − H[i]·b^L`, the same value as
`RollingHash.Of`), a per-length bitset prefilter, HMAC confirmation exactly as `FingerprintIndex`,
including Stage 2 task 1's rule by calling `FingerprintIndex.SplitsASurrogatePair` (no window starting
on a low surrogate or ending on a high one).
Each entry gets a class from data already stored: *no-whitespace* (whitespace-stripped entries, and
plain entries of a set without one), *base64 alphabet*, *base64url alphabet*, *free* (a plain entry of
a set that has a whitespace-stripped one: it may hold line breaks; its whitespace count is exactly
`W = L − S`). A start is tried for a length only while the class allows (a run of allowed characters
at least that long; for free entries, exactly `W` of CR, LF, space, tab in the window of the view
being scanned). Free entries
are also tried on a view with each `\r\n` folded to `\n`, hits mapped back to raw spans that include
the folded `\r`s. `MaxRawLength` = max over entries of `L`, or `L + W` for free entries (each folded
break adds at most one raw character). `PendingFrom`: the earliest start whose visible part fits some
class (no-whitespace and base64 classes: inside the trailing run; free: at most `W_max` of CR, LF,
space, tab counted on the **folded** view, the one whitespace set used everywhere; this always holds
at least the last character when free entries exist, so a trailing `\r` awaiting its `\n` is never
emitted early), and no earlier than `text.Length − (cap − 1)`; caps and `W_max` rounded up to a
multiple of 256 ("Hold-back as a timing channel"). `PendingFrom` reads no hash, bitset or HMAC.
Equal-span hits are reported once, in tie order: name ordinal, current before previous, kind.
- `Scan_RawHits_EqualFingerprintIndexScan` (property: random vaults with multi-line, burned and
  previous values, texts with every variant planted; hit sets equal, folded hits excluded): fails on
  any unsound pruning (e.g. `=` missing from the base64 class, a whitespace plain entry classed
  no-whitespace).
- `Scan_MultiLine_Onlcr_Found`, `Scan_CrLfValue_OnlcrOutput_Found`, `Scan_CrLfValue_PipeOutput_Found`
  (spans cover the raw text): fail without the folded view or with wrong mapping.
- `Scan_CrLfValue_LfOutput_NotFound`: pins a documented gap.
- `MaxRawLength_PemSized_IncludesFoldSlack` (3,300-char value, 51 line breaks): fails if it uses
  `FingerprintIndex.MaxLength`.
- `PendingFrom_IsSound` (property: for every planted occurrence and every cut inside it,
  `PendingFrom(text[..cut]) <= start`): fails if pruning is too eager.
- `PendingFrom_SingleLineVault_TrailingSpace_HoldsNothing`: fails if it returns the length bound.
- `PendingFrom_IsSound` plants folded `\r\n` occurrences with cuts between `\r` and `\n`;
  `PendingFrom_TrailingCr_HeldWhenFreeEntriesExist` (GLM M1).
- `PendingFrom_IndependentOfValues` (two vaults with the same class and length profile, different
  values: identical results on random texts) and `PendingFrom_CapsQuantised` (a 300-char longest
  value holds as a 512 cap): fail if the hold depends on hashes or exact lengths.
- `Scan_DuplicateValues_OneHitPerSpanInTieOrder` (two names, one value; a current equal to its
  previous).
- `Scan_RollingHashCollision_NoHitWithoutHmac`, `Scan_WindowSplittingASurrogatePair_NoHit` (Stage 2's
  case, value bytes `61 62 FF` against `ab😀`).

**T2. `FingerprintStreamMatcher` and the package.** Files `TswapCli/FingerprintStreamMatcher.cs`,
`TswapCli/TswapCli.csproj` (`1.1.0-local.N` until G2); test `TswapTests/FingerprintStreamMatcherTests.cs`
(through the real `StreamRedactor`).
- `Matcher_OtherSecret_AcrossChunks_Masked`, `Matcher_PreviousValue_LabelledPrevious`,
  `Matcher_BurnedValue_StillMasked`: fail if labels or sets are built wrong.
- `Matcher_TwoThreads_SameResults`: fails with shared mutable buffers.
- `Matcher_EmptyIndex_MaxMatchLengthOne`.
- `Matcher_ChunkSplitInsideCrLf_StillMasked` (a multi-line secret through ONLCR, a chunk ending on the
  `\r`): fails if the trailing `\r` is emitted.

**T3. `run` decrypts only what it substitutes** (needs Stage 2 tasks 1-4). File `RunCommand.cs` only
(decryption scope: the `runner.Run` call and `FakePty` change in T4); test
`TswapTests/RunMinimumDecryptionTests.cs` (the store's `ValueDecrypted` seam).
- `Run_DecryptsOnlyItsTokens` (six secrets, format 3; `{{a}} {{b:previous}}` → exactly (a, current)
  and (b, previous), and nothing from building the index): fails if `ctx.LoadSecrets` comes back.
- `Run_FileMarkers_DecryptOnlyMarkedVersions` (markers `c`, `d:previous`): fails if files are filled
  from a full load.
- `Run_TokenTwice_DecryptedOnce`.
- `Run_MissingToken_MessageUnchanged_NothingElseDecrypted`, `Run_NoPreviousValue_MessageUnchanged`.
- `Run_Format2Record_OnlyThatRecordDecrypted` (before a reindex) and `Run_FormatTwoToken_WarnsOnce`
  (Stage 2's `get`/`apply` text with `n` = records `run` named, after the child's output; no name,
  file name or value in it): fails without the warning or with a vault-wide count.
- `Run_UnreadableNamedRecord_FailsNamingFile_NoChild` and
  `Run_UnreadableOtherRecord_WarnedAndRuns` (the unreadable-record rule).
- `Run_DisposesVaultViewAfterChild` (through a `VaultView` disposal seam if Stage 2 has one, else by
  review).
- Unchanged and passing: `RecordConflictTests` (no input changes), `PreviousValueTests`,
  `PreviousValueWarningTests`, `RunFileTokenTests`.

**T4. `run` masks the vault; the coverage warning.** Files `RunCommand.cs`, `TswapCli/RunCoverage.cs`,
`RunFileTokenTests.cs` (`FakePty` only); test `TswapTests/RunVaultRedactionTests.cs`.
Warning (stderr, identical before the child starts and after it exits, my call: one text to grep):
`Warning: <n> record(s) are not fully fingerprinted[, <m> can't be read]: 'run' masks the secrets
it substitutes and the fingerprinted values, not these. Ask the user to run {fix}.` ({fix} as Stage
2 writes it, `ElevatedCommand.For(prefix, "vault reindex")`.)
Plus one line when `OlderVariantSet > 0` (unreachable at variant set 1; tested on `RunCoverage` with a
built `VaultMetadata`). If the process ends through the signal path, the second line may be missing
(my call: the signal path exits at once).
- `Run_OtherVaultSecret_Masked` (the fake child prints a secret nobody substituted): fails if the
  matcher isn't passed.
- `Run_OtherSecret_Base64AndStripped_Masked`, `Run_OtherSecretsPreviousValue_Masked`.
- `Run_PemSizedOtherSecret_OnlcrAndBase64_Masked` (`FakePty.Onlcr`, 4096-char chunks, the split
  inside the fold slack): fails if `MaxMatchLength` ignores the slack or folding is missing.
- `Run_PartlyFingerprinted_WarnsTwice_RunsAndMasksFingerprinted` (per D1; exit code passed through):
  fails if the warning appears once, if `run` refuses, or (D1) if the fingerprinted secret is shown.
- `Run_UnreadableRecord_InWarning`, `Run_FullyFingerprinted_NoWarning`,
  `Run_ChildFails_WarningStillAfterOutput`.
- Pinned gaps: `Run_OtherSecretBase64UrlPadded_CoreMasked_PaddingShown`,
  `Run_SecretAddedDuringChild_NotMasked`.
- `Run_NestedAndOverlappingTokenValues_FullyMasked` (`{{a}}` inside `{{b}}`, and two overlapping
  values): every character of each masked.
- `Run_MatcherFailure_NoOutputAfterIt_MessageClean` (a `FakePty` path whose matcher throws): `run`
  exits non-zero, its stderr message contains no child output.
- The existing `RunFileTokenTests`, now on the with-matcher path through `FakePty`, are the pin that
  plaintext plus matcher never shows a form the 1.0 path masked.
- `EndToEnd_Run_PromptVisible_WithPemInVault` (Linux, the same harness: `run ./prompt.sh {{token}}`
  with a script at `printf "Continue? [y/N] "; read x` and a multi-line secret in the vault; the
  prompt appears before input is sent): fails if `run` doesn't set `ReleaseWhenAwaitingInput`.
- `EndToEnd_Run_OtherSecretMasked_RealPty` in `EndToEndTests` (the outer-PTY harness at
  `EndToEndTests.cs:341`, built NativeAOT binary): fails if trimming or default-interface dispatch
  breaks the matcher under AOT.

**T5. Performance (numbers recorded in the PR and the release notes).** Test
`TswapTests/RunRedactionThroughputTests.cs`, `[Trait("Category", "Perf")]`, returns early with a
message unless `TSWAP_PERF=1`; Release; `StreamRedactor` directly in 4096-char chunks; prints:

| Case | Vault | Output |
|---|---|---|
| before | 1.0 redactor, a substituted token's forms (#251 list) | 100 MB log-like; 100 MB base64-heavy |
| after A | same plaintext + matcher, 200 secrets × 4 variants (16-64 chars, 10 multi-line 1.7-3.3 K) | same two |
| after B | 2,000 secrets (16-128, 1 % multi-line) | same two |

Also: Mchars/s; `MaxMatchLength`; mean characters held on log text; startup (unlock excluded) of
`LoadSecrets` vs `LoadMetadata` + `FingerprintKeys` + `Build` for B; one case with 5,000-char values
(the probe's 200 × 16-5,000); the CPU cost of one `LinuxInputWaitProbe` check against a group of 1
and of 20 processes (it runs at most every 100 ms while holding). Headroom is thin (prototype 24 vs
≥ 20; 1.3 vs ≥ 1) and "after A" includes the multi-line set. Targets per D3; **a miss is reported to
the owner with the profile, never loosened or tuned away silently.** Case → number in the PR.

**T6. Docs, version, owner check.** `docs/security-model.md` (`:79` row and the `run` limits, the
table above in short), `docs/commands.md` (`run`), `docs/release-notes/v0.3.0.md` (run section:
minimum decryption, vault-wide masking, the warning, the gaps, D2's prompt release per platform);
`docs/security-model.md` states with the other limits: the residual limit in its general form (D2);
the per-platform prompt release (macOS only no-echo prompts; Windows and redirected output hold); the
stdout/stderr split under `FallbackPty`; the hold-back timing channel (256-character buckets, whether
a whitespace secret exists). **The spec** (`docs/superpowers/specs/2026-11-01-import-story-design.md`,
its Stage 3 section, Stage 3's to edit as Stage 2's task 10 does for its sections): owner-amendment
blocks for D1 (overrules `:247-251`), D2 (prompt release, residual limit), D3, D4, the
`RedactionOptions` API shape, the coverage table in short.
`TswapCli.csproj` to 1.1.0 after G2 (clear the local feed from the restore). Prompt text unchanged
(`prompt-hash` stable). Owner check: `tswap run ssh <host>` with a PEM in the vault, on Linux and macOS.

## Review focus

1. Nothing decrypted beyond the substituted versions, file markers and `:previous` included
   (`RunMinimumDecryptionTests`); format 2 exception documented.
2. RedactingPty: frozen spans byte-identical; `UnixPty` changed only at line 148 plus the overload;
   the 1.0 path untouched (`NoMatchers_SameAsOneDotZero`); package validation output.
3. Soundness: no partial value ever emitted (`PendingFrom_IsSound`, the straddler test, the
   PEM-sized tests); `MaxMatchLength` honest for folded hits.
4. Overlap resolution: longest, leftmost, plaintext first; replacement text never rescanned.
5. Thread safety under `FallbackPty`; `FingerprintKeys` disposed after the child.
6. Coverage claims in the docs match the table and the tests (including the pinned gaps).
7. Warning text, twice, `run` keeps working (D1); `run`'s stderr order; the unreadable-record rule;
   the format 2 line counts only named records.
8. D2: time never releases held text; every probe failure holds; the `/dev/tty` rule (controlling
   terminal = slave, compared by device numbers); probes, `ptsname` and `stat` run only in the
   parent; `Release` masks complete matches first; the residual limit documented in its general form.
9. Fail closed: no output after a matcher failure, exception texts without output text.
10. `PendingFrom` depends on no hash and on quantised caps only (the timing channel).
11. `writing-dotnet10-code` defaults in new code.

## Risks

- **Throughput on base64-heavy output** (probe: about 1 Mchar/s): a 100 MB dump takes minutes;
  backpressure slows the child, nothing is lost. D3.
- **Prompt detection misses** (D2): programs waiting in `poll`/`select` on the terminal, macOS
  `y/N` prompts, Windows, and kernels where `/proc/<pid>/syscall` is unreadable keep their prompt
  hidden behind a held multi-line tail (safe, not silent: R2b reports which programs are detected).
- **Partial release** (D2 residual limit): a secret split by an input wait, or by another thread or
  a background job, has its first part shown.
- **Release coupling:** tswap's PR waits for G2; local packs must never use the release version.
- **Two scanners** (`FingerprintIndex` for Stage 2, `FingerprintScanner` here): the equality
  property test keeps them aligned; Stage 2 may adopt the scanner later.
- **Stage 2's contract drifts** after its approval: S1-S7 are what `run` relies on; a change goes to
  the owner before either brief continues.
- **macOS ICANON** (pending owner confirmation): if a D2-named prompt (ssh, sudo, gpg) clears ICANON,
  R2b's report shows it and the condition is dropped.
- **Default interface member and package validation** (fallback above).
