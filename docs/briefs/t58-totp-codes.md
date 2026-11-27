# Brief T58: TOTP codes from a stored seed; the seed only with sudo (#374)

Milestone 0.3.3. Base: `origin/main` at e86f028 (this brief's branch, `brief/t58`, starts there). Read AGENTS.md and
CLAUDE.md first (AGENTS.md "Lock files", "Privilege Boundary", "Token Substitution", "Files with secrets"), then:
`TswapCli/Commands/RunCommand.cs` (`Execute` from the token checks to the matcher, `EnvToken`, `BracedNameRegex`);
`TswapCore/Validation.cs:1-60` and `:160-175`; `TswapCore/Apply.cs` (all); `TswapCore/Check.cs` (`MarkerRegex`,
`CheckMarkers`); `TswapCore/ISecretLookup.cs`; `VaultView.ResolveToken` and `Find` (`TswapCore/VaultView.cs:66`,
`:183`); `TswapCli/Commands/NamesCommand.cs`; `TswapCli/CliJson.cs`; `TswapCore/SecretInfo.cs`;
`TswapCore/Keyring/RecordMetadata.cs`; the format 3 layout comment in `TswapCore/Keyring/SecretRecordCodec.cs:60-80`;
`TswapCore/Fields/FieldSet.cs:5-18` (the extension registry); `TswapCore/Keyring/RecordWrites.cs`;
`RecordVaultStore` `:860-900` (the write dispatch), `Reindex`/`IsCurrent` (`:1401`, `:1434`), `NextRecord` (`:1530`),
`PrepareV3` (`:2056`); `TswapCore/Broker/BrokerSecrets.cs:66-150`; `TswapCore/Broker/SshAgent/SshKeys.cs:80-100`;
`TswapCli/Commands/GetCommand.cs`, `ApplyCommand.cs`, `RotateCommand.cs`; `TswapCore/Prompt.cs`; and the tests
`RunEnvTests` (its `RecordingPty` harness), `MetadataCommandTests.Names_DecryptsNoValue`, `RecordWritesTests`,
`FieldTokenRefusalTests`, `TswapTests/Build/DependencyPinningTests.cs`.

One commit per task, test first, a break-it-once check per key test (name in the commit message which line you
changed and which test failed), `./runtests.sh --unit` after each task, the full `./runtests.sh` at the end. No
hardware suites, `ykman`, `sudo`, real YubiKeys or `~/.config/tswap`. Commits end with
`Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, explicit-path commits, no push, merge or rebase; stop and
report when the brief can't be built as written. **No existing test's assertions change except the four this brief
names** (Task 2: `FieldTokenRefusalTests.MalformedMessage` and `.MarkerMessage`, `RunEnvTests.Exactly` and its
`{{x:bogus}}` row); the controller sanctions them because each pins the list of token suffixes, which gains `:totp`.
Adding a parameter at a call site is not an assertion change. Tests never read the real clock: every time is a fixed
`TimeProvider` (`FleetMachine.Time`, `CommandContext.Time`), and no test sleeps. No test, message or log prints a seed,
a URI or a code it didn't compute from a public test vector. A parallel brief (T59) owns `.github/workflows/release.yml`,
`renovate.json5`, the release-packaging tests and `docs/BROKER.md`: don't touch them.

## What is wrong (evidence)

The owner stored the Certum code-signing token's whole `otpauth://totp/...` URI as `certum-totp` (#368). Reproduced
on this base (Debug build, test mode, a temp config folder, the RFC 6238 SHA1 seed in a URI with
`algorithm=SHA256`):

| Command (no sudo) | Today |
|---|---|
| `run /usr/bin/test '{{demo-totp}}' = "$URI"` | exit 0: the child got the whole URI, seed included (`RunCommand.cs:149` resolves the stored value, `VaultView.ResolveToken`, `VaultView.cs:183`) |
| `run … '{{demo-totp:totp}}'` | `Unknown token '{{demo-totp:totp}}': the only suffix is ':previous' …` (`Validation.cs:15-21`) |
| `run … '{{@f.yaml}}'` with `# tswap: demo-totp:totp` | `Unknown marker … the only suffix is ':previous'.` (`Apply.cs:77-80`) |
| `tswap totp demo-totp` | `Unknown command: totp` |
| `names`, `names --json` | no sign the record is a TOTP seed (`NamesCommand.cs:108`, `CliJson.cs:12`) |

So every non-sudo consumer of the record gets the seed, and nothing can hand out a 30-second code instead. The broker
reads values the same way (`BrokerSecrets.cs:86`, `:128`, `SshKeys.cs:89`).

## Owner decisions and controller defaults

Owner, 2026-11-27 (#374): "I stored the certum otpauth url simply as the whole URL. I imagine tswap recognising it is
an OTP auth url and some option to give a totp code with remaining time at issue. I guess that should be the default
behaviour for a totp code. I also guess tswap names should mark it as totp, and there should be an option for
accessing the seed, but only with sudo."

| # | Decision | Source |
|---|---|---|
| D1 | A value whose trimmed text starts with `otpauth:` (case ignored) is an **otpauth record**. Recognition is generous, the parse strict: an otpauth record that doesn't parse as a usable TOTP URI is refused wherever a code would be given, never passed on as itself | owner (recognise); controller (generous/strict split) |
| D2 | In `run` (`{{name}}`, `--env`, `{{@file}}` markers) an otpauth record gives its **current code**; `{{name:totp}}` / `# tswap: name:totp` is the explicit form, and the only way a **bare Base32** value becomes a code (a bare value is never auto-recognised: any random value may be Base32) | owner (default); controller (bare only via `:totp`, as #374 proposed) |
| D3 | `{{name:previous}}` of an otpauth previous value gives that seed's current code | controller default; owner may change |
| D4 | `tswap totp <name>` (no sudo): the code alone on stdout, the seconds it stays valid on stderr | owner (code + remaining); controller (format) |
| D5 | `names` marks otpauth records from metadata stored at write time; `names` decrypts no value, as today | owner (mark); controller (how) |
| D6 | The seed only with sudo: `sudo tswap get` prints the stored URI unchanged; no non-sudo path hands it out (table in Task 2) | owner |
| D7 | `sudo tswap apply` fills markers exactly as `run`'s `{{@file}}` does (codes), so the two documented forms of one file agree; the seed is `get`'s | controller default; owner may change (to "apply writes the URI") |
| D8 | The broker refuses otpauth records (routes, templates, ssh-agent); a broker that hands out codes is a later feature | controller default; owner may change |
| D9 | `rotate` (random value) refuses an otpauth record; `ingest --rotate` (the issuer's new seed) works | controller default; owner may change |
| D10 | `digits` 6 or 8 only (the Key URI Format allows exactly these; Otp.NET would take 1-10, so 7 is refused by tswap, not by the library) | controller, from the spec |

## Task 1: parse and compute (Otp.NET, pinned)

**Library.** Otp.NET 1.4.1 (kspearrin/Otp.NET, MIT, published 2025-12-01, targets up to net10.0, no dependencies,
not archived). It implements RFC 4226/6238 (HMAC-SHA1/256/512, dynamic truncation, 1-10 digits, any step > 0) and is
the library #374 names. Its clock seam is an explicit `DateTime` (`Totp.ComputeTotp(DateTime)`,
`Totp.RemainingSeconds(DateTime)`; both read only `Ticks`, so pass `now.UtcDateTime`); its parameterless overloads read
`DateTime.UtcNow` and are never called. Its `Base32Encoding.ToBytes` is lax (it trims any number of `=`, accepts lower
case, ignores trailing bits and decodes one character to zero bytes), so tswap validates the text first (below) and
hands the library only canonical text. It has no URI parser; the parse below is tswap's (it is input validation, not
crypto). `<PackageReference Include="Otp.NET" Version="[1.4.1]" />` in `TswapCore/TswapCore.csproj`, with a comment
in the style of the others (what it is used for, licence, pinned); regenerate the three `packages.lock.json` on Linux
x64 as AGENTS.md "Lock files" says, and show the lock-file diff (Otp.NET only) in the report. `renovate.json5` needs
nothing. The Release `dotnet publish TswapCli/TswapCli.csproj -c Release` must stay free of IL2xxx/IL3xxx warnings;
if Otp.NET brings any, stop and report.

**New `TswapCore/Totp/`.** `ValueKind` (`None`, `Totp`, `OtpAuthUnusable`); `OtpAuthUri.IsOtpAuth(string value)`
(D1); `TotpSeed` (key bytes, algorithm, digits, period; `IDisposable`, zeroes its key; Otp.NET's internal copy can't
be zeroed, like the resolved strings `VaultView` keeps); `TotpSeed.FromUri(string value)` and
`TotpSeed.FromBase32(string value)`, both throwing `TotpSeedException(string reason)` with a reason from the table
below and nothing else; `TotpCode Compute(TotpSeed, DateTimeOffset now)` → `record TotpCode(string Code,
int RemainingSeconds, int Period)`; `ValueKind Classify(string value)` (`None` unless D1; `Totp` when `FromUri`
succeeds; else `OtpAuthUnusable`).

**The parse (`FromUri`), from the Key Uri Format (google/google-authenticator wiki) and RFC 3986/4648.** On the value
trimmed of `char.IsWhiteSpace` at both ends:

| Part | Accepted | Otherwise (reason) |
|---|---|---|
| Scheme | `otpauth://`, case ignored (RFC 3986 3.1) | R1 `the URI doesn't start with otpauth://` |
| Type | up to the first `/`, `?` or `#`: `totp`, case ignored (3.2.2). `hotp` | R2 `HOTP (counter-based) URIs aren't supported`; anything else (userinfo, port, other words) R3 `the URI's type isn't totp` |
| Fragment | none | R4 `a '#' fragment isn't allowed` |
| Label | after `/` up to `?`: not used, not checked; may be empty or absent | - |
| Query | split on `&`; empty pieces skipped; name up to the first `=` | no query or no `secret`: R5 `the secret parameter is missing` |
| Known names | exactly `secret`, `algorithm`, `digits`, `period` (ordinal) | the same word in another case: R6 `parameter names are lower case: 'algorithm'` (the known spelling, never the URI's); twice: R7 `the parameter 'digits' appears more than once`; no `=`: R8 `the parameter 'period' has no value` |
| Other names | ignored, not decoded (`issuer`, `image`, `counter`, vendor additions) | - |
| Values of known names | percent-decoded (`%` and two hex digits; the result strict UTF-8); `+` is a literal `+` (RFC 3986 has no `+` rule) | R9 `a parameter has a malformed percent-encoding` |
| `algorithm` | `SHA1` (default), `SHA256`, `SHA512`, case ignored | R10 `algorithm must be SHA1, SHA256 or SHA512` |
| `digits` | exactly `6` (default) or `8` (D10) | R11 `digits must be 6 or 8` |
| `period` | 1-3 ASCII digits, value 1-300 (default 30) | R12 `period must be a whole number of seconds from 1 to 300` |
| `secret` | Base32 as below, no spaces | B1-B5 |

The first failing check wins, in this order: R1, R2/R3, R4, the query's pieces left to right (R6-R9), R5, then
the values (R10-R12, B1-B5).

**Base32 (RFC 4648 section 6), both forms.** `FromBase32` first removes U+0020 spaces (a bare seed is often written in
groups) and trims; inside a URI no space is allowed. Then: letters A-Z in either case and digits 2-7; `=` only as a run
at the end, and only when the padded length is a multiple of 8 and the run is 1, 3, 4 or 6 long (what 5-byte groups
leave); unpadded length mod 8 in {0, 2, 4, 5, 7}; the unused low bits of the last character zero (canonical, RFC 4648
3.5); at least 16 characters, 80 bits (the spec's own example `JBSWY3DPEHPK3PXP` is 80 bits; RFC 4226 asks 128, but
80-bit seeds are common). Checked in the order B1, B3, B2, B4, B5. Reasons: B1 `the seed isn't Base32 (A-Z and 2-7,
with '=' padding only at the end)`, B2 `the seed's length isn't a Base32 length`, B3 `the seed's '=' padding is wrong`, B4 `the seed isn't canonical Base32 (its
last character has unused bits set)`, B5 `the seed is shorter than 16 Base32 characters (80 bits)`. The canonical text
(upper case, no padding) goes to `Base32Encoding.ToBytes`; the decoded length is checked against `5 * length / 8`.

**Tests** (`TswapTests/Totp/`), all with fixed `DateTimeOffset`s:

| Test | Input | Outcome |
|---|---|---|
| RFC 6238 vectors | the appendix B seeds as Base32 (SHA1 `GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ`, SHA256 the 32-byte seed, SHA512 the 64-byte seed, padded and unpadded), 8 digits, period 30, at 59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000 | the 18 codes of the RFC (SHA1 at 59: `94287082`, SHA256 `46119246`, SHA512 `90693936`; …) |
| SHA256 URI | `otpauth://totp/X:y?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=SHA256` at 1111111111 | `584430`, not SHA1's `050471` (the Certum mistake) |
| Window edges | the SHA1 URI, 6 digits, at 1111111109.999 / 1111111110.000 / 1111111139.999 / 1111111140.000 | `081804` 1 s; `050471` 30 s; `050471` 1 s; `266759` 30 s |
| Period 60, digits 8 | the same seed with `&period=60&digits=8` | the code of step `t / 60`; remaining `60 - t mod 60` |
| Accepted spellings | `OTPAUTH://TOTP/…`, `algorithm=sha512`, `secret=gezd…` (lower), the SHA256 seed text with its padding as `%3D%3D%3D%3D` and `algorithm=SHA256`, no label, `issuer=` twice, unknown `image=…`, surrounding whitespace | parsed, same code as the plain form |
| Refusals | one row per reason R1-R12 and B1-B5 (`otpauth:totp/…`, `otpauth://hotp/…?counter=1`, `otpauth://u@totp/`, `…#x`, `?issuer=X`, `Secret=`, `digits=6&digits=6`, `&period&`, `secret=%G1`, `algorithm=SHA-256`, `digits=7`, `period=0`, `period=301`, `secret=GEZ1…`, length 17, `GEZD=GNB…`, the SHA256 seed text ending `GEZB` (canonical `GEZA`), `GEZDGNBVGY3TQ` (13, 8 bytes)) | `TotpSeedException` with exactly that reason; the message contains neither the URI nor the secret text (assert both absent) |
| Bare forms | `gezd gnbv gy3t qojq gezd gnbv gy3t qojq`, mixed case; the 32-byte seed's text with and without `====` | at 1111111111: `050471`; `201283` (SHA1, 6 digits, the bare defaults) |
| Classify | a password, a bare Base32 seed, the SHA1 URI, a hotp URI, ` otpauth:x` | `None`, `None`, `Totp`, `OtpAuthUnusable`, `OtpAuthUnusable` |
| No system clock | the sources under `TswapCore/` and `TswapCli/` | no call of `ComputeTotp()`, `RemainingSeconds()` or `WindowStart()` without an argument (a source scan) |

Break-it-once: map `SHA256` to `OtpHashMode.Sha1` (the SHA256 URI row and the SHA256 vectors fail); drop the trailing-bits
check (the B4 row fails).

## Task 2: codes in `run` and `apply`; the seed stays in

**Grammar.** A token is `{{NAME}}`, `{{NAME:previous}}` or `{{NAME:totp}}`; a marker `# tswap: NAME`,
`NAME:previous` or `NAME:totp`; one suffix at most (`:previous:totp` is an unknown suffix). Every spelling of the
grammar changes together: `Validation.TokenRegex` (`:9`), `ThrowIfUnknownTokenSuffix` (`:15-21`), the malformed-token
text (`:46`), `AnyTokenRegex` (`:168`); `Apply.MarkerRegex`, `AnyMarkerRegex` check, `ValidMarkerTail` (`:8`, `:15`) and
the two marker texts (`:73`, `:80`); `Check.MarkerRegex` (`:8`) and `CheckMarkers`' suffix split (`:156`);
`ToCommentProcessor.ExistingMarker` (`:16`); `SecretMatcher.ConsumedMarker` (`:290`); `RunCommand.BracedNameRegex`
(`:498`), the encoded-token decoding beside it, and `EnvToken`'s text (`:432`). New texts:
- `Unknown token '{{x:bogus}}': the suffixes are ':previous' (the value the last rotation replaced) and ':totp' (the current code of a TOTP seed).`
- `'…' is not a valid token: a token is {{NAME}}, {{NAME:previous}} or {{NAME:totp}}, and fields aren't substituted into commands.`
- `'…' is not a valid marker: a marker is # tswap: NAME, # tswap: NAME:previous or # tswap: NAME:totp, and fields aren't substituted into commands.`
- `Unknown marker '# tswap: x:bogus' (line N): the suffixes are ':previous' and ':totp'.`
- `the value must be exactly one {{name}}, {{name:previous}} or {{name:totp}} token`

**`CommandValues`** (`TswapCore/Totp/CommandValues.cs`): `sealed class CommandValues(ISecretLookup inner,
DateTimeOffset now) : ISecretLookup`, the one place a stored value becomes what a command is given. Every method
strips a `:totp` suffix before asking `inner`. `ResolveToken(token, where)`: the stored value of `name` or
`name:previous` from `inner`; then `:totp` → `FromUri` when `IsOtpAuth`, else `FromBase32`; no suffix (or
`:previous`) and `IsOtpAuth` → `FromUri`; otherwise the stored value as today. A code is computed at `now` (one clock
reading per command, so `{{x}}`, `{{x:totp}}` and a marker of `x` in one run get the same code) and cached per token. A
`TotpSeedException` becomes the `TswapException`
`'{{x}}': secret 'x' holds no TOTP seed tswap can use (<reason>), so nothing was substituted. The user can see the value with 'sudo tswap get x' and store a corrected one with 'sudo tswap add x'.`
(the token as typed, the marker form `'# tswap: x' (line N)` for a marker, the bare name for Task 3). `StoredForms(token)`:
for a token that gave a code, the stored value and the secret text as written in it and in canonical form, for
redaction.

**Wiring.** `run` wraps its view once (`new CommandValues(view, ctx.Time.GetUtcNow())`) and uses it for the tokens,
`--env` and `Apply.ApplySecretsReporting`; it redacts each token's result as today (a 6-digit code goes to the
short-value matcher, so it is masked as a whole number; an 8-digit one anywhere) and also every `StoredForms` entry,
under the same `[REDACTED: <token>]` label. `ApplyCommand` wraps its view the same way (D7). `get`, `field adopt` and
`export` keep the raw view.

**Every path that hands out a value without sudo**, after this task (Task 3 adds `totp`, Task 4 `rotate`):

| Path | For an otpauth record |
|---|---|
| `run` `{{x}}`, `{{x:previous}}`, `--env N={{x}}`, `{{@file}}` markers | the current code (D2, D3); unusable: refused before the child starts |
| `run` `{{x:totp}}` / `# tswap: x:totp` | the code; a bare Base32 value too; anything else refused |
| broker routes, templates, ssh-agent (`BrokerSecrets.cs:86`, `:128`, `SshKeys.cs:89`) | refused (D8): `BrokerSecretException` `secret 'x' is a TOTP seed (an otpauth:// URI); the broker doesn't hand out TOTP seeds`, value zeroed |
| `redact`, `tocomment`, `check`, `names`, `burned`, `field show` | no value, as today (`tocomment` writes `# tswap: x`, which `run` fills with the code) |
| `sudo get`, `sudo list`, `sudo export`, `sudo field adopt` | unchanged: the stored value (D6) |
| `sudo apply` | the code, as `run`'s files (D7) |

**Tests** (in-process, the `RunEnvTests` `RecordingPty` harness, `FleetMachine.Time` fixed at 1111111111.5 s; the
SHA1 URI unless said):

| Case | Outcome |
|---|---|
| `run tool {{t}}` | child argv `050471`; stored URI not in argv |
| SHA256 URI, `{{t}}` | `584430` |
| `{{t:totp}}` on a bare Base32 record (spaces, lower case) | `050471` |
| `{{t}}` on a bare Base32 record | the stored text, as today |
| `{{t:previous}}` after `ingest --rotate` (burned first) from the SHA1 URI to the SHA256 URI | `050471`; `{{t}}` `584430` |
| `--env OTP={{t}}` | env `OTP=050471` |
| `{{@f.yaml}}` with `code: ""  # tswap: t` and `c2: ""  # tswap: t:totp` | both lines `"050471"` in the filled copy |
| child prints the code, the URI and the secret text | output `[REDACTED: t]` three times; a longer number containing `050471` stays unmasked |
| `{{t:totp}}` on `hunter2-password`; `{{t}}` on a hotp URI; `# tswap: t` on `digits=7` | refused with the texts above (B1, R2, R11), exit 1, child not started, no seed or URI on stdout or stderr |
| `{{t:previous:totp}}`, `# tswap: t:previous:totp` | the new unknown-suffix texts |
| `check` on a file with `# tswap: t:totp` | `Ok`, no value decrypted |
| `sudo apply` (sudo bypass) on the file above | the code on both lines |
| `sudo get t` | the stored URI |
| a broker route, a template and an ssh-agent key naming `t` (`VaultBrokerSecretSource` over a record vault, as `BrokerTemplateCallTests` builds it; `SshKeys` likewise) | refused with the broker text; a plain secret still served |

Break-it-once: make `CommandValues.ResolveToken` return the stored value for an otpauth record (the `{{t}}` argv row
fails); drop the `StoredForms` redaction (the redaction row fails); remove the broker check (the broker row fails).

## Task 3: `tswap totp <name>`

`TswapCli/Commands/TotpCommand.cs`, registered after `run`: `Name` `totp`, `HelpUsage` `totp <name>`, `Description`
`Print the current code of a TOTP secret (an otpauth://totp/ URI, or a Base32 seed) and how long it stays valid; the
seed itself only with sudo get`, `RequiresSudo` false. It validates the name, unlocks, opens the view as `get` does,
resolves `name:totp` through `CommandValues` at `ctx.Time.GetUtcNow()` (so a bare Base32 seed works here, as with
`:totp`), and prints:
- stdout: the code and a newline, nothing else, so `code=$(tswap totp x)` captures exactly the code;
- stderr: `Valid for 17 more seconds (a new code every 30 seconds).` (`1 more second` in the singular);
- a burned value: before those lines, on stderr, run's `Warning: 'x' is a burned value — using it anyway; rotate it after use.`;
- format 2: `get`'s warning (`FormatTwoUse.Substitute`).
The refusals are Task 2's, naming the secret. No `--json` and no waiting for the next period (out of scope).

Tests (`FleetMachine.Time` fixed): the SHA1 URI at 1111111109.000 → `081804\n`, stderr `Valid for 1 more second (a new
code every 30 seconds).`; at 1111111110.000 → `050471`, 30 seconds; period 60 at an edge; a bare seed; burned (warning
first); a missing name; a password value (refused, value absent from both streams); exactly one value section
decrypted (the `_values` recorder of `RunEnvTests`). Break-it-once: print the remaining time on stdout (the stdout
assertion fails).

## Task 4: `names` marks otpauth records (metadata written with the value)

`names` already unlocks (`NamesCommand.cs:38`) and reads metadata only (`:43`, `Names_DecryptsNoValue`), so the kind
must be in the metadata. Format 3 metadata carries an extension list that every build keeps byte for byte (ruling 6,
`RecordMetadata.cs:33`); a value write keeps extensions it doesn't own (`FieldEdits.ForWrite`, `RecordWrites.cs:93`).
Because a build before this one keeps the extension when it writes a new value, the kind is bound to a version:

- **`ValueKinds` extension, type `0x0101`** (add it to the registry comment in `FieldSet.cs`): format byte `1`, count
  (1 byte, 0-2), per entry the version stamp (28 bytes, the codec's stamp encoding) and the kind (1 byte: 1 `Totp`,
  2 `OtpAuthUnusable`). Only otpauth versions get an entry; no entries, no extension.
- **Read** (`ValueKinds.Of(RecordMetadata, bool previous)`): the entry whose stamp equals that retained version's;
  none, an unknown kind byte or an extension that doesn't decode is `None` (display only: never an unreadable record).
  `SecretInfo` gains `ValueKind Kind` (the current version's), set in `SecretInfo.From`.
- **Write.** Where a new version is sealed, from the value in hand (no new decryption, so the decrypt counts of the
  write commands stay as they are): `RecordWrites.Next`/`NewVersion` get an optional `ValueKind newKind = None`
  (`RecordVaultStore.cs:881` passes `Classify` of `v.Value`, decoded as `Fingerprinter.Compute` decodes it), carry the previous version's entry when its stamp matches,
  drop the rest; `PrepareV3` (`:2056`, plaintext known) sets the extension from both retained values; both tombstone
  paths drop it. `RecordWritesTests.RecordWrites_MatchNextRecord_OnRandomStates` must include otpauth values in its
  random states (a test-input change) so it holds the two write paths equal here too. A folder still writing format 2
  stores no extensions: such a record is marked after `vault reindex`.
- **Reindex.** `IsCurrent` (`:1434`) is false when the extension disagrees with `Classify` of a retained value (the
  values are in hand), so `sudo tswap vault reindex` marks records written before this release and rewrites only those.
- **Output.** `names`: ` [TOTP]` or ` [OTPAUTH: unusable]` after the date, before ` [BURNED]`. `NameEntry` gains
  `string? Kind` (`"totp"`, `"otpauth-unusable"`; null otherwise, so omitted: the existing JSON is unchanged).
- **`rotate`** (D9): after `SecretRotation.Check` (`RotateCommand.cs:38`), a current kind other than `None` refuses:
  `'x' holds a TOTP seed, which comes from the issuer: 'rotate' would replace it with a random value. Store the new
  seed with '<source> | tswap ingest --rotate x'.` (`ctx.Prefix` for `tswap`).

**`certum-totp`** (written by 0.3.2, no extension): `run` and `totp` work at once (they decide from the value);
`names` marks it after `sudo tswap vault reindex` once, or after its next write (docs/commands.md says so).

Tests:

| Case | Outcome |
|---|---|
| `ingest` of the SHA1 URI, a hotp URI, a password | `names`: `[TOTP]`, `[OTPAUTH: unusable]`, nothing; `--json` `kind` the same; no value decrypted (`Names_DecryptsNoValue`'s recorder) |
| `ingest --rotate` URI → password (burned first) | no mark; `:previous` still gives a code (Task 2) |
| `add` (sudo bypass), `restore` back to the URI, export + import | marked |
| burned TOTP record | `… [TOTP] [BURNED]` |
| a record written as 0.3.2 writes it (the test writes the URI, then removes the extension through the codec) | no mark; `vault reindex` → marked, `Rewritten` 1 (the plain records are current) |
| an extension whose entry names a stamp the record no longer retains (an old build's rotate) | no mark |
| `rotate t` (burned) | refused with the text above; `ingest --rotate t` works |

Break-it-once: drop the stamp comparison in `ValueKinds.Of` (the stale-entry row fails); make `IsCurrent` ignore kinds
(the reindex row fails).

## Task 5: docs (last)

- `TswapCore/Prompt.cs` (ASCII only, `Prompt_IsAsciiOnly`): in "Commands you SHOULD use", after `run`: `` `%CMD% totp
  <name>` - Print the current code of a TOTP secret on stdout and how many seconds it stays valid on stderr. A code is
  a short-lived live credential, not the seed: use it at once, never store it; seeing a code needs no burn. ``; in the
  `run` bullet: a TOTP secret (an `otpauth://totp/` URI) gives its current code in `{{name}}` and in markers
  (`{{name:totp}}` for a secret stored as a bare Base32 seed); the seed is for the user only (`sudo %CMD% get`); the
  `names` bullet: `[TOTP]` marks them. A seen URI or seed is burned as any value. `prompt-hash` changes (no test pins
  it); the owner refreshes installed copies with `tswap prompt > …/SKILL.md` after the release.
- `docs/commands.md`: regenerate the block (`TSWAP_REGENERATE_DOCS=1`, `CommandReferenceIsCurrent`); a short section
  "TOTP secrets": recognition (D1), the token forms and D2/D3, the refusal reasons (the two tables of Task 1, condensed),
  `totp`'s output, `names`' marks, `vault reindex` for old records, `rotate` vs `ingest --rotate`.
- AGENTS.md: `totp <name>` in the No-sudo list; one sentence in "Token Substitution".
- `docs/security-model.md`: "What each command decrypts" gains `totp` (the one value it computes from); a short
  "TOTP secrets" note: a code is a live credential valid for one period, the seed never leaves without sudo, `run`
  masks code, URI and seed text, other records' seeds inside URIs are masked only as whole values (fingerprints cover
  whole values), the broker refuses otpauth records (D8; the `docs/BROKER.md` line follows after T59), and the Certum
  signing flow (#368) keeps its YubiKey code.
- Release notes are the controller's (there is no next-release file); the `vault reindex` note lives in commands.md.

## Out of scope

HOTP counters; waiting for the next period; `--json` for `totp`; broker routes that hand out codes; masking seeds
inside other records' URIs; the Certum CI signing flow (#368 keeps the owner's YubiKey and touch).
