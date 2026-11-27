# Brief T58: TOTP codes from a stored seed; the seed only with sudo (#374)

**The body below is authoritative.** It states every rule as amended in review rounds 1-5. The amendment history at
the end is a record of how the rules got here; where its wording differs from the body, the body wins.

Milestone 0.3.3. Base: `origin/main` at e86f028 (this brief's branch, `brief/t58`, starts there). Read AGENTS.md and
CLAUDE.md first (AGENTS.md "Lock files", "Privilege Boundary", "Token Substitution", "Files with secrets"). Then read:
- `TswapCli/Commands/RunCommand.cs` (`Execute` from the token checks to the matcher, `Redact` at `:175-184`,
  `EnvToken`, `BracedNameRegex`, `ViewSecretLine`);
- `TswapCore/Validation.cs:1-60` and `:160-175`; `TswapCore/Apply.cs` (all); `TswapCore/Check.cs` (`MarkerRegex`,
  `CheckMarkers`); `TswapCore/ISecretLookup.cs`;
- `VaultView.Find` and `ResolveToken` (`TswapCore/VaultView.cs:66`, `:183`); `TswapCore/VaultWriter.cs`;
- `TswapCli/Commands/NamesCommand.cs`, `BurnedCommand.cs`, `GetCommand.cs`, `ApplyCommand.cs`, `RotateCommand.cs`;
  `TswapCli/SecretRotation.cs`; `TswapCli/CliJson.cs`; `TswapCore/SecretInfo.cs`;
- `TswapCore/Keyring/RecordMetadata.cs`; the format 3 layout comment in `TswapCore/Keyring/SecretRecordCodec.cs:60-80`;
  `TswapCore/Fields/FieldSet.cs:5-18` (the extension registry); `TswapCore/Keyring/RecordWrites.cs`;
- `RecordVaultStore`: `:860-900` (the write dispatch), `SameValue` (`:934-956`), `Reindex`/`IsCurrent` (`:1401`,
  `:1434`), `NextRecord` (`:1530`), `Tombstone` (`:1601`), `WriteSnapshot` (`:1613`), `WriteAll`'s `PrepareV3` call
  (`:2018`) and `PrepareV3` (`:2056`);
- `TswapCore/Broker/BrokerSecrets.cs:66-150`; `TswapCore/Broker/SshAgent/SshKeys.cs:80-100`; `TswapCore/Prompt.cs`;
  `TswapCli/TswapCli.csproj`;
- the tests `RunEnvTests` (its `RecordingPty` harness), `MetadataCommandTests`, `WriteCommandDecryptionTests`,
  `RecordWritesTests`, `FieldTokenRefusalTests`, `PromptTests`, `EndToEndTests` (vault set-up, `:63-65`, `:340`),
  `TswapTests/Build/DependencyPinningTests.cs`.

One commit per task, test first, a break-it-once check per key test (name in the commit message which line you
changed and which test failed), `./runtests.sh --unit` after each task, the full `./runtests.sh` at the end. No
hardware suites, `ykman`, `sudo`, real YubiKeys or `~/.config/tswap`. Commits end with
`Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, explicit-path commits, no push, merge or rebase; stop and
report when the brief can't be built as written.

**No existing test's assertions change except these five:**
- Task 2: `FieldTokenRefusalTests.MalformedMessage` and `.MarkerMessage`, and `RunEnvTests.Exactly` with its
  `{{x:bogus}}` row. The controller sanctions them because each pins the list of token suffixes, which gains `:totp`.
- Task 4: `WriteCommandDecryptionTests.Rotate_DecryptsNoValue`, sanctioned by the owner (2026-11-27).

These stay unchanged, and the brief is written so they do: `MetadataCommandTests.Names_DecryptsNoValue` and
`Burned_DecryptsNoValue`, `PromptTests.Prompt_RunBullet_SaysScriptBlock`, `SecretValueOutputTests`, and
`Add_OtherVariantSet_DamagedCurrent_RefusesNamingTheFile_WritesNothing`. Adding a parameter at a call site is not an
assertion change, and neither is a test-input change the brief names.

Tests never read the real clock: every time is a fixed `TimeProvider` (`FleetMachine.Time`, `CommandContext.Time`),
and no test sleeps. The one exception is the published-binary tests of Task 6, which assert shapes only. No test,
message or log prints a seed, a URI or a code it didn't compute from a public test vector. `SpellingTests` (British
spelling) scans `.cs` files too, so new comments and strings are in its scope.

A parallel brief (T59) owns `.github/workflows/release.yml`, `renovate.json5` and the release-packaging tests: read
them, don't change them. Of `docs/BROKER.md`, this brief changes only the one line of Task 7 in "Limits (v1)"; T59
edits another paragraph.

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
reads values the same way (`BrokerSecrets.cs:86`, `:128`, `SshKeys.cs:89`). `rotate` on a burned record replaces the
seed with a random value without sudo.

## Owner decisions and controller defaults

Owner, 2026-11-27 (#374): "I stored the certum otpauth url simply as the whole URL. I imagine tswap recognising it is
an OTP auth url and some option to give a totp code with remaining time at issue. I guess that should be the default
behaviour for a totp code. I also guess tswap names should mark it as totp, and there should be an option for
accessing the seed, but only with sudo."

| # | Decision | Source |
|---|---|---|
| D1 | A value that contains `otpauth:` anywhere (case ignored) is an **otpauth record**. Recognition is generous and the parse strict. An otpauth record that isn't a clean, usable TOTP URI is refused wherever a code or value would be given without sudo, and never passed on as itself; that includes a value that only mentions a URI among other text | owner (recognise); controller (generous/strict split, "anywhere") |
| D2 | In `run` (`{{name}}`, `--env`, `{{@file}}` markers) an otpauth record gives its **current code**. `{{name:totp}}` / `# tswap: name:totp` is the explicit form, and the only way a **bare Base32** value becomes a code. A bare value is never recognised, because any random value may be Base32 | owner (default); controller (bare only via `:totp`, as #374 proposed) |
| D3 | `{{name:previous}}` of an otpauth previous value gives that seed's current code | controller default; owner may change |
| D4 | `tswap totp <name>` (no sudo): the code alone on stdout, the seconds it stays valid on stderr | owner (code + remaining); controller (format) |
| D5 | `names` marks otpauth records from metadata stored at write time; `names` decrypts no value, as today | owner (mark); controller (how) |
| D6 | The seed only with sudo: `sudo tswap get` prints the stored URI unchanged. No non-sudo path hands out a recognised record's seed (table in Task 2) | owner |
| D7 | `sudo tswap apply` fills markers exactly as `run`'s `{{@file}}` does (codes), so the two documented forms of one file agree; the seed is `get`'s | controller default; owner may change (to "apply writes the URI") |
| D8 | The broker refuses otpauth records (routes, templates, ssh-agent); a broker that hands out codes is a later feature | controller default; owner may change |
| D9 | `rotate` (random value) refuses an otpauth record, decided from the decrypted value, marked or not; `ingest --rotate` (the issuer's new seed) works | owner, 2026-11-27 |
| D10 | `digits` 6 or 8 and the three algorithms only: the Key Uri Format allows exactly these. Otp.NET would take 1-10 digits, so 7 is refused by tswap, not by the library | Key Uri Format |

## Task 1: parse and compute (Otp.NET, pinned)

**Library.** Otp.NET 1.4.1 (kspearrin/Otp.NET, MIT, published 2025-12-01, targets up to net10.0, no dependencies,
not archived). It implements RFC 4226/6238 (HMAC-SHA1/256/512, dynamic truncation, 1-10 digits, any step > 0) and is
the library #374 names.
- Its clock seam is an explicit `DateTime`: `Totp.ComputeTotp(DateTime)` and `Totp.RemainingSeconds(DateTime)` read
  only `Ticks`, so pass `now.UtcDateTime`. Its parameterless overloads read `DateTime.UtcNow` and are never called.
- Its `Base32Encoding.ToBytes` is lax: it trims any number of `=`, accepts lower case, ignores trailing bits, decodes
  one character to zero bytes and throws on a space. So tswap validates the text first (below) and hands the library
  only canonical text. It has no URI parser; the parse below is tswap's (input validation, not crypto).
- The namespace `TswapCore.Totp` shares its name with `OtpNet.Totp`: refer to the class through
  `using OtpTotp = OtpNet.Totp;`. Its constructor is `(byte[] secretKey, int step, OtpHashMode mode, int totpSize)`,
  period before algorithm before digits; say so in a comment at the call.
- `<PackageReference Include="Otp.NET" Version="[1.4.1]" />` in `TswapCore/TswapCore.csproj`, with a comment in the
  style of the others (what it is used for, licence, pinned). Regenerate the three `packages.lock.json` on Linux x64
  as AGENTS.md "Lock files" says, and show the lock-file diff (Otp.NET only) in the report.
- Renovate (`renovate.json5`, checked, not changed): an Otp.NET bump matches only the NuGet `rangeStrategy: 'pin'` rule
  and the majors rule. The only automerge rules are for test-package patches, the first GitHub Actions pin and
  global.json patches, and `config:recommended` adds none, so a bump is always an ordinary PR. `ci.yml` runs on
  `pull_request` without a path filter on the four-OS matrix (`ci.yml:26`), which runs this task's tests and Tasks 5
  and 6.

**New `TswapCore/Totp/`.**
- `ValueKind` (`None`, `Totp`, `OtpAuthUnusable`).
- `OtpAuthUri.IsOtpAuth(string value)`: true when the value contains `otpauth:` anywhere, case ignored (D1).
- `TotpSeed`: key bytes, algorithm, digits, period; `IDisposable`, zeroes its key. Otp.NET's internal copy can't be
  zeroed, like the resolved strings `VaultView` keeps.
- `TotpSeed.FromUri(string value)` and `TotpSeed.FromBase32(string value)`, both throwing
  `TotpSeedException(string reason)` with a reason from the tables below and nothing else.
- `TotpCode Compute(TotpSeed, DateTimeOffset now)` → `record TotpCode(string Code, int RemainingSeconds, int Period)`.
- `ValueKind Classify(string value)`: `None` unless `IsOtpAuth`; `Totp` when `FromUri` succeeds; else
  `OtpAuthUnusable`.

**The parse (`FromUri`), from the Key Uri Format (google/google-authenticator wiki) and RFC 3986/4648.** It works on
the value trimmed of `char.IsWhiteSpace` at both ends (U+FEFF is not white space):

| Part | Accepted | Otherwise (reason) |
|---|---|---|
| Start | the trimmed text starts with `otpauth:`, case ignored | R0 `the value holds an otpauth URI among other text; store the URI alone` |
| Scheme | `otpauth://`, case ignored (RFC 3986 3.1) | R1 `the URI doesn't start with otpauth://` |
| Type | up to the first `/`, `?` or `#`: `totp`, case ignored (3.2.2). `hotp` | R2 `HOTP (counter-based) URIs aren't supported`; anything else (userinfo, port, other words) R3 `the URI's type isn't totp` |
| Fragment | none | R4 `a '#' fragment isn't allowed` |
| Label | after `/` up to `?`: not used, not checked; may be empty or absent | - |
| Query | split on `&`; empty pieces skipped; name up to the first `=` | no query or no `secret`: R5 `the secret parameter is missing` |
| Known names | exactly `secret`, `algorithm`, `digits`, `period` (ordinal) | the same word in another case: R6 `parameter names are lower case: 'algorithm'` (the known spelling, never the URI's); twice: R7 `the parameter 'digits' appears more than once`; no `=`: R8 `the parameter 'period' has no value` |
| Other names | ignored, not decoded (`issuer`, also twice, `image`, `counter`, vendor additions) | - |
| Values of known names | percent-decoded: `%` and two hex digits in either case (RFC 3986 2.1), the result strict UTF-8; `+` is a literal `+` (RFC 3986 has no `+` rule) | R9 `a parameter has a malformed percent-encoding` |
| `algorithm` | `SHA1` (default), `SHA256`, `SHA512`, and the aliases `SHA-1`, `SHA-256`, `SHA-512`; case ignored | R10 `algorithm must be SHA1, SHA256 or SHA512 (or SHA-1, SHA-256, SHA-512)` |
| `digits` | exactly `6` (default) or `8` (D10) | R11 `digits must be 6 or 8` |
| `period` | 1-3 ASCII digits, value 1-300 (default 30) | R12 `period must be a whole number of seconds from 1 to 300` |
| `secret` | no U+0020 after percent-decoding; then Base32 as below | R14 `the secret parameter contains a space (a URI's secret is Base32 without spaces)`; then B1-B5 |

The first failing check wins, in this order: R0, R1, R2/R3, R4, the query's pieces left to right (R6-R9), R5, then the
values (R10, R11, R12, R14, B1-B5).

**Base32 (RFC 4648 section 6).** `FromBase32` (the bare form) first removes U+0020 spaces (a bare seed is often
written in groups) and trims; a URI's `secret` is never de-spaced (R14). Then, in this order:
- B1, the character set: A-Z, a-z, 2-7 and `=`. Text: `the seed isn't Base32 (letters A-Z, digits 2-7, '=' padding)`.
- B2, the unpadded length (the text before the first `=`) mod 8 is 1, 3 or 6. Text: `the seed's length isn't a
  Base32 length`.
- B3, an `=` followed by any non-`=` character, or a non-empty trailing run of `=` that isn't exactly the run the
  unpadded length needs (mod 8 of 0: none; 2: six; 4: four; 5: three; 7: one). An empty run is always fine, so unpadded
  text of any valid length is accepted, padded or not. Text: `the seed's '=' padding is wrong`.
- B4, the unused low bits of the last character are not zero (RFC 4648 3.5). Text: `the seed isn't canonical Base32
  (its last character has unused bits set)`.
- B5, fewer than 16 characters (80 bits; the spec's own example `JBSWY3DPEHPK3PXP` is 80 bits; RFC 4226 asks 128, but
  80-bit seeds are common). Text: `the seed is shorter than 16 Base32 characters (80 bits)`.

The canonical text (upper case, no padding) goes to `Base32Encoding.ToBytes`; the decoded length is checked against
`5 * length / 8`.

**tswap's own strictness.** These rules go beyond the Key Uri Format; docs/commands.md marks each as tswap's, with its
reason: B3 (one key, one accepted spelling), B4 (canonical only), B5 (80-bit floor), R6 (case-sensitive names), R12
(1-300 s) and R14 (no spaces in a URI's secret: merging words into a key gives silent wrong codes). R10 and R11 are the
spec's own rules.

**Tests.** Two classes, in this task's commit.

`TswapTests/Totp/OtpNetContractTests.cs`. Its summary says it is the upgrade guard for Otp.NET: each test pins one thing
tswap relies on and fails by name when a bump changes it. Every row goes through `TotpSeed.FromUri`/`FromBase32` and
`Compute`, not the raw library alone.

| Test | Input | Outcome |
|---|---|---|
| RFC 6238 vectors | the Appendix B seeds as Base32 (SHA1 `GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ`, SHA256 the 32-byte seed, SHA512 the 64-byte seed, padded and unpadded), 8 digits, period 30, at 59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000 | the 18 codes of the RFC (SHA1 at 59: `94287082`, SHA256 `46119246`, SHA512 `90693936`; …) |
| Leading zeros | SHA1 8 digits at 1111111109; the SHA1 URI with 6 digits at 1111111111 | `07081804`; `050471`, each asserted as the whole string |
| Step edges, period 30 | the SHA1 URI, 6 digits, at 1111111109.999 / 1111111110.000 / 1111111139.999 / 1111111140.000 | `081804` 1 s; `050471` 30 s; `050471` 1 s; `266759` 30 s |
| Step edges, period 60 | the SHA1 seed with `period=60`, at 1111111139.999 / 1111111140.000 | `360094` (8 digits `19360094`) 1 s left; `593113` (`68593113`) 60 s left (computed with Python's `hmac`, as the other vectors) |
| Digits 6 and 8 | the same seed and time | the 6-digit code is the last six digits of the 8-digit one |
| Base32 decoding | each accepted spelling: upper, lower and mixed case; padded with `=` or `%3D`/`%3d`; the bare form with spaces | the key bytes `TotpSeed` holds equal `12345678901234567890` (or the 32-byte seed) |

Break-it-once: compute with `totpSize: 7` (the digits row fails); pass the bare form to the library without removing
its spaces (the spaces decode row fails, because Otp.NET throws on a space).

`TswapTests/Totp/TotpParseTests.cs`, all with fixed `DateTimeOffset`s:

| Test | Input | Outcome |
|---|---|---|
| SHA256 URI | `otpauth://totp/X:y?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&algorithm=SHA256` at 1111111111 | `584430`, not SHA1's `050471` (the Certum mistake) |
| Period 60, digits 8 | the same seed with `&period=60&digits=8` | the code of step `t / 60`; remaining `60 - t mod 60` |
| Accepted spellings | `OTPAUTH://TOTP/…`, `algorithm=sha512`, `algorithm=sha-256`, `secret=gezd…` (lower), the SHA256 seed text with its padding as `%3D%3D%3D%3D` and `algorithm=SHA256`, no label, `issuer=` twice, unknown `image=…`, surrounding whitespace | parsed, same code as the plain form |
| Refusals, 25 rows | R0: `﻿otpauth://totp/…` (the SHA1 URI behind a BOM), `certum-totp: otpauth://totp/…`, `user: alice\notpauth://totp/…`; R1 `otpauth:totp/…`; R2 `otpauth://hotp/…?counter=1`; R3 `otpauth://u@totp/`; R4 `…#x`; R5 `?issuer=X`; R6 `Secret=`; R7 `digits=6&digits=6`; R8 `&period&`; R9 `secret=%G1`; R10 `algorithm=MD5`; R11 `digits=7`; R12 `period=0`, `period=301`; R14 `secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ note`, `secret=GEZD%20GNBV%20GY3T%20QOJQ%20GEZD%20GNBV%20GY3T%20QOJQ`; B1 `secret=GEZ1…`; B2 length 17; B3 `GEZD=GNB…`, `GEZDGNBVGY3TQOJQ=`, `GEZDGNBVGY3TQ==`; B4 the SHA256 seed text ending `GEZB` (canonical `GEZA`); B5 `GEZDGNBVGY3TQ` (13 characters, 8 bytes) | `TotpSeedException` with exactly that reason; the message contains neither the URI nor the secret text (assert both absent) |
| Bare forms | `gezd gnbv gy3t qojq gezd gnbv gy3t qojq`, mixed case; the 32-byte seed's text with and without `====` | at 1111111111: `050471`; `201283` (SHA1, 6 digits, the bare defaults) |
| Classify | a password; a bare Base32 seed; `otpauth-backup-codes` (no colon); the SHA1 URI; a hotp URI; ` otpauth:x`; the three R0 values | `None`, `None`, `None`, `Totp`, `OtpAuthUnusable` for the rest |
| No system clock | the sources under `TswapCore/` and `TswapCli/` | no call of `ComputeTotp()`, `RemainingSeconds()` or `WindowStart()` without an argument (a source scan) |

Break-it-once: map `SHA256` to `OtpHashMode.Sha1` (the SHA256 URI row and the SHA256 vectors fail); drop the
trailing-bits check (the B4 row fails); make `IsOtpAuth` test "starts with" (the R0 classify rows fail).

## Task 2: codes in `run` and `apply`; the seed stays in

**Grammar.** A token is `{{NAME}}`, `{{NAME:previous}}` or `{{NAME:totp}}`; a marker is `# tswap: NAME`,
`NAME:previous` or `NAME:totp`. One suffix at most: `:previous:totp` is an unknown suffix, so a previous bare seed
can't give a code (docs say so). Every spelling of the grammar changes together:
- `Validation.TokenRegex` (`:9`), `ThrowIfUnknownTokenSuffix` (`:15-21`), the malformed-token text (`:46`),
  `AnyTokenRegex` (`:168`);
- `Apply.MarkerRegex`, the `AnyMarkerRegex` check and `ValidMarkerTail` (`:8`, `:15`), the two marker texts (`:73`,
  `:80`), and `Apply`'s base-name split (`:85-87`), which strips `:totp` as it strips `:previous`;
- `Check.MarkerRegex` (`:8`) and `CheckMarkers`' suffix split (`:156`);
- `ToCommentProcessor.ExistingMarker` (`:16`); `SecretMatcher.ConsumedMarker` (`:290`);
- `RunCommand.BracedNameRegex` (`:498`), the encoded-token decoding beside it, and `EnvToken`'s text (`:432`).

New texts:
- `Unknown token '{{x:bogus}}': the suffixes are ':previous' (the value the last rotation replaced) and ':totp' (the current code of a TOTP seed).`
- `'…' is not a valid token: a token is {{NAME}}, {{NAME:previous}} or {{NAME:totp}}, and fields aren't substituted into commands.`
- `'…' is not a valid marker: a marker is # tswap: NAME, # tswap: NAME:previous or # tswap: NAME:totp, and fields aren't substituted into commands.`
- `Unknown marker '# tswap: x:bogus' (line N): the suffixes are ':previous' and ':totp'.`
- `the value must be exactly one {{name}}, {{name:previous}} or {{name:totp}} token`

**`CommandValues`** (`TswapCore/Totp/CommandValues.cs`), the one place a stored value becomes what a command is given:

```csharp
public sealed class CommandValues(ISecretLookup inner, DateTimeOffset now, string prefix, bool windows) : ISecretLookup
```

- **Name members** (`Contains`, `HasPreviousValue`, `ThrowIfUnreadable`) take names and pass them to `inner`
  unchanged; `Apply` and `Check` pass them the base name.
- **Token members** (`ResolveToken`, `IsBurnedToken`) strip a `:totp` suffix before asking `inner`. So
  `IsBurnedToken("t:totp")` answers for `t`'s current value; `VaultView.Split` (`:282-283`) would treat `t:totp` as a
  name.
- **`ResolveToken(token, where)`**: the stored value of `name` or `name:previous` from `inner`. Then:
  - `:totp`: `FromUri` when `IsOtpAuth`, else `FromBase32`;
  - no suffix or `:previous`, and `IsOtpAuth`: `FromUri`;
  - otherwise the stored value, as today.

  A code is computed at `now`: one clock reading per command, so `{{x}}`, `{{x:totp}}` and a marker of `x` in one run
  get the same code. It is cached per token.
- **Refusal.** A `TotpSeedException` becomes this `TswapException` (the token as typed; the marker form
  `'# tswap: x' (line N)` for a marker; the bare name for Task 3):
  - Unix: `'{{x}}': secret 'x' holds no TOTP seed tswap can use (<reason>), so nothing was substituted. The user can see the value with 'sudo <prefix> get x' and store a corrected one with 'sudo <prefix> add x'.`
  - Windows: the same first sentence, then `The user can see the value with '<prefix> get x' and store a corrected one with '<prefix> add x', from an elevated command prompt.` (`RunCommand.ViewSecretLine`'s split).
- **`StoredForms(token)`**, for a token that gave a code. It is keyed by the token exactly as `ResolveToken` received
  it (`x`, `x:previous`, `x:totp`), the key `ApplySecretsReporting` reports its rows under. It holds exactly:
  - the stored value as stored (the whole URI, or the bare seed text);
  - the `secret` parameter's text as written in the URI (before percent-decoding) and percent-decoded;
  - the seed in four spellings: upper case unpadded, upper case padded, lower case unpadded, lower case padded (for a
    bare seed: after removing spaces).

**Wiring.**
- `run` wraps its view once: `new CommandValues(view, ctx.Time.GetUtcNow(), ctx.Prefix, ctx.Os == OSPlatform.Windows)`.
  It uses that one object for the tokens (`ResolveToken` and the burned warning's `IsBurnedToken`), `--env` and
  `Apply.ApplySecretsReporting`.
- Masking (`Redact`, `RunCommand.cs:175-184`) routes each form by its own length through the short-value test
  (`:177`):
  - the code: `Redact(token, code, [])`. A 6-digit code goes to the short-value matcher and is masked as a whole
    number; an 8-digit one is masked anywhere;
  - then one `Redact(token, form, [])` per `StoredForms` entry. Each is at least 16 characters (B5; the URI is longer),
    so all go to `redactions` and are masked anywhere, as are their base64 and base64url forms (`Redaction.Variants`).

  All of them carry the label `[REDACTED: <token>]`. No other spelling is masked: the seed grouped with spaces, in a
  mixed case other than as stored, the key bytes in hex or base64, or the URI re-encoded.
- `ApplyCommand` wraps its view the same way (D7). `get`, `field adopt` and `export` keep the raw view.
- The broker (D8): `VaultBrokerSecretSource.Read` and `ReadMany` (`BrokerSecrets.cs:86`, `:128`) and `SshKeys`
  (`:89`) refuse a value for which `IsOtpAuth` is true. They throw `BrokerSecretException`
  `secret 'x' is a TOTP seed (an otpauth:// URI); the broker doesn't hand out TOTP seeds` and zero the value.

**Every path that hands out a value without sudo**, after Tasks 2-4:

| Path | For an otpauth record |
|---|---|
| `run` `{{x}}`, `{{x:previous}}`, `--env N={{x}}`, `{{@file}}` markers | the current code (D2, D3); unusable (any `OtpAuthUnusable`, R0 included): refused before the child starts |
| `run` `{{x:totp}}` / `# tswap: x:totp` | the code; for a bare Base32 value too; anything else refused |
| `totp x` (Task 3) | the code; refusals as `run` |
| broker routes, templates, ssh-agent | refused (D8), value zeroed |
| `rotate x` (Task 4) | refused, decided from the decrypted value |
| `redact`, `tocomment`, `check`, `names`, `burned`, `field show` | no value, as today (`tocomment` writes `# tswap: x`, which `run` fills with the code; `check` reports `Ok` for `# tswap: x:totp` from metadata, without testing the seed) |
| `sudo get`, `sudo export`, `sudo field adopt` | unchanged: the stored value (D6) |
| `sudo list` | unchanged: names and dates, no value (`ListCommand.cs:9`) |
| `sudo apply` | the code, as `run`'s files (D7) |

A bare Base32 value is never recognised (D2), so `{{name}}` still hands it out. A bare seed is given only through
`{{name:totp}}`.

**Tests** (in-process, the `RunEnvTests` `RecordingPty` harness, `FleetMachine.Time` fixed at 1111111111.5 s; the
SHA1 URI unless the row says otherwise):

| Case | Outcome |
|---|---|
| `run tool {{t}}` | child argv `050471`; stored URI not in argv |
| SHA256 URI, `{{t}}` | `584430` |
| `{{t:totp}}` on a bare Base32 record (spaces, lower case) | `050471` |
| `{{t}}` on a bare Base32 record | the stored text, as today |
| `{{t:previous}}` after `ingest --rotate` (burned first) from the SHA1 URI to the SHA256 URI | `050471`; `{{t}}` `584430` |
| `--env OTP={{t}}` | env `OTP=050471` |
| `{{@f.yaml}}` with `code: ""  # tswap: t` and `c2: ""  # tswap: t:totp` | both lines `"050471"` in the filled copy |
| `{{t:totp}}` on a burned record | the code, and `run`'s burned warning naming `t:totp` |
| the child prints the code, the URI, the secret text, the percent-decoded seed and the lower-case padded seed | `[REDACTED: t]` for each; a longer number containing `050471` stays unmasked; a line with the key bytes in hex stays unmasked |
| the child prints `x<URI>`, `-<URI>`, `x<seed, lower case unpadded>` | `[REDACTED: t]` for each, nothing of the URI or seed left on stdout |
| `_pty.ChunkSize = 3` (`RecordingPty.cs:18`); the child prints the code, then the URI | `[REDACTED: t]` for each, nothing of either left |
| `{{t:totp}}` on `hunter2-password`; `{{t}}` on a hotp URI; `# tswap: t` on `digits=7` | refused with the texts above (B1, R2, R11), exit 1, child not started, no seed or URI on stdout or stderr |
| the three R0 values of Task 1: `{{t}}`, `--env OTP={{t}}`, `# tswap: t` | refused (R0), exit 1, child not started, neither the URI nor the secret text on stdout or stderr |
| `{{t:previous:totp}}`, `# tswap: t:previous:totp` | the new unknown-suffix texts |
| `check` on a file with `# tswap: t:totp` | `Ok`, no value decrypted |
| `sudo apply` (sudo bypass) on the file above | the code on both lines |
| `sudo get t` | the stored URI |
| a broker route, a template and an ssh-agent key naming `t` (`VaultBrokerSecretSource` over a record vault, as `BrokerTemplateCallTests` builds it; `SshKeys` likewise), for the SHA1 URI and the three R0 values | refused with the broker text; a plain secret still served |

Break-it-once: make `CommandValues.ResolveToken` return the stored value for an otpauth record (the `{{t}}` argv row
fails); drop the `StoredForms` redaction (the redaction rows fail); route the stored forms by the code's length (the
embedded rows fail); remove the broker check (the broker row fails).

## Task 3: `tswap totp <name>`

`TswapCli/Commands/TotpCommand.cs`, registered after `run`:
- `Name` `totp`, `HelpUsage` `totp <name>`, `RequiresSudo` false.
- `Description`: `Print the current code of a TOTP secret (an otpauth://totp/ URI, or a Base32 seed) and how long it
  stays valid; the seed itself only with sudo get`.
- `PrintsSecretValues => false`: that flag only makes a redirected stdout UTF-8 on Windows for values
  (`ICliCommand.cs:39-43`), and a code is ASCII digits. `SecretValueOutputTests.OnlyGetAndApplyPrintSecretValues` stays
  as it is.

It validates the name, unlocks, opens the view as `get` does, and resolves `name:totp` through `CommandValues` at
`ctx.Time.GetUtcNow()`, so a bare Base32 seed works here, as with `:totp`. It prints:
- stdout: the code and a newline, nothing else, so `code=$(tswap totp x)` captures exactly the code;
- stderr: `Valid for 17 more seconds (a new code every 30 seconds).`, with the seed's own period (`… every 60
  seconds.` for `period=60`) and `1 more second` in the singular;
- for a burned value: before those lines, on stderr, `run`'s
  `Warning: 'x' is a burned value — using it anyway; rotate it after use.`;
- for format 2: `get`'s warning (`FormatTwoUse.Substitute`).

The refusals are Task 2's, naming the secret. No `--json` and no waiting for the next period (out of scope).

This task's commit also regenerates the generated block of `docs/commands.md` (`TSWAP_REGENERATE_DOCS=1` on
`CommandReferenceIsCurrent`), so `./runtests.sh --unit` passes after it. Task 7 adds only prose.

Tests: a new `TswapTests/TotpCommandTests.cs`, with its own value recorder copying `RunEnvTests`'
(`_m.StoreOpened = store => store.ValueDecrypted = …`; `RunEnvTests._values` is private) and `FleetMachine.Time` fixed.
Both streams are compared after `ReplaceLineEndings("\n")`.
- The SHA1 URI at 1111111109.000 gives `081804\n` and stderr `Valid for 1 more second (a new code every 30
  seconds).`. At 1111111110.000 it gives `050471` and 30 seconds.
- Period 60 at an edge; a bare seed; a burned record (the warning first).
- A missing name, and a password value: refused, the value absent from both streams.
- Exactly one value section is decrypted.

Break-it-once: print the remaining time on stdout (the stdout assertion fails).

## Task 4: `names` marks otpauth records; `rotate` refuses them

`names` already unlocks (`NamesCommand.cs:38`) and reads metadata only (`:43`, `Names_DecryptsNoValue`), so the kind
must be in the metadata. Format 3 metadata carries an extension list that every build keeps byte for byte (ruling 6,
`RecordMetadata.cs:33`), and a value write keeps extensions it doesn't own (`FieldEdits.ForWrite`,
`RecordWrites.cs:93`). Because an older build keeps the extension when it writes a new value, the kind is bound to a
version.

**The `ValueKinds` extension, type `0x0101`.** Add it to the registry comment in `FieldSet.cs`.
- Layout: format byte `1`; a count (1 byte, 0-2); per entry, the version stamp (28 bytes, `SecretRecordCodec`'s stamp
  encoding) and the kind (1 byte: 1 `Totp`, 2 `OtpAuthUnusable`).
- Entries are ordered current, then previous, as `RetainedVersions()` orders them. Only otpauth versions get an entry;
  with no entries there is no extension.

**Read.** `ValueKinds.Of(RecordMetadata)` gives the current version's kind: the entry whose stamp equals the current
version's. It gives `None` for no entry, an unknown kind byte, an unknown format byte, a count of 0, an extension that
doesn't decode, or two `0x0101` extensions. This is display only and never makes a record unreadable. `SecretInfo`
gains `ValueKind Kind`, set in `SecretInfo.From`. Nothing reads a previous version's mark, but its entry is kept so a
restore keeps the mark.

**Write.** A kind entry is written only for a version being sealed now, from the value in hand. A version that a write
merely carries keeps its entry if it has one and stays without one if it doesn't. Only `vault reindex` fills in entries
for carried versions, since it holds every value. The current kind is still always right for `run`, `totp` and
`rotate`, which decide from the value. Where this happens:
- **New version.** `RecordWrites.Next`/`NewVersion` get an optional `ValueKind newKind = None`
  (`RecordVaultStore.cs:881` passes `Classify` of `v.Value`, decoded as `Fingerprinter.Compute` decodes it). So does
  `NextRecord`'s new-version branch (`:1535-1566`). The new version's entry comes from `newKind`; the replaced current
  becomes previous and keeps its entry if it has one; every other entry is dropped.
- **`WriteSnapshot`** (`:1613-1640`, the `migrate --to-records` path, `RecordMigration.cs:163`) builds each record as a
  new version from its plaintext, so it sets the entry from `Classify` of that value.
- **Burn, field write, same value:** extensions untouched, as today.
- **`PrepareV3`** (`:2056`; `WriteAll` sends every format 3 write made from plaintext through it, `:2018`): it sets
  entries from both retained values only when `recomputeOlderSets` is true (reindex), and otherwise leaves the
  extension as the write made it.
- **Tombstones:** `FieldEdits.ForTombstone` drops `0x0101`, and both tombstone paths call it (`RecordWrites.Tombstone`,
  `RecordVaultStore.Tombstone` `:1601-1604`). An older build keeps the extension on a tombstone, which is harmless:
  `SecretInfo.From` returns null for one.
- **Format 2 folders** store no extensions: such a record is marked after `vault reindex`.

`RecordWrites_MatchNextRecord_OnRandomStates` compares against `PrepareV3(…, recomputeOlderSets: false)`
(`RecordWritesTests.cs:442`), so it holds the two write paths equal under this rule. As a sanctioned test-input
change, its random states draw otpauth values as well as plain ones. Each state's `ValueKinds` extension holds, at
random, consistent entries, no entry for a retained version, or a stale entry for a stamp no longer retained.

**Reindex.** `IsCurrent` (`:1434`) is false when the extension disagrees with `Classify` of a retained value (the values
are in hand). So `sudo tswap vault reindex` marks records written before this release and rewrites only those.

**Merges.** `ValueKinds` follows `RecordMerge.MergeExtensions`' rule for every type but `Fields`: the whole list of the
input with the largest write stamp. It never makes a record unreadable. A mark lost because an unmarked copy (an older
build's write) wins comes back with `vault reindex`.

**Output.**
- `names`: ` [TOTP]` or ` [OTPAUTH: unusable]` after the date, before ` [BURNED]`.
- `NameEntry` gains `string? Kind` (`"totp"`, `"otpauth-unusable"`; null otherwise, so it is omitted and the existing
  JSON is unchanged).
- `burned`: after the existing `→ Rotate these secrets: …` line (`BurnedCommand.cs:70`, unchanged, so
  `Burned_DecryptsNoValue` stays as it is), and only when an outstanding entry's `Kind` is not `None`, one more line:
  `→ A TOTP seed can't be rotated: the user stores the issuer's new seed with '<source> | <prefix> ingest --rotate <name>'.`

**`rotate` (D9).** It decides from the value, marked or not:
- New `VaultWriter.ReadCurrentValue(string name)`, modelled on `SameValue` (`RecordVaultStore.cs:934-956`). It returns
  the current value's bytes (one value section, the read `get` uses), or null when that section can't be decrypted.
  The caller zeroes the bytes.
- `RotateCommand` calls it after `SecretRotation.Check` (`RotateCommand.cs:38`) and before
  `CreateCommand.GenerateValue` (`:40`), so a refusal requests no entropy. When `Classify` of the value is `Totp` or
  `OtpAuthUnusable`, it refuses: `'x' holds a TOTP seed, which comes from the issuer: 'rotate' would replace it with a
  random value. Store the new seed with '<source> | <prefix> ingest --rotate x'.`
- A section that can't be decrypted (null) doesn't refuse: `rotate` goes on as today. That keeps owner decision 8 and
  `Add_OtherVariantSet_DamagedCurrent_RefusesNamingTheFile_WritesNothing` unchanged; a damaged seed can't be lost
  further.
- `ingest --rotate` decrypts nothing and still works.
- The owner sanctions the extra decrypt. `WriteCommandDecryptionTests.Rotate_DecryptsNoValue`'s
  `Assert.Empty(_values)` becomes exactly one entry, `a`'s file at its current version before the rotate. Rename the
  test `Rotate_DecryptsOnlyTheCurrentValue`. The class summary adds "except `rotate`, which reads the current value
  once to refuse a TOTP seed (#374)".

**`certum-totp`** (written by 0.3.2, no extension): `run`, `totp` and `rotate` are right at once, because they decide
from the value. `names` marks it after one `sudo tswap vault reindex`, or after its next write.

Tests:

| Case | Outcome |
|---|---|
| `ingest` of the SHA1 URI, a hotp URI, a password, a labelled paste (R0) | `names`: `[TOTP]`, `[OTPAUTH: unusable]`, nothing, `[OTPAUTH: unusable]`; `--json` `kind` the same; no value decrypted (`Names_DecryptsNoValue`'s recorder) |
| `ingest --rotate` URI → password (burned first) | no mark; `:previous` still gives a code (Task 2) |
| `add` (sudo bypass), `restore` back to the URI, export + import | marked |
| a classic vault holding the SHA1 URI, `migrate --to-records` | `[TOTP]` without a reindex |
| burned TOTP record | `… [TOTP] [BURNED]`; `burned` prints the TOTP line after the rotate line |
| a record written as 0.3.2 writes it (the test writes the URI, then removes the extension through the codec) | no mark; `vault reindex` → marked, `Rewritten` 1 (the plain records are current) |
| an entry-less previous version after a rotation | stays entry-less; `vault reindex` gives it its entry |
| an extension whose entry names a stamp the record no longer retains (an old build's rotate) | no mark |
| two copies (a main file and a sync-conflict copy), the unmarked one with the larger write stamp; then the other way round | no mark, `run` still gives the code, `vault reindex` → marked; marked |
| a codec round trip of the extension | the layout above, byte for byte |
| `0x0101` truncated, with an unknown format byte, an unknown kind byte, a count of 0, or two `0x0101` extensions | `names` lists the record without a mark, nothing is unreadable, `run` still gives the code |
| delete | the tombstone carries no `0x0101` |
| an unmarked record (as 0.3.2 writes it) holding the SHA1 URI: `burn t`, then `rotate t` | refused, exit 1, the value and the record file unchanged, no entropy requested |
| the same with a marked record | the same |
| the same with a labelled paste (R0) | the same |
| a damaged current section, `rotate` | works, as today |
| after `burn t`, `<new URI> \| ingest --rotate t` | works; the new value is marked |

Break-it-once: drop the stamp comparison in `ValueKinds.Of` (the stale-entry row fails); make `IsCurrent` ignore kinds
(the reindex row fails); decide `rotate` from the mark instead of the value (the unmarked rotate row fails).

## Task 5: trim and AOT warnings fail the Release publish

**Evidence on this base:**
- `dotnet publish TswapCli/TswapCli.csproj -c Release -p:TrimmerSingleWarn=false -p:IlcTreatWarningsAsErrors=true`
  on Linux x64 passes with no IL warning.
- In CI run 45839723503 (main), the "AOT publish" step (`ci.yml:132`, Release) shows none on any of the four legs.
- The E2E step's Debug publish shows `warning IL2104: Assembly 'Yubico.YubiKey' produced trim warnings` on all four.
  Locally, with `TrimmerSingleWarn=false`, that is one
  `IL2026 Yubico.YubiKey.Cryptography.CryptographyProviders..cctor(): … HMAC.Create(String)`.

Because of that Debug warning, the error applies to Release only, which is what ships. NativeAOT's ILCompiler reads
both properties (`Microsoft.NETCore.Native.targets:31`, `:308`, `:311` in the package the pinned SDK restores). In
`TswapCli/TswapCli.csproj`:
- `<TrimmerSingleWarn>false</TrimmerSingleWarn>` in the first PropertyGroup, so a package's warnings are listed per
  member, not collapsed into one IL2104;
- a new `<PropertyGroup Condition="'$(Configuration)' == 'Release'">` with
  `<IlcTreatWarningsAsErrors>true</IlcTreatWarningsAsErrors>` (ILC's `--warnaserror`: every IL2xxx/IL3xxx it reports
  is an error).

Each gets a comment saying why, naming the properties (not line numbers) and the Debug IL2026 above as known and
pre-existing. `Directory.Build.props` can't take them: `DependencyPinningTests` (`PropsProperties`, `:61`) allows
exactly three properties there. First re-run the Release publish with both settings, here and from the newest main CI
log. If any IL warning shows in Release, stop and report.

Guard test `TswapTests/Build/AotWarningTests.cs`, reading files only:
- the two settings are present as above, one unconditional and one Release-conditioned;
- no project file sets `IlcTreatWarningsAsErrors` false, `TrimmerSingleWarn` true, `SuppressTrimAnalysisWarnings` true,
  `SuppressAotAnalysisWarnings` true (ILC's `--noaotwarn`, `:313`), or `NoWarn`/`WarningsNotAsErrors` with an
  `IL2`/`IL3` code;
- no file under `.github/workflows/` passes any of those as `-p:` (`release.yml` is read, not changed);
- one positive row per forbidden form proves the scan finds it in a sample string.

Break-it-once, with the output in the report: add a throwaway call of a `[RequiresUnreferencedCode]` method to
`Program.cs`. The Release publish fails with `error IL2026` and the Debug publish only warns. Revert it.

## Task 6: published-binary end-to-end tests

In `EndToEndTests`, which CI runs against the NativeAOT Debug publish via `TSWAP_E2E_BINARY`
(`TswapBinaryFixture.cs:27`). The vault is set up as the existing tests do it: `TSWAP_TEST_KEY` and a temp
`TSWAP_CONFIG_DIR` (`EndToEndTests.cs:63-65`), `init --yubikey --no-recovery` (`:340`); values go in through `ingest`
on stdin. The real clock runs inside the binary, so these tests assert shapes and absences only, never a code's value,
and pass at any instant. Stderr is matched line by line after `ReplaceLineEndings("\n")`, because `ctx.Unlock` may add
a touch notice.
- `tswap totp` on the SHA1 URI (6 digits) and on a SHA512 URI with `digits=8`: exit 0. Stdout is exactly one line of 6
  (or 8) ASCII digits. A line of stderr matches `^Valid for [0-9]+ more seconds? \(a new code every 30 seconds\)\.$`.
- `tswap run` with `{{t}}`: the child is a script (Unix `sh`, Windows `pwsh -File`; the pattern at `:388-391` and
  `:782`). It prints only value-free markers: `LEN=<length of $1>`, `DIGITS=yes` when `$1` is all digits, and `LEAK`
  when `$1` contains `otpauth` or the seed text, case ignored. Assert:
  - `LEN=6` (`LEN=8` for the SHA512 URI) and `DIGITS=yes`;
  - no `LEAK`;
  - stdout doesn't contain the URI, the seed text or `otpauth`.
- `names --json`: the TOTP record's entry has `"kind": "totp"`, a plain one has no `kind`.
- A refused URI (`digits=7`): `run` and `totp` exit 1 with the R11 refusal on stderr, and neither stream contains the
  URI or the seed.

Break-it-once: make `CommandValues` return the stored value (the `LEAK` assertion fails in the published binary). Run
it with `TSWAP_E2E_BINARY` pointed at a local Debug publish and report the output.

## Task 7: docs (last)

- **`TswapCore/Prompt.cs`** (ASCII only, `Prompt_IsAsciiOnly`):
  - In "Commands you SHOULD use", after `run`: `` `%CMD% totp <name>` - Print the current code of a TOTP secret on
    stdout and how many seconds it stays valid on stderr. A code is a short-lived live credential, not the seed: use it
    at once, never store it; seeing a code needs no burn. ``
  - The `run` bullet keeps its ending (`…run finds no token`, pinned by `PromptTests.Prompt_RunBullet_SaysScriptBlock`,
    unchanged). The TOTP sentences go on a continuation line after it, as the `rotate` bullet's continuation lines do:
    a TOTP secret (an `otpauth://totp/` URI) gives its current code in `{{name}}` and in markers; `{{name:totp}}` is for
    a secret stored as a bare Base32 seed; store a URI alone, not inside other text; the seed is for the user only
    (`sudo %CMD% get`).
  - The `names` bullet: `[TOTP]` marks them.
  - Rule 7 (`Prompt.cs:119-121`) gains a continuation line: a TOTP seed can't be rotated; replacing one is the user's
    job: the issuer's new seed, stored with `<source> | %CMD% ingest --rotate <name>`.
  - A seen URI or seed is burned as any value.
  - `prompt-hash` changes (no test pins it). The owner refreshes installed copies with `tswap prompt > …/SKILL.md`
    after the release.
- **`docs/commands.md`**, prose only (the block was regenerated in Task 3), a section "TOTP secrets" covering:
  - recognition (D1), the token forms and D2/D3, and that a bare seed is given only through `{{name:totp}}`;
  - the refusal reasons (the tables of Task 1, condensed), with tswap's own strictness marked and the reasons given;
  - store the URI alone;
  - `totp`'s output; `names`' marks;
  - `vault reindex` for old records; `rotate` vs `ingest --rotate`;
  - the spellings `run` masks (Task 2's `StoredForms` list) and that no other spelling is masked;
  - `check` reports `Ok` for a `:totp` marker from metadata, without testing the seed;
  - a previous bare seed can't give a code (`:previous:totp` is not a token);
  - a code filled into a `{{@file}}` copy expires within one period: codes belong in arguments or `--env` at use time.
- **AGENTS.md:** `totp <name>` in the No-sudo list (`:115`), in rule 3's command list (`:349`), and one sentence in
  "Token Substitution".
- **`docs/agent-integration.md:101`:** `totp` in the `ALLOWED_COMMANDS` example.
- **`docs/security-model.md`:**
  - the reading-command list (`:211-212`) gains `totp`;
  - "What each command decrypts" gains `totp` (the one value it computes from);
  - `rotate` leaves the write-command rows at `:179` and `:230` and gets its own row: "The one current value, to refuse
    a TOTP seed (#374); none for a section that can't be decrypted";
  - a short "TOTP secrets" note:
    - a code is a live credential valid for one period;
    - the seed of a recognised otpauth record never leaves without sudo, but a bare Base32 value is not recognised;
    - `run` masks the code, the stored value and the spellings listed in docs/commands.md, and another spelling of
      the same key is not masked; other records' seeds inside URIs are masked only as whole values;
    - the broker refuses otpauth records (D8);
    - `sudo tswap field adopt NAME FIELD --from <TOTP secret>` turns the URI into a visible field, which `field show`
      prints without sudo; adopt only what is meant to be visible;
    - the Certum signing flow (#368) keeps its YubiKey code.
- **`docs/BROKER.md`**, "Limits (v1)": one bullet saying the broker refuses TOTP records (a value holding `otpauth:`)
  on routes, templates and the ssh-agent, and hands out neither seeds nor codes.
- **Release notes** are the controller's (there is no next-release file). The lines for the controller to add:
  - `sudo tswap vault reindex` marks TOTP records written before 0.3.3;
  - a URI with a short seed, a long period, inexact padding or a space in its secret is refused (tswap's own rules);
  - a value that only mentions an otpauth URI among other text is now refused without sudo;
  - a bare Base32 seed stays an ordinary value: `{{name}}` hands it out, `burn` plus `rotate` replaces it, and `names`
    gives no hint. Store seeds as URIs.

## Out of scope

HOTP counters; waiting for the next period; `--json` for `totp`; broker routes that hand out codes; masking seeds
inside other records' URIs; the Certum CI signing flow (#368 keeps the owner's YubiKey and touch).

## Amendment history (a record only; the body above is authoritative)

Review rounds: MiMo rounds 1-4, GLM round 2, owner and controller rulings. Each amendment below is applied in the body.
Round 5 (GLM r2) consolidated the body and added: the value-based `rotate` rule written in place (I-1) and every
stale line (M-1); the prompt continuation line (M-2); `VaultWriter.ReadCurrentValue` before `GenerateValue` (M-3);
`IsBurnedToken` through `CommandValues` and a burned `{{t:totp}}` row (M-4); entry order and the two-extensions row
(M-5); docs for `check`, a previous bare seed and codes in files (M-6, M-7, M-14); stderr matched line by line (M-8);
the burned hint, prompt rule 7, `ALLOWED_COMMANDS`, the security-model list and the BROKER.md line in this brief
(M-9); the `OtpTotp` alias and the constructor comment (M-10); Tasks 5 and 6 owning amendments 13 and 14 (M-11);
`SpellingTests` covering `.cs` (M-12); the release-note lines (M-13).

### Amendments (round 1: MiMo; GLM's round 1 hit its quota and reviews round 2; controller and owner rulings)

(Applied in the body.)

1. **`rotate` decides from the value (MiMo I1; owner decision 2026-11-27, option a).** The metadata mark alone fails
   open: `certum-totp` (written by 0.3.2) has none, and `burn` then `rotate` needs no sudo, so an agent could replace the
   seed with a random value. `rotate` therefore decrypts the record's current value once (one value section, the read
   `get` uses; bytes zeroed after) and refuses with Task 4's text when `Classify` gives `Totp` or `OtpAuthUnusable`,
   marked or not. A current section that can't be decrypted doesn't refuse: `rotate` goes on as today (owner decision 8,
   `Add_OtherVariantSet_DamagedCurrent_RefusesNamingTheFile_WritesNothing` keeps its `rotate`; a damaged seed can't be
   lost further). `ingest --rotate` decrypts nothing and still works (the issuer's new seed). The owner sanctions the
   extra decrypt. Changed assertion: `WriteCommandDecryptionTests.Rotate_DecryptsNoValue`'s `Assert.Empty(_values)`
   becomes exactly one entry, `a`'s file at its current version before the rotate (rename the test
   `Rotate_DecryptsOnlyTheCurrentValue`). Security model: the "A reading command decrypting values it doesn't use" row
   (`docs/security-model.md:179`) and the "What each command decrypts" row of the write commands (`:230`) take `rotate`
   out: its own row, "The one current value, to refuse a TOTP seed (#374); none for a section that can't be
   decrypted". New Task 4 test rows: a record written as 0.3.2 writes it (no mark) holding the SHA1 URI, `burn t` then
   `rotate t` → refused, exit 1, the value and the record file unchanged; the same with a marked record; a damaged
   current section → `rotate` works; after `burn t`, `<new URI> | ingest --rotate t` works and the new value is marked.
2. **`PrintsSecretValues` (M2).** `TotpCommand.PrintsSecretValues => false`: the flag only makes a redirected stdout
   UTF-8 on Windows for values (`ICliCommand.cs:39-43`), and a code is ASCII digits.
   `SecretValueOutputTests.OnlyGetAndApplyPrintSecretValues` stays as it is.
3. **The period in `totp`'s stderr line (M3)** is the seed's: `Valid for 17 more seconds (a new code every 60 seconds).`
   for `period=60`.
4. **Newlines (M4).** Task 3's stdout and stderr assertions compare after `ReplaceLineEndings("\n")`.
5. **What `run` masks for a token that gave a code (M5).** `StoredForms(token)` is exactly: the stored value as stored
   (the whole URI, or the bare seed text); the `secret` parameter's text as written in the URI (before
   percent-decoding) and percent-decoded; and the seed in four spellings: upper case unpadded, upper case padded, lower
   case unpadded, lower case padded (for a bare seed: after removing spaces). Each goes through `Redaction.Variants` as
   any value does, so its base64 and base64url forms are masked too; the code itself is masked as in Task 2. No other
   spelling is masked (the seed grouped with spaces or in mixed case other than as stored, the key bytes in hex or
   base64, the URI re-encoded). Task 2's redaction row gains the percent-decoded and lower-case-padded seed, and a hex
   key line that stays unmasked. The security-model note says "`run` masks the code, the stored value and the
   spellings of the seed listed in docs/commands.md; another spelling of the same key is not masked", and commands.md
   lists them.
6. **B2 and B3 (M6).** Checked in the order B1, B2, B3, B4, B5. B2 is the unpadded length (the text before any `=`)
   with length mod 8 of 1, 3 or 6. B3 is every padding fault: an `=` before a non-`=` character, or a trailing run whose
   length isn't the one the unpadded length needs (mod 8 of 0: none; 2: 6; 4: 4; 5: 3; 7: 1). New refusal rows:
   `GEZDGNBVGY3TQOJQ=` (B3: 16 characters need no padding) and `GEZDGNBVGY3TQ==` (B3: 13 need three).
7. **Merges (M7).** `ValueKinds` follows `RecordMerge.MergeExtensions`' rule for every type but `Fields`: the whole list
   of the input with the largest write stamp. It never makes a record unreadable; a mark lost because an unmarked copy
   (an older build's write) wins comes back with `sudo tswap vault reindex`. New Task 4 row: two copies of the TOTP
   record (a main file and a sync-conflict copy), the unmarked one with the larger write stamp → `names` shows no mark,
   `run` still gives the code, `vault reindex` → marked; with the marked one larger → marked.
8. **Platform wording (M8).** `CommandValues` takes `string prefix, bool windows` from the CLI (`ctx.Prefix`,
   `ctx.Os == OSPlatform.Windows`). The refusal's last sentence is, on Unix, `The user can see the value with 'sudo
   <prefix> get x' and store a corrected one with 'sudo <prefix> add x'.`, and on Windows, `The user can see the value
   with '<prefix> get x' and store a corrected one with '<prefix> add x', from an elevated command prompt.`
   (`RunCommand.ViewSecretLine`'s split). The broker text needs neither.
9. **`field adopt` (M9).** The security-model "TOTP secrets" note gains: `sudo tswap field adopt NAME FIELD --from
   <TOTP secret>` turns the URI into a visible field, which `field show` prints without sudo; adopt only what is meant
   to be visible.
10. **Hyphenated algorithms (M10; controller ruling).** `algorithm` also accepts `SHA-1`, `SHA-256`, `SHA-512`, case
    ignored, as aliases (authenticators accept them, and they name the same hash). R10's text becomes `algorithm must be
    SHA1, SHA256 or SHA512 (or SHA-1, SHA-256, SHA-512)`; its refusal row uses `algorithm=MD5`; the accepted-spellings
    row gains `algorithm=sha-256`. The other strict rules stay (B4 non-canonical trailing bits, R12 above 300, B5 under
    80 bits, R11 `digits=7`) and docs/commands.md lists each with its reason. The refusal table has 20 rows (amendment 18; 23 with amendment 26): one per
    reason, two for R12 (`period=0`, `period=301`), three for B3 (amendment 6 and `GEZD=GNB…`).
11. **The plaintext write path (M11).** `NextRecord` needs no change: `WriteAll` sends every format 3 write made from
    plaintext through `PrepareV3` (`RecordVaultStore.cs:2018`), which sets the extension. That is why
    `RecordWrites_MatchNextRecord_OnRandomStates` (which compares `RecordWrites` with `NextRecord` plus `PrepareV3`)
    holds the two paths equal once its random states include otpauth values.

### Amendments (round 1b: package upgrades; owner, 2026-11-27)

Owner: "Make sure we have tests that would catch any issues on package upgrades". (Applied in the body.)

12. **Otp.NET contract tests.** `TswapTests/Totp/OtpNetContractTests.cs`, whose summary says it is the upgrade guard
    for Otp.NET: each test pins one thing tswap relies on and fails by name when a bump changes it. Every row goes
    through tswap's own path (`TotpSeed.FromUri`/`FromBase32` and `Compute`), not only the raw library. Task 1's rows
    move into this class where they are this contract; the rest stay in Task 1's tests.
    - The RFC 6238 Appendix B vectors: all six times × SHA1, SHA256 and SHA512, 8 digits, period 30 (18 codes; Task 1's
      first row).
    - Leading zeros kept: SHA1 8 digits at 1111111109 is `07081804`; the SHA1 URI with 6 digits at 1111111111 is
      `050471` (Task 1's window-edge row). Assert the whole string, including the zero.
    - Step boundaries at the last millisecond of a step and the first of the next. Period 30 is Task 1's window-edge row.
      Period 60, SHA1 seed: at 1111111139.999, `360094` (8 digits: `19360094`) with 1 s left; at 1111111140.000,
      `593113` (`68593113`) with 60 s left. Values computed with an independent HMAC (Python `hmac`), as the other
      vectors were.
    - Digits 6 and 8 for the same seed and time: the 6-digit code is the last six digits of the 8-digit one.
    - Base32 decoding of the forms tswap hands the library. Each accepted spelling must decode to the bytes of
      `12345678901234567890` (or the 32-byte seed): upper, lower and mixed case; padded with `=` or `%3D`; the bare
      form with spaces. Compare the key bytes `TotpSeed` holds, not codes.
    - Remaining seconds at a step's first and last millisecond, for periods 30 and 60.
    - Break-it-once: compute with `totpSize: 7` (the digits row fails); pass the bare form to the library without
      removing its spaces (the spaces decode row fails: Otp.NET throws on a space).
13. **Trim and AOT warnings fail the Release publish.** Evidence on this base:
    - `dotnet publish TswapCli/TswapCli.csproj -c Release -p:TrimmerSingleWarn=false -p:IlcTreatWarningsAsErrors=true`
      on Linux x64 passes with no IL warning.
    - CI run 45839723503 (main): the "AOT publish" step (`ci.yml:132`, Release) shows none on any of the four legs.
    - The E2E step's Debug publish shows `warning IL2104: Assembly 'Yubico.YubiKey' produced trim warnings` on all
      four. Locally, with `TrimmerSingleWarn=false`, that is one
      `IL2026 Yubico.YubiKey.Cryptography.CryptographyProviders..cctor(): … HMAC.Create(String)`.

    Because of that Debug warning the error is Release-only, which is what ships. Mechanism (NativeAOT's ILCompiler
    reads both properties, `Microsoft.NETCore.Native.targets:31`, `:308`, `:311`): in `TswapCli/TswapCli.csproj`,
    - `<TrimmerSingleWarn>false</TrimmerSingleWarn>` in the first PropertyGroup, so a package's warnings are listed
      per member, not collapsed into one IL2104;
    - a new `<PropertyGroup Condition="'$(Configuration)' == 'Release'">` with
      `<IlcTreatWarningsAsErrors>true</IlcTreatWarningsAsErrors>` (ILC's `--warnaserror`: every IL2xxx/IL3xxx it
      reports is an error).

    Both get a comment saying why, and naming the Debug IL2026 above as known and pre-existing. `Directory.Build.props`
    can't take them: `DependencyPinningTests` (`PropsProperties`, `:61`) allows exactly three properties there. The
    implementer first re-runs the Release publish with both settings, here and from the newest main CI log. If any IL
    warning shows in Release, stop and report.

    Guard test `TswapTests/Build/AotWarningTests.cs`, reading files only:
    - the two settings are present as above, unconditional and Release-conditioned respectively;
    - no project file sets `IlcTreatWarningsAsErrors` false, `TrimmerSingleWarn` true, `SuppressTrimAnalysisWarnings`
      or `NoWarn`/`WarningsNotAsErrors` with an `IL2`/`IL3` code;
    - no file under `.github/workflows/` passes any of those as `-p:` (`release.yml` is read, not changed);
    - one positive row per forbidden form, proving the scan finds it in a sample string.

    Break-it-once, with output in the report: add a throwaway call of a `[RequiresUnreferencedCode]` method to
    `Program.cs`. The Release publish fails with `error IL2026`, and the Debug publish only warns. Revert it.
14. **Published-binary E2E** (`EndToEndTests`, which CI runs against the NativeAOT Debug publish via `TSWAP_E2E_BINARY`,
    `TswapBinaryFixture.cs:27`). Vault set-up as the existing tests do it: `TSWAP_TEST_KEY` and a temp
    `TSWAP_CONFIG_DIR` (`EndToEndTests.cs:63-65`), `init --yubikey --no-recovery` (`:340`). Values go in through
    `ingest` on stdin. The real clock runs inside the binary, so these tests assert shapes and absences only, never a
    code's value, and pass at any instant:
    - `tswap totp` on the SHA1 URI (6 digits) and on a SHA512 URI with `digits=8`: exit 0. Stdout is exactly one line
      of 6 (or 8) ASCII digits. Stderr has one line matching `^Valid for [0-9]+ more seconds? \(a new code every 30
      seconds\)\.$`.
    - `tswap run` with `{{t}}`: the child is a script (Unix `sh`, Windows `pwsh -File`, the pattern at `:388-391` and
      `:782`). It prints only value-free markers: `LEN=<length of $1>`, `DIGITS=yes` when `$1` is all digits, and
      `LEAK` when `$1` contains `otpauth` or the seed text, case ignored. Assert:
      - `LEN=6` (`LEN=8` for the SHA512 URI) and `DIGITS=yes`;
      - no `LEAK`;
      - stdout doesn't contain the URI, the seed text or `otpauth`.
    - `names --json`: the TOTP record's entry has `"kind": "totp"`, a plain one has no `kind`.
    - A refused URI (`digits=7`): `run` and `totp` exit 1 with the R11 refusal on stderr, and neither stream contains
      the URI or the seed.

    Break-it-once: make `CommandValues` return the stored value (the `LEAK` assertion fails in the published binary).
    Run it with `TSWAP_E2E_BINARY` pointed at a local Debug publish and report the output.
15. **Renovate.** `renovate.json5` (checked, unchanged): an Otp.NET bump matches only the NuGet `rangeStrategy: 'pin'`
    rule (and the majors rule). The only automerge rules are for test-package patches (`Microsoft.NET.Test.Sdk`,
    `xunit*`), the first GitHub Actions pin and global.json patches, and `config:recommended` sets no automerge. So an
    Otp.NET bump is always an ordinary PR, never automerged. `ci.yml` runs on `pull_request` with no path filter, on the
    four-OS matrix (`ci.yml:26`). That covers this class, the AOT publish of amendment 13 and the E2E tests of
    amendment 14. Whether Otp.NET joins the "security-critical packages" rule (no automerge either way, but a label and
    the owner's eye) is the owner's call. This brief doesn't change it, since `renovate.json5` is T59's.

### Amendments (round 2: MiMo on 209e7c1; controller rulings)

(Applied in the body.) Round 1b (amendments 12-15) is unaffected, except where
amendment 16 replaces amendment 11.

16. **When a kind entry is written (I-1; replaces amendment 11).** A kind entry is written only for a version being
    sealed now. Entries are never invented for a version a write merely carries: such a version keeps its entry if it
    has one and stays without one if it doesn't. Only `vault reindex` fills entries for carried versions, since it holds
    every value. The current kind is still always right for `run`, `totp` and `rotate`, because they decide from the
    value (amendment 1). The rule, the same on both write paths:
    - **New version** (`RecordWrites.NewVersion` and `RecordVaultStore.NextRecord`'s new-version branch, `:1535-1563`):
      the new version's entry from `Classify` of its value; the replaced current becomes previous and keeps its entry
      if it has one; every other entry is dropped. So `NextRecord` does change (amendment 11 said it needn't).
    - **Burn, field write, same value:** extensions untouched, as today.
    - **`PrepareV3`:** sets entries from both retained values only when `recomputeOlderSets` is true (reindex).
      Otherwise it leaves the extension as the write made it.

    `RecordWrites_MatchNextRecord_OnRandomStates` compares against `PrepareV3(…, recomputeOlderSets: false)`
    (`RecordWritesTests.cs:442`), so it holds the two paths equal under this rule. Its random states (a sanctioned
    test-input change) draw values that are otpauth URIs as well as plain ones. Each state's `ValueKinds` extension
    holds, at random, consistent entries, no entry for a retained version, or a stale entry for a stamp no longer
    retained. Add a Task 4 row: an entry-less previous version stays entry-less after a rotation, and gets its entry
    from `vault reindex`.
17. **One Base32 rule (I-2; replaces the order and B1/B3 wording of Task 1 and amendment 6).**
    - The checks run in the order B1, B2, B3, B4, B5.
    - **B1, the character set:** A-Z, a-z, 2-7 and `=`, with the text `the seed isn't Base32 (letters A-Z, digits 2-7,
      '=' padding)`.
    - **B2:** the unpadded length (the text before the first `=`) mod 8 is 1, 3 or 6.
    - **B3:** an `=` followed by any non-`=` character, or a non-empty trailing run of `=` that isn't exactly the run
      the unpadded length needs (mod 8 of 0: none; 2: six; 4: four; 5: three; 7: one). An empty run is always fine,
      so unpadded text of any valid length is accepted, padded or not.
    - **B4 and B5:** unchanged.

    This gives: `GEZD=GNB…` B3, `GEZDGNBVGY3TQOJQ=` B3, `GEZDGNBVGY3TQ==` B3, the 32-byte seed with and without
    `====` accepted.
18. **Refusal table (M-1):** 20 rows: R1-R11 one each, R12 two, B1 one, B2 one, B3 three, B4 one, B5 one.
19. **`rotate` text (M-2):** Task 4's sentence reads "when `Classify` of the decrypted current value is `Totp` or
    `OtpAuthUnusable` (amendment 1)". The refusal text is unchanged.
20. **Spaces and percent-hex (M-3).** A URI's `secret` loses its U+0020 spaces after percent-decoding, as the bare form
    does, so `%20`-grouped seeds are accepted. "Inside a URI no space is allowed" is withdrawn. Percent-escapes take
    either hex case (`%3d`, `%3D`; RFC 3986 2.1). Amendment 5's "as written" form covers such spellings: it is the
    parameter text before decoding.
21. **`CommandValues` surface (M-4).** Only the token-taking members (`ResolveToken`, `IsBurnedToken`) strip a `:totp`
    suffix. `Contains`, `HasPreviousValue` and `ThrowIfUnreadable` take names, as today; `Apply` and `Check` pass them
    the base name, with `:totp` stripped as `:previous` is. `StoredForms` is keyed by the token or marker name exactly as
    `ResolveToken` received it (`x`, `x:previous`, `x:totp`), the key `ApplySecretsReporting` reports its rows under.
22. **Split writes (M-5).** Add a Task 2 row: `_pty.ChunkSize = 3` (`RecordingPty.cs:18`). The child prints the code,
    then the URI. Output: `[REDACTED: t]` for each, nothing of either left.
23. **`ValueKinds.Of` (M-6)** takes the metadata only and gives the current version's kind. Nothing reads a previous
    version's mark. Entries for the previous version are still kept, so a restore keeps its mark.
24. **tswap's own strictness (M-7).** `docs/commands.md` marks each rule that is tswap's and not the Key Uri Format's as
    such, with its reason: B4 canonical-only, B5 the 80-bit floor, R12's 1-300, R6's case-sensitive names (R11's 6/8 and R10's list are the
    Key Uri Format's own, amendment 37).
    The controller's release note says that a short-seed or long-period service is refused.
25. **Task 2's table (M-8):** `sudo list` shows names and dates, no value (`ListCommand.cs:9`). Its cell reads
    "unchanged: no value"; `get`, `export` and `field adopt` keep "the stored value".

### Amendments (round 3: MiMo; controller ruling on I-1)

(Applied in the body.) Round 1b and round 2 are unaffected, except that
amendment 26 widens D1. The body lines that rounds 1-2 had left contradicting the amendments (the `CommandValues`
suffix sentence, `ValueKinds.Of`'s signature, the row count, the header's `VaultView` citation) are now edited in
place to match.

26. **Recognition: `otpauth:` anywhere (I-1; controller ruling, toward fail-closed; widens D1).**
    `OtpAuthUri.IsOtpAuth(value)` is true when the value contains `otpauth:` anywhere, case ignored. Before, it had to
    start the trimmed text. The strict parse is unchanged and runs on the value trimmed of `char.IsWhiteSpace`, as
    before. When that trimmed text doesn't start with `otpauth:` (case ignored), the parse fails with a new first
    reason:
    `R0 the value holds an otpauth URI among other text; store the URI alone`.
    This covers a labelled paste, a BOM (U+FEFF is not white space) and a URI on a later line. `Classify` gives
    `OtpAuthUnusable` for such a value. Every consumer refuses it:
    - `{{x}}`, `{{x:previous}}`, `{{x:totp}}`, `--env`, markers in `run` and `apply`, and `totp`, with the refusal text
      of Task 2 (its last sentence names `sudo <prefix> get x` and `sudo <prefix> add x`, per amendment 8);
    - the broker (D8), with its text;
    - `rotate` (amendment 1).

    `names` shows `[OTPAUTH: unusable]`. A value that merely mentions `otpauth:` (a note, a URL in a JSON blob) is
    thereby refused where it was passed on before. That is the intended price: such a value is used with sudo, or
    stored differently.

    New rows in Task 1's refusal table, which now has 23 rows:
    - `﻿otpauth://totp/…` (the SHA1 URI behind a BOM);
    - `certum-totp: otpauth://totp/…` (a labelled paste);
    - `user: alice\notpauth://totp/…` (two lines, the URI on the second).

    Each gives R0, and the message holds neither the URI nor the secret text.

    The same three values get end-to-end rows in Task 2. `{{t}}`, `--env OTP={{t}}` and `# tswap: t` are refused,
    exit 1, the child not started, and neither the URI nor the secret text appears on stdout or stderr. The broker
    row is refused with its text. `names` shows `[OTPAUTH: unusable]`. Task 1's `Classify` row gains them
    (`OtpAuthUnusable`), and a value with `otpauth` but no colon (`otpauth-backup-codes`) stays `None`.
    `docs/commands.md` and the prompt say: store the URI alone.
27. **Migration writes the kind (M-1).** `RecordVaultStore.WriteSnapshot` (`:1613-1640`, the `migrate --to-records`
    path, `RecordMigration.cs:163`) builds each record as a new version from its plaintext. It sets the entry from
    `Classify` of that value, as amendment 16 does for a version being sealed. New Task 4 row: a classic vault holding
    the SHA1 URI, migrated, shows `[TOTP]` without a reindex.
28. **AGENTS.md's agent rules (M-2).** Task 5 also adds `totp` to rule 3's command list (`AGENTS.md:349`, "Use `create`,
    `ingest`, `names`, `run`, …"), next to the No-sudo list (`:115`) and the "Token Substitution" sentence.
29. **B3 is tswap's own (M-3).** Amendment 24's list gains B3. An exact padding run is tswap's rule; the Key Uri Format
    says padding "should be omitted", and Otp.NET and Google Authenticator accept any run. Its reason: one key, one
    accepted spelling. The controller's release note mentions it.
30. **ILCompiler line numbers (M-4; refuted).** Amendment 13's `:31`, `:308`, `:311` are the lines of
    `Microsoft.NETCore.Native.targets` in the package the pinned SDK restores
    (`~/.nuget/packages/microsoft.dotnet.ilcompiler/11.0.0/build/`, checked). MiMo's `:32/:317/:320` are dotnet/runtime's
    main branch. The comment in `TswapCli.csproj` names the properties, not line numbers.
31. **Body contradictions and header (M-5, M-6):** fixed in place (above).

### Amendments (round 4: MiMo; controller rulings on I-1 and I-2)

(Applied in the body.) The body lines MiMo listed (M-1), and the lines
amendments 37-39 touch, are edited in place to match.

32. **No spaces in a URI's `secret` (I-1; controller ruling, fail closed; withdraws amendment 20's space part).**
    Under amendment 20, `secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ note` would merge into a 36-character key. That is a
    valid length and canonical, so it would silently give wrong codes; Otp.NET and Google Authenticator refuse it.
    So a URI's `secret` that contains U+0020 after percent-decoding is refused with a new reason, checked before B1:
    `R14 the secret parameter contains a space (a URI's secret is Base32 without spaces)`.
    Amendment 20's other part stays: percent-escapes in either hex case. A bare seed keeps its de-spacing, and a bare
    seed is used only through `:totp` (and `totp`). New refusal rows:
    - `secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ note`;
    - `secret=GEZD%20GNBV%20GY3T%20QOJQ%20GEZD%20GNBV%20GY3T%20QOJQ`.

    Both give R14, and the message holds neither the URI nor the secret text. The refusal table now has 25 rows.
33. **Masking routed per form (I-2).** `run` routes each `StoredForms` entry by its own length through the
    short-value test (`RunCommand.cs:177`), not by the code's. Every such entry is at least 16 characters (B5, and the
    URI is longer), so all go to `redactions` and are masked anywhere. Only the code goes to the short-value matcher:
    one `Redact(token, code, [])`, then one `Redact(token, form, [])` per stored form. New Task 2 rows, each giving
    `[REDACTED: t]` with nothing of the URI or seed left on stdout:
    - the child prints `x<URI>`;
    - it prints `-<URI>`;
    - it prints `x<seed, lower case unpadded>`.
34. **Doc block with the command (M-2).** Task 3's commit also regenerates the generated block of `docs/commands.md`
    (`TSWAP_REGENERATE_DOCS=1` on `CommandReferenceIsCurrent`), so `./runtests.sh --unit` passes after Task 3. Task 5
    adds only prose.
35. **`ValueKinds` fail-safe rows (M-3)** in Task 4:
    - a codec round trip pinning the layout: format byte `1`, count, then each entry's 28-byte stamp in
      `SecretRecordCodec`'s stamp encoding and its kind byte;
    - an extension of `0x0101` that is truncated, has an unknown format byte, an unknown kind byte, or a count of 0:
      `names` lists the record without a mark, nothing is unreadable, and `run` still gives the code;
    - a delete: the tombstone carries no `0x0101`.
36. **`SuppressAotAnalysisWarnings` (M-5).** Amendment 13's guard also forbids `SuppressAotAnalysisWarnings` true
    (ILC's `--noaotwarn`, `Microsoft.NETCore.Native.targets:313` in the pinned package), with a positive row.
37. **R11 and R10 are the spec's (M-4).** The Key Uri Format allows exactly `digits` 6 or 8 and the three algorithms.
    Amendment 24's "tswap's own" list is B3, B4, B5, R12, R6 and R14 (edited in place). docs/commands.md calls R10 and
    R11 the spec's rules.
38. **Bare seeds (M-6).** The security-model note says the seed never leaves without sudo for a record recognised as an
    otpauth URI. A bare Base32 value is never recognised (any random value may be Base32), so `{{name}}` still hands it
    out: give a bare seed only through `{{name:totp}}`. docs/commands.md and the prompt say so (edited in Task 5's
    bullet).
39. **Small gaps (M-7).**
    - Task 3's tests live in a new `TswapTests/TotpCommandTests.cs`, with its own value recorder copying `RunEnvTests`'
      (`_m.StoreOpened = store => store.ValueDecrypted = …`; `RunEnvTests._values` is private).
    - Renaming `Rotate_DecryptsNoValue` (amendment 1): the class summary of `WriteCommandDecryptionTests` adds
      "except `rotate`, which reads the current value once to refuse a TOTP seed (#374)".
    - Tombstones: the `0x0101` extension is dropped in `FieldEdits.ForTombstone`, which both tombstone paths call
      (`RecordWrites.Tombstone` and `RecordVaultStore.Tombstone`, `:1601-1604`). An older build keeps it on a tombstone, which is harmless:
      `SecretInfo.From` returns null for one.

