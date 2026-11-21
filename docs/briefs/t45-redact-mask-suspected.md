# Brief T45: `redact` masks what looks like an unrecognised secret, and its warning never shows the value (#389)

Issue: https://github.com/stevedcc/TokenSwap/issues/389 (with its correction comment). Milestone 0.3.2. Base:
`origin/main` at c1fbf62. Read AGENTS.md and CLAUDE.md first, then `TswapCore/Redact.cs`, `TswapCli/Commands/RedactCommand.cs`,
`TswapTests/RedactTests.cs` (the `FindUnknownSecrets` section), the redact tests in `TswapTests/CommandTests.cs`
(around `Redact_IncludesBurnedSecretValues`) and `docs/commands.md` (the "Fingerprints" paragraph near line 64 and the
`### redact` block).

One commit per task, test first, a break-it-once check per key test (name in the commit message which line you
changed and which test failed), `./runtests.sh --unit` after each task, the full `./runtests.sh` at the end. No
hardware suites, `ykman`, `sudo`, real YubiKeys or `~/.config/tswap`. Commits end with
`Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, explicit-path commits, no push, merge or rebase; stop and
report when the brief can't be built as written. **No existing test's assertions change.** If an existing test
expects an unknown, credential-looking value (a keyword from the heuristic followed by 12 or more value characters)
to come out of `redact` unchanged, stop and list those tests: that needs the owner's sanction.

## Why

`tswap redact <file>` prints the file with every value the vault knows replaced by `[REDACTED: name]`, then runs a
heuristic (`Redact.CredentialHeuristic`: a keyword such as `password`, `token`, `secret`, `key`, `apikey`, `pass`,
then `:` or `=`, then 12 or more of `[A-Za-z0-9+/\-_]`) and prints one warning per hit to stderr:

```
⚠ Line {n}: possible unrecognised secret: {snippet}
```

`FindUnknownSecrets` returns `lines[i].Trim()` as the snippet, so the warning repeats the whole line, value included.
And the value is on stdout too: the vault doesn't know it, so nothing masked it. A user pasting `redact`'s output into
an issue, or an agent reading it, gets exactly the value the heuristic suspected. The owner chose (2026-11-21, #389) to
mask suspected values as well, accepting that a false positive (a long public identifier after `key:`) gets masked
too: for a redaction tool, masking too much is the safe side.

## Task 1: `Redact.MaskUnknownSecrets`

In `TswapCore/Redact.cs`, replace `FindUnknownSecrets` with

```csharp
public static (string Masked, IReadOnlyList<(int Line, string Keyword)> Hits) MaskUnknownSecrets(string content)
```

- Every match of `CredentialHeuristic` has **only its value** (the regex's value group) replaced by
  `[POSSIBLE SECRET]`; the keyword, the separator, spaces and quotes stay. All matches on a line are masked.
- `Hits` has one entry per match, in order: the 1-based line number and the keyword exactly as it appears in the
  input (its own case). Nothing in `Hits` contains any value character.
- Line endings are kept exactly (`\n` and `\r\n` input both round-trip byte for byte apart from the masked values).
- The heuristic itself (keywords, the 12-character minimum, the character class) does not change.
- Remove `FindUnknownSecrets`. Its four tests in `RedactTests.cs` assert only counts and `Line`; move them to the new
  method as they are (same inputs, same assertions, the call renamed), which is not an assertion change.

Tests (in `RedactTests.cs`):

| Input | `Masked` | `Hits` |
|---|---|---|
| `password: abcdefghijklmno` | `password: [POSSIBLE SECRET]` | `(1, "password")` |
| `TOKEN="abcdefghijklmnop"` | `TOKEN="[POSSIBLE SECRET]"` | `(1, "TOKEN")` |
| `a: 1\r\napi_key=ABCDEFGHIJKLMNOP==\r\n` | `a: 1\r\napi_key=[POSSIBLE SECRET]\r\n` | `(2, "api_key")` |
| `password=aaaaaaaaaaaaaa token=bbbbbbbbbbbbbbbb` | both values masked | two hits on line 1, in order |
| `password: short` (5 characters) | unchanged | empty |
| `hostname: abcdefghijklmno` | unchanged | empty |
| `password: [REDACTED: db-pw]` (already masked) | unchanged | empty |

Each test also asserts that no `Hits` keyword contains a value character from its input.

Break-it-once: make `MaskUnknownSecrets` return `content` unchanged; the first row's test must fail.

## Task 2: `redact` prints the masked text and a value-free warning

In `RedactCommand`: run `MaskUnknownSecrets` on the fingerprint-redacted text, write **`Masked`** to stdout (instead of
the redacted text), then for each hit write to stderr:

```
⚠ Line {n}: possible unrecognised secret after '{keyword}', masked
```

Exit code stays 0. Nothing else in the command changes (the fingerprint refusal, the file checks, the order of
streams).

Test (in `CommandTests.cs`, next to `Redact_IncludesBurnedSecretValues`, same setup style): a vault with `db-pw` =
`known-secret-value-42`; a file

```
user: admin
password: known-secret-value-42
token: unknownsecretvalue9876
```

`tswap redact <file>` exits 0; stdout contains `password: [REDACTED: db-pw]` and `token: [POSSIBLE SECRET]`, and
contains `user: admin`; stderr contains `Line 3` and `'token'`; **neither stdout nor stderr contains
`known-secret-value-42` or `unknownsecretvalue9876`**.

Break-it-once (two runs): (a) write the unmasked redacted text to stdout again; (b) put the line back into the
warning. Each time the new command test must fail.

## Task 3: docs

- `docs/commands.md`, the fingerprints paragraph near line 64: one sentence after it says that `redact` also masks a
  value that looks like a credential it doesn't know (a keyword such as `password`, `token`, `secret` or `key`, then 12
  or more characters) as `[POSSIBLE SECRET]`, with a warning on stderr naming the line and the keyword, never the
  value; and that a short or unusual value can still slip through, so check the output before sharing it.
- The command reference block (`### redact`) and `RedactCommand.Description` stay as they are.
- `TswapCore/Prompt.cs` stays as it is (its `redact` line remains true).

## Amendments (round 1)

- **A1 (both reviewers; controller ruling).** The mask covers the **whole run** that starts at the value group: from the
  group's first character up to, not including, the next whitespace, `"`, `'`, `,`, `;`, `)`, `]`, `}` or the end of the
  line. Matching itself does not change (keywords, the 12-character minimum, the character class): only how much of the
  line is replaced. Add these rows to Task 1's table:

  | Input | `Masked` | `Hits` |
  |---|---|---|
  | `password: CorrectHorse!Battery` | `password: [POSSIBLE SECRET]` | `(1, "password")` |
  | `token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl` | `token: [POSSIBLE SECRET]` | `(1, "token")` |
  | `token="abcdefghijkl!x" next` | `token="[POSSIBLE SECRET]" next` | `(1, "token")` |
  | `password=aaaaaaaaaaaaaa,user=bob` | `password=[POSSIBLE SECRET],user=bob` | `(1, "password")` |
  | `password=aaaaaaaaaaaaaatoken=bbbbbbbbbbbbbbbb` | `password=[POSSIBLE SECRET]` | one hit, `(1, "password")` |

  The existing rows keep their expected results. The Task 2 warning text stays.
- **A2 (both).** Replace "asserts that no `Hits` keyword contains a value character from its input" with: for every
  row, the masked run's original text (the characters replaced, as the test computes from its input) appears nowhere
  in `Masked` and in no `Hits` keyword (`Assert.DoesNotContain(run, masked)`, and the same for each keyword).
- **A3 (GLM).** Task 1 adds `MaskUnknownSecrets` and moves the four tests, but keeps `FindUnknownSecrets` so the build
  stays green; Task 2 switches `RedactCommand` over and removes `FindUnknownSecrets`.
- **A4 (MiMo).** Capture the keyword in its own named group in `CredentialHeuristic` (matching unchanged) and report
  that group's text. A keyword inside a longer word (`monkey:` gives `key`) is reported as matched; that's accepted.
- **A5 (MiMo).** Task 3 also updates `docs/security-model.md` (the bullet near line 259 that says a deleted secret's
  stored value is printed unmasked by `redact`): add "unless it matches the unknown-secret heuristic, which masks it
  as `[POSSIBLE SECRET]`".
- **A6 (MiMo).** Task 2's commit message says the warning's format changed on purpose. `TswapCore/Prompt.cs` stays as
  it is (no prompt-hash change for this).

## Out of scope

- The guessing-oracle rate limit for redaction (#252).
- `tocomment`, `run` and the broker's redaction.
- Changing the heuristic's keywords or its 12-character minimum.
