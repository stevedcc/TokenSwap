# Command reference

This page is for anyone who runs tswap by hand or from scripts. It lists every command with its usage,
which commands need sudo, the environment variables tswap reads, and the files it writes.

Setting up a vault step by step, with the guided `init`, is in [setup.md](setup.md).

The per-command part is generated from tswap's own help text. A test checks it and the list of
environment variables against the code; the Files section is not checked.

## Which commands need sudo

A command whose usage line below starts with `sudo` needs sudo. Four commands mix the two:

- `slot` is marked `sudo` as a whole, but only some of its subcommands check for it.
- `broker` is marked without `sudo`, but the subcommands that change `broker.json` need it.
- `vault` is marked `sudo` as a whole, but `vault move` needs none.
- `field` is marked without `sudo`: setting, removing and showing fields needs none; only `field adopt`, which turns
  a secret value into a visible field, needs it.

This table lists each of their subcommands. "sudo" means it refuses to run without sudo.

| Subcommand | Sudo | Why |
|---|---|---|
| `slot request` | no | Runs on the new machine, which has no usable vault yet; it touches no existing vault's secrets |
| `slot approve` | sudo | Unlocks this vault and writes a file that lets whoever holds the request's private key open it: the same risk as `export` |
| `slot accept` | no | Finishes enrolment on the new machine. On a record-store vault, or with `--vault-dir`, it also writes the new slot into the vault folder's keyring; the human check for that slot was the earlier `sudo tswap slot approve` |
| `slot merge` | sudo | Adds the slots of a receipt: each one is a new way to open the vault |
| `slot enroll` | no | Runs request and accept here; approve and merge run on the other machine over SSH, under its sudo (human use only) |
| `slot stage` | no | Moves the enrolment files between the SSH session and the host's staging folder; refused under sudo on Unix |
| `slot add` | sudo | Adds a plugged-in YubiKey (its OTP challenge-response, or a FIDO2 credential) or another brand's security key (a FIDO2 credential), or this machine's TPM or Secure Enclave, as a new slot: a new way to open the vault |
| `broker serve` | no | Runs as the vault's own user; it refuses root |
| `broker unlock` | no | Runs as the vault user; it refuses sudo |
| `broker lock` | no | Runs as the vault user; it refuses sudo |
| `broker status` | no | Runs as the vault user; it refuses sudo |
| `broker forward` | no | Runs inside the container; it needs no vault |
| `broker call` | no | Runs inside the container; it needs no vault |
| `broker route add` | sudo | Changes `broker.json`, which decides which credentials containers can use |
| `broker route remove` | sudo | Changes `broker.json`, as above |
| `broker socket add` | sudo | Changes `broker.json`, as above |
| `broker socket bind` | sudo | Changes `broker.json`, as above |
| `broker socket remove` | sudo | Changes `broker.json`, as above |
| `broker template add` | sudo | Changes `broker.json`: a template runs host-side commands with vault secrets |
| `broker template remove` | sudo | Changes `broker.json`, as above |
| `vault merge` | sudo | Decrypts every record of both copies, and may add the other copy's slots: each one a new way to open the vault |
| `vault reindex` | sudo | Decrypts every value once to rewrite each record with fingerprints |
| `vault move` | no | Moves this machine's encrypted files and edits only its own config; it refuses sudo on Unix (an elevated Windows prompt is fine) |
| `field set` | no | Fields are plain, visible data, never secret; every value is checked against the stored secrets' fingerprints first |
| `field unset` | no | Removes plain fields; no secret value is read or changed |
| `field show` | no | Prints plain fields only; no secret value is decrypted |
| `field adopt` | sudo | Decrypts a secret's value and turns it into a visible field (deleting that secret): the one deliberate path from secret to visible, so the owner approves each |

A FIDO2 slot, on a YubiKey or a security key of another brand, needs tswap 0.3.0 or newer on every
machine that opens it: 0.2.x has no FIDO2 slots and can't open a vault through one.
Upgrade.

Three commands marked without `sudo` have one case that needs it, as their descriptions below say:
`rotate` and `ingest --rotate` need sudo unless the secret is burned, and `migrate --to-records` needs sudo.

On Windows there is no sudo: run a command that needs it from an elevated command prompt.

## Fingerprints, format 2 records and `vault reindex`

`redact` and `tocomment` recognise secrets by the keyed fingerprints in each record's encrypted
metadata and decrypt no value (since 0.3; what every command decrypts:
[security-model.md](security-model.md#what-each-command-decrypts)). A record without fingerprints
can't be recognised, so on a vault holding one they refuse, exit 1, print nothing on stdout and
don't open the file. The message (one line on stderr, after `❌ Error:`, wrapped here):

```
'redact' recognises secrets by their fingerprints, and 2 record(s) in this vault have none yet
(written by an older tswap, or the vault was never reindexed). Ask the user to run
`sudo tswap vault reindex`. The file was not read.
```

(`tocomment` adds "or changed".) Such records are format 2 ones (from tswap 0.1, or written since
by a 0.1 machine on a shared folder) and format 3 ones written without fingerprints. Run
`sudo tswap vault reindex` once ([what it does](multi-machine.md#record-format-3-and-vault-reindex)).
Records fingerprinted by an older tswap are still matched with the fingerprints they have; the
commands print a note naming the count and the reindex, which adds the newer variants.

The other reading commands keep working on format 2 records: `names`, `list`, `burned`, and
`check`, `get` or `apply` on a record they name, decrypt such a record whole (the only way to read
format 2), wipe the values they don't use, and print one line on stderr after their output, with
the number of records and the same fix (when they fail, before the error). Exit codes don't change.
The write commands (`create`, `ingest`, `rotate`, `burn`, `restore`, `add`, `delete`, `import`; since
0.3 each reads only the records of the names it is given, `import` every exported name so it can skip
the ones the vault holds) do the same for a format 2 record they read: they decrypt it whole, wipe the
value versions they don't need, and print the warning after their output (when they fail, before the
error), also when they then write nothing (`create` of an existing name, `add` of the same value,
`import` skipping a name).
None of these texts (the refusal, the note, the warning) ever names a secret, a file or a value.
(The errors about one unreadable record name its hashed file, so it can be restored.)

Other changes in 0.3, from reading metadata only: `redact` masks a multi-line value (a PEM key) across
lines; neither command matches a secret inside or across a label or marker it inserted itself;
`tocomment --dry-run` redacts its "before" lines in one pass, so a value spanning two changed lines is
masked there too; `get` and `apply` no longer report records they don't read; `check` no longer stops
on an unreadable format 2 record that no marker names; and conflicted copies that only their
plaintext could show equal make `list` and `check` refuse that record
([details](security-model.md#what-each-command-decrypts)).
`tocomment` also adopts a YAML literal block scalar (`key: |`, `|-` or `|+`) whose content is exactly
one stored value, a PEM key say: the key line becomes `key: ""  # tswap: <name>` and the block's lines
go (`--dry-run` shows them as `[removed block line]`, never their text). Inside a block scalar (`|` or
`>`, with any indicators, anchor or tag), a line holding an **encoded** form of a value (base64, base64url or
the value without its whitespace) is left as it is, with a warning naming the line number and the
secret, because a marker is always filled with the plain value. A plain value inside a block is still
replaced by a marker, whose `#` then becomes part of the block's text: right for shell scripts and
YAML kept in a block, not for JSON. Known gaps, handled as any other line: a document-root block
(`--- |`, `--- >`), a bare nested entry (`- - |`), an empty key (`: |`) and keys containing `#`
(`- - key: |` and `? key: |` are recognised). `check` warns (exit 2) about a
marker under `data:` in a `kind: Secret` manifest, where Kubernetes expects base64 but the marker gets
the raw value: use `stringData:` (JSON status `data-not-base64`).

`run` (since 0.3) decrypts only the value versions it substitutes and masks every other value in the
vault that has fingerprints, in its stored forms (verbatim, whitespace-stripped, base64, base64url),
also a multi-line one printed through a terminal ([what `run` masks](security-model.md#what-run-masks)).
On a vault where some records can't be matched it keeps working and prints one line on stderr before
the command starts and the same line after it exits (wrapped here):

```
Warning: 2 record(s) are not fully fingerprinted, 1 can't be read: 'run' masks the secrets it
substitutes and the fingerprinted values, not these. Ask the user to run `sudo tswap vault reindex`.
```

(", … can't be read" only when a record can't be read.) A format 2 record a token or marker names is
decrypted whole, with the warning above after the command's output. Exit codes don't change; a
redaction failure ends `run` with exit 1 after the command, its output cut off at the failure.

## Fields: plain data next to a secret

Fields are bundled storage for convenience: everything about a credential is kept in one place next to its
secret (the username, the URL, where the value is used, where its master copy lives, how to rotate it). They are
plain, visible data, not a second kind of secret and not a way into commands. `field show` prints them, nothing
redacts them, nothing burns them, and no command substitutes them: `run` refuses any `{{NAME.anything}}` token,
and `run … {{@file}}` and `apply` refuse any `# tswap: NAME.anything` marker, instead of filling in NAME's value
(`'{{db.url}}' is a field: fields aren't substituted into commands. Read it with 'tswap field show db' and write
the value into the command.`). Setting, removing and showing fields needs no sudo; `field adopt` needs it
([the sudo table](#which-commands-need-sudo)).

```bash
# key=value, repeatable: for people, quick changes and voice through an agent
tswap create grafana-admin 32 --field username=admin --field source=generated:tswap
tswap field set opnsense-root url=https://192.168.1.1 kind=password --by owner
tswap field unset opnsense-root url

# JSON: for agents, files and longer or multi-line values
tswap create grafana-admin 32 --fields '{"username": "admin", "source": "generated:tswap"}'
printf '%s' "$TOKEN" | tswap ingest cloudflare-ddns --fields '{"kind": "api-key", "source": "external:cloudflare"}'
tswap field set opnsense-root @fields.json

tswap field show opnsense-root              # one line per field, each value a JSON string
tswap field show opnsense-root --json       # one JSON object of the fields: the form for agents
tswap field show opnsense-root --history    # each field's last changes, removed fields included
```

- **Only the fields given change**, like an object initializer; every other field keeps its value. In JSON,
  `null` removes a field (`{"url": null}`); in the key=value form only `field unset` removes one, and an empty
  `FIELD=` is refused. key=value splits at the first `=`, so a value may contain `=`; a value with a line break
  needs JSON. JSON is one flat object whose values are strings or `null` (anything else, or a key given twice, is
  refused naming the key); `@FILE` reads it from a file, never from stdin. One form per call: `--field` and
  `--fields` (or key=value and JSON in `field set`) together are refused.
- **The value commands** `create`, `ingest`, `ingest --rotate`, `rotate` and `sudo tswap add` take
  `--field FIELD=VALUE` (repeatable) or `--fields JSON|@FILE`, and `--by LABEL`: the value and the fields land in
  one record write. All or nothing: every name, value, format, cap and the check below is done first, and if
  anything is refused nothing is written, the value included. Without `--field`/`--fields` they write the value
  alone and keep the fields as they are (`burn` and `restore` keep them too).
- **Names** are `[a-z0-9_-]`, 1-64 characters. **Values** are stored in Unicode NFC form, at most 4096
  characters; line feeds are allowed, other control characters, format characters (bidi overrides, zero-width
  characters), surrogates and private-use characters are refused naming the field and the code point. A secret
  holds at most 64 live fields and 64 KiB of encoded fields (removed-field markers count towards the bytes). A
  merged copy may be over a cap ([multi-machine.md](multi-machine.md#the-merge-rules)); then only a write that
  shrinks it (`field unset`, or shorter values) is accepted. `field unset` brings a secret back under the 64-field
  cap, but frees few bytes: a removed field's marker keeps its history, so over 64 KiB only shorter values help.
- **Well-known fields**, checked when set:

  | Field | Meaning | Format |
  |---|---|---|
  | `consumers` | where the value is used | one entry per line, free text; conventions `k8s:<ns>/<secret>#<key>`, `file:<repo>/<path>`, `chargehand:<setting>`, `external:<system>` |
  | `source` | where the master copy lives, or who manages it | free text; conventions `generated:tswap`, `bitwarden[:<item>]`, `managed:<system>`, `external:<system>[/<id>]` |
  | `kind` | what the value is | one of `password`, `token`, `api-key`, `private-key`, `certificate`, `connection-string`, `other` |
  | `expires` | when the value stops working | `YYYY-MM-DD` or `YYYY-MM-DDTHH:MM:SSZ` (UTC with `Z`), nothing else |
  | `rotate` | how to rotate it | free text, may be several lines |

  `username`, `url`, `host` and `port` are conventions, not checked.
- **No secret in a field.** Every value is checked against the fingerprints of every stored value (every retained
  version of every live secret, burned ones included; no value is decrypted), and with a value command also against
  the value of that call. A value that contains one is refused without naming which secret:
  `Refused: the value for 'NAME.FIELD' contains a stored secret value. Fields are visible; a secret never goes in
  one.` A value of 20 or more characters from the base64 or hex alphabet with no space is written with a warning
  on stderr asking whether it is a secret. The check's limits:
  [security-model.md](security-model.md#fields-plain-visible-data).
- **A new value already in a field.** `add`, `ingest`, `ingest --rotate` and `rotate` warn on stderr, naming each
  `NAME.FIELD` (never the value) that contains the value they just wrote, **only when the same call gives
  `--field` or `--fields`**: without them a value write reads only its own record, no other record's fields, so it
  can't look. (`field set` refuses the other direction, a field holding a stored value, in every case.)
- **Not before the reindex.** A field write that sets a value (`field set`, `field adopt`, or a value command with
  `--field`/`--fields`) on a vault where records have no fingerprints yet (format 2) is refused before anything is
  written, as `redact` is: the check above can't see a value without fingerprints. `field unset` sets no value, so
  it works there. Run `sudo tswap vault reindex`
  once ([above](#fingerprints-format-2-records-and-vault-reindex)). `field show` keeps working. A classic vault's
  field commands refuse, like every other command there, and point to `sudo tswap migrate --to-records`.
- **`field show`** prints the live fields, each value as a JSON string (quoted, escaped), so a value can't pass as
  tswap's own text; `--json` prints one JSON object of the same shape `field set` takes, so show, edit and set
  round-trip. `--history` adds each field's current state and the 5 states before it, newest first, each with
  the UTC time, the operating-system user (the invoking user under sudo; `DOMAIN\user` on Windows), whether it
  ran elevated and with a terminal, the
  `--by` label and the machine (origin id). It lists **removed fields too**, marked `(removed)`, with who removed
  them and when; plain `show` lists live fields only. The user name is what that machine reports and `--by` is
  self-asserted: a history, not an authentication. `--json --history` adds the same under `history`.
- **`sudo tswap field adopt NAME FIELD --from SECRET`** copies SECRET's current value (burned or not: the main
  case is a username once stored as a secret) into the field `NAME.FIELD`, then deletes SECRET, in one commit. It
  refuses when SECRET is NAME, when either doesn't exist, when `NAME.FIELD` has a value already (unset it first),
  when SECRET has fields of its own (move them first) and when another live secret holds the same value. It is the
  one deliberate path from secret to visible; no refusal prints the value.
- `field set`, `unset` and `show` on a name that doesn't exist, or was deleted, refuse (`No secret 'NAME'.`).
  Deleting a secret drops its fields; a secret created again under that name starts with none.
- `export` carries each secret's current fields (no history, no removed fields); see the
  [export note](security-model.md#a-shared-vault-folder-what-a-sync-provider-sees-and-what-isnt-detected) on a
  field removed after an export. `import` applies no caps, as a merge doesn't: a secret a merge left over 64 fields
  or 64 KiB is restored with every field, and afterwards accepts only writes that shrink it.

## Commands

`sudo tswap add <name>` stores the value exactly as it was typed or piped. When the value ends in
whitespace (or is only whitespace) it prints one warning line on stderr after its success line, also
when the value was already stored: such a value is usually a paste mistake, and `run` can't always
mask it ([what `run` masks](security-model.md#what-run-masks)). The line names the secret and the
reason only, never the value, its length or which whitespace, and the exit code doesn't change.
(`ingest` trims trailing whitespace, and refuses an input of whitespace only.)

`add`, `ingest`, `ingest --rotate`, `create` and `rotate` also print one warning line on stderr after
their success line (in `add`, after the whitespace warning) when the value they store is shorter than
8 characters: for `add` the typed or piped value (also when it was already stored), for `ingest` the
value after trimming, for `create` and `rotate` the generated value (exactly the length asked for; the
default 32 never warns). `run`, `redact` and `tocomment` match a value wherever it appears, also inside
longer words and numbers, so a short value gets hidden in unrelated output and gives itself away
([what `run` masks](security-model.md#what-run-masks)); a username, a port or a setting doesn't belong
in tswap. The line names the secret and the reason only, never the value or its length; the command
still succeeds and its exit code doesn't change. `restore`, `import`, `vault merge` and `migrate` write
values that were already stored and don't warn.

<!-- BEGIN GENERATED: commands (TswapTests/Docs/CommandReference.cs) -->

### init

```
tswap init [--yubikey|--fido2 [--serial <n>]|--tpm|--secure-enclave --with-touch|--no-touch] [--password|--no-password] [--no-recovery|--recovery-key-out <file>] [--folder <dir>] | init --vault-dir <shared folder>
```

Create a record vault (one file per secret, shareable by sync tools) in \<config dir\>/vault, or in --folder \<dir\> (absent or empty, e.g. a sync folder). At a terminal, plain init is a guided setup: it lists this machine's YubiKeys and other security keys, and TPM or Secure Enclave, makes a slot for each one you pick, and shows how to add other machines. Without a terminal, name the slot: --yubikey (one YubiKey; add keys with 'slot add --yubikey'), --tpm (Windows/Linux) or --secure-enclave (macOS; needs --with-touch, Touch ID or password on every unlock, or --no-touch: no prompt, read its warning). --fido2 names the slot too but still needs a terminal: one security key's FIDO2 credential (any brand with hmac-secret and a FIDO2 PIN; on Linux and macOS other brands than YubiKeys need libfido2), its PIN typed at the terminal and a touch on every unlock (--serial picks a YubiKey by its serial on Linux and macOS). Plus a recovery slot unless --no-recovery; its key is printed once, and when stdout is not a terminal init refuses unless --recovery-key-out \<file\> names a new file for it (readable by you only; never overwritten). --password gives the slot a vault password (asked for on a terminal when neither --password nor --no-password is given). --vault-dir joins a folder another machine shares

### slot

```
sudo tswap slot request [--tpm|--secure-enclave --with-touch|--no-touch] [--password|--no-password] [--vault-dir <folder>] <file> | slot approve <request-file> <approve-file> | slot approve - - | slot approve --staged <id> --expect <sha256-hex> | slot accept <file> [--receipt <file>] [--vault-dir <shared folder>] | slot merge <receipt> [--yes] | slot merge - | slot merge --staged <id> --expect <sha256-hex> | slot enroll --via <user@host> [--tpm|--secure-enclave --with-touch|--no-touch] [--password|--no-password] [--vault-dir <folder>] [--remote-tswap <path>] [--no-remote-sudo] [--fresh] [--batch] | slot stage <id> put request|receipt | slot stage <id> get approve | slot stage <id> clean | slot add --tpm [--password|--no-password] | slot add --secure-enclave --with-touch|--no-touch [--password|--no-password] | slot add --fido2 [--serial <n>] | slot add --yubikey (approve, merge and add take --recovery-key-stdin)
```

Enroll another machine into a keyring vault via hand-carried files (request, approve, accept, merge), or in one command run on the new machine over SSH (slot enroll --via \<user@host\>: request and accept there, approve and merge on the machine that opens the vault, under its sudo on a terminal of their own, so sudo and the vault may ask for a password there; it needs a terminal here, and --batch runs it without one, under sudo -n with no prompt on the host; --remote-tswap names tswap's path there, --no-remote-sudo drops sudo, --fresh starts a new enrolment instead of continuing a kept one; for a person, never an agent), or add this machine's TPM or Secure Enclave (--tpm, --secure-enclave with --with-touch or --no-touch; it then opens the vault on this machine) or a plugged-in YubiKey or other security key to this machine's keyring as its own slot (--yubikey: a YubiKey's OTP challenge-response; --fido2: a FIDO2 credential on a key of any brand, its PIN and a touch on every unlock, read at the terminal; --serial picks a YubiKey by its serial on Linux and macOS); slot request --secure-enclave and slot add --secure-enclave need --with-touch (Touch ID or password on every unlock) or --no-touch (no prompt; read its warning). A '-' file is stdin or stdout: slot approve - - reads the request from stdin and writes the approve file to stdout (every other line goes to stderr), as do slot approve - \<approve-file\> and slot approve \<request-file\> - for one of the two, and slot merge - reads the receipt from stdin. slot stage \<id\> put|get|clean (no sudo, refused under sudo; run by slot enroll) moves the enrolment files between an SSH session and the host's staging folder (\<config dir\>/enrol-staged/\<id\>), and slot approve --staged \<id\> --expect \<sha256-hex\> and slot merge --staged \<id\> --expect \<sha256-hex\> read the staged file, refusing one whose SHA-256 isn't the one given

### migrate

```
tswap migrate [--to-records [--vault-dir <dir>]]
```

Guide to upgrade slots for touch requirement; --to-records (sudo) converts the vault to one file per secret, shareable by sync tools

### create

```
tswap create <name> [len] [--field FIELD=VALUE]… [--fields JSON|@FILE] [--by LABEL]
```

Generate random secret (no display); --field (repeatable) or --fields sets plain fields in the same write, --by labels that change

### ingest

```
tswap ingest [--rotate] <name> [--field FIELD=VALUE]… [--fields JSON|@FILE] [--by LABEL]
```

Pipe secret from stdin (no display); --rotate replaces an existing one (sudo unless it is burned); --field (repeatable) or --fields sets plain fields in the same write, --by labels that change

### rotate

```
tswap rotate <name> [len] [--field FIELD=VALUE]… [--fields JSON|@FILE] [--by LABEL]
```

Replace a secret with a new random value (no display); sudo unless it is burned; --field (repeatable) or --fields sets plain fields in the same write, --by labels that change

### names

```
tswap names [--json]
```

List secret names (no values)

### slots

```
tswap slots [--ack]
```

List the vault's slots and what protects each one (--ack: acknowledge the YubiKeys' touch settings)

### yubikey

```
tswap yubikey setup (--touch|--no-touch) [--serial N] [--replace]
```

Prepare a YubiKey's slot 2 for challenge-response (a configured slot is overwritten only with --replace)

### agent

```
tswap agent <start [--timeout <d>]|serve [--foreground]|stop|status>
```

Hold the vault password in memory so commands need no prompt, like ssh-agent (run as the vault user, never with sudo)

### run

```
tswap run [--env NAME={{name}}]... [--] <cmd> [args...]
```

Execute with {{token}} and {{@file}} substitution; --env sets a secret in the command's environment instead of its arguments

### check

```
tswap check <path> [--json]
```

Verify # tswap: markers in file/dir

### redact

```
tswap redact <file>
```

Output file with secret values redacted

### tocomment

```
tswap tocomment <file> [--dry-run]
```

Replace inline secrets with # tswap: comments

### apply

```
sudo tswap apply <file>
```

Print a file with # tswap: markers filled in (human use; agents: run … {{@file}})

### burn

```
tswap burn <name> [reason]
```

Mark a secret as burned

### burned

```
tswap burned [--json]
```

List all burned secrets

### field

```
tswap field set NAME <FIELD=VALUE…|JSON|@FILE> [--by LABEL] | field unset NAME FIELD… [--by LABEL] | field show NAME [--history] [--json] | field adopt NAME FIELD --from SECRET
```

Plain, visible fields on a secret (username, url, consumers, source, kind, expires, rotate, ...): never secret, never substituted into commands; sudo for adopt

### prompt

```
tswap prompt
```

Show AI agent instructions

### prompt-hash

```
tswap prompt-hash
```

Hash of agent instructions

### installscript

```
tswap installscript
```

Generate a platform install script (redirect to a file, review, then run)

### add

```
sudo tswap add <name> [--field FIELD=VALUE]… [--fields JSON|@FILE] [--by LABEL]
```

Add a secret (user-provided value); --field (repeatable) or --fields sets plain fields in the same write, --by labels that change

### get

```
sudo tswap get <name>
```

Get a secret value

### list

```
sudo tswap list
```

List all secrets (names and dates, no values)

### delete

```
sudo tswap delete <name>
```

Delete a secret

### restore

```
sudo tswap restore <name>
```

Put back the value a rotation replaced, as a new version (record store)

### export

```
sudo tswap export <file>
```

Export all secrets to an encrypted backup

### import

```
sudo tswap import [--include-burned] <file>
```

Import secrets from an encrypted backup (burned secrets skipped by default)

### vault

```
sudo tswap vault merge <other-vault-dir> [--yes] (takes --recovery-key-stdin) | vault reindex | vault move <new-folder> [--yes]
```

Merge another copy of this record-store vault folder (scp/rsync/USB) into this one: keyring union, records by the merge rules; reindex: rewrite every record in record format 3 with fingerprints; move (no sudo): move this machine's vault folder (copied, checked, the old one kept renamed), e.g. out of the config folder before sharing it

### recover

```
sudo tswap recover --yubikey|--tpm|--secure-enclave --with-touch|--no-touch [--password|--no-password] [--recovery-key-stdin]  (recovery key on stdin)
```

Break glass: open the vault with the recovery private key (piped on stdin) and enroll this machine's YubiKey, TPM or Secure Enclave as a new slot (--secure-enclave needs --with-touch or --no-touch)

### completion

```
tswap completion <bash|zsh|fish|powershell>
```

Print a shell completion script

### broker

```
tswap broker <serve|unlock|lock|status|forward|call|route|socket|template> ...
```

Credentials for containers that never hold them: HTTP routes, command templates and an ssh-agent (serve, and unlock|lock|status for a broker whose slot has the vault password, as the vault user; forward/call in the container; sudo for route|socket|template add|remove)

### version

```
tswap version
```

Print tswap's version (also: --version)

<!-- END GENERATED: commands -->

## `run --env`

`tswap run --env PGPASSWORD={{db-pw}} -- psql -h db -U app` sets `PGPASSWORD` in the command's environment only
(not tswap's, not the calling shell's), so the value is not in its arguments; it is masked in the output like a
`{{name}}` in an argument. Give `--env NAME={{name}}` (or `--env=NAME={{name}}`) once per variable, at most 64, before
the command; an optional `--` ends them, and an `--env` after the command is the command's own argument. The value
is exactly one `{{name}}` or `{{name:previous}}` token: a literal is refused (it isn't a secret, so set it in your
shell, where the command inherits it), and so is a `{{@file}}` (put that in the command). Refused names, compared
ignoring case: `PATH`, `PATHEXT`, `LC_ALL`, `PWD`, `LD_*`, `DYLD_*`, `ComSpec`, `PSModulePath`, and the names and
prefixes the broker's command templates refuse because they can make a program run code or load files they name
(`BASH_ENV`, `GIT_SSH_COMMAND`, `PAGER`, `HOME`, `PYTHON*`, `NODE_*`, `JAVA*`, `XDG_*`, …;
[BROKER.md](BROKER.md#secrets-reach-the-child-through-env-or-a-read-only-file-only)). That knowingly includes
harmless ones such as `NODE_ENV`, `JAVA_HOME` or the `XDG_*` folders: set those in your shell too.

What it protects against: other local users and command-line logging. On Linux every local user can read a
running process's arguments in `/proc/<pid>/cmdline` unless `/proc` is mounted with `hidepid`; its environment only
the same user and root ([who can read what](security-model.md#who-can-read-a-secret-run-hands-to-a-command)). It
gains nothing against the agent itself, which runs as the same user as the command. On a machine with several users,
mount `/proc` with `hidepid=invisible,gid=<group>`, which hides one user's processes from the others (also for tools
that take a secret only as an argument); the broker's vault user needs that group
([broker threat model](broker-threat-model.md#limits-of-the-identity-check)).

## Environment variables

| Variable | Effect |
|----------|--------|
| `TSWAP_CONFIG_DIR` | The config directory to use; overrides everything else, including the `sudo` home lookup |
| `TSWAP_YUBIKEY_SERIAL` | The YubiKey to unlock with when several are plugged in (see [Several YubiKeys plugged in](setup.md#several-yubikeys-plugged-in)); `sudo` drops it unless kept |
| `XDG_CONFIG_HOME` | Linux: the config base, when it is an absolute path (a relative one is ignored) |
| `XDG_RUNTIME_DIR` | Linux and macOS: where `run` puts the private folder holding the filled copies of its `{{@file}}` tokens, when it is an absolute path to a folder of your own (not a symlink) that no group or other user can write to; otherwise the temp folder. `slot enroll --via` keeps the socket of its shared SSH connection in `$XDG_RUNTIME_DIR/tswap-ssh` (a folder of your own, 0700; without the variable `<temp folder>/tswap-ssh-<uid>`) |
| `TSWAP_AGENT_SOCK` | The tswap agent's socket path (Unix only), for commands and for `agent start\|serve`, like `SSH_AUTH_SOCK`; it picks a path, not a trust level (the server's uid is checked as always). `sudo` drops it: root's commands find the vault owner's agent by the vault folder's owner (see [Which agent a command asks](vault-password-and-agent.md#which-agent-a-command-asks)) |

Commands that need no vault (`--help`, `<command> --help`, `--version`, `version`, `prompt`, `prompt-hash`, `completion`,
`installscript`, `broker forward`, `broker call`) work without a home folder; the others say "Cannot determine the config folder"
if there is none and `TSWAP_CONFIG_DIR` isn't set.

> **macOS and sudo:** tswap releases before 0.1.0 used `~/.config/tswap/` under `sudo` (and
> `~/Library/Application Support/tswap/` otherwise). If your vault is only in `~/.config/tswap/`,
> tswap stops and tells you to move it (or to set `TSWAP_CONFIG_DIR`); if both folders hold a
> vault, it refuses until you choose. It never moves or picks one by itself.

> **Upgrading from an earlier version?** tswap automatically renames `tswap-poc` to `tswap` on first run if the old directory exists and the new one does not. If both directories are present (e.g. you ran `init` twice), move your files manually: rename the `tswap-poc` folder beside the config directory (see [Files](#files)) to `tswap`, for example `~/.config/tswap-poc/` to `~/.config/tswap/` on Linux, `~/Library/Application Support/tswap-poc/` to `~/Library/Application Support/tswap/` on macOS, and `%APPDATA%\tswap-poc\` to `%APPDATA%\tswap\` on Windows.

## Files

| Platform | Config directory |
|----------|-----------------|
| Linux | `$XDG_CONFIG_HOME/tswap/` (only an absolute `XDG_CONFIG_HOME` counts), else `~/.config/tswap/` |
| macOS | `~/Library/Application Support/tswap/` (also under sudo; see the macOS note under [Environment variables](#environment-variables)) |
| Windows | `%APPDATA%\tswap\` |

The kinds of vault, in the words these pages use:

- A **keyring vault** keeps a random vault key wrapped once per slot (a YubiKey, a TPM, a Secure
  Enclave, the recovery key), so each slot opens it on its own.
- A **record vault** (or record-store vault) keeps one encrypted file per secret in a vault folder,
  with its keyring there too. Every vault `init` makes since 0.2 is a record vault and a keyring
  vault.
- A **classic** vault (from 0.1) is one encrypted file, `secrets.json.enc`; its `config.json`
  holds either an XOR share (two YubiKeys) or a keyring. tswap 0.2 only converts or exports it
  ([upgrading-from-0.1.md](upgrading-from-0.1.md)).

A **classic** vault:

```
<config directory>/
├── config.json         # this machine's config: YubiKey serials + XOR share, or the keyring and slot id
└── secrets.json.enc    # AES-256-GCM encrypted secrets database
```

A **record-store** vault (`migrate --to-records`, `init --vault-dir`) keeps only this machine's
`config.json` in the config directory (its slot, origin id and clock; never synced) and the
shareable part in the vault folder:

```
<vault folder>/          # default <config directory>/vault; --vault-dir puts it anywhere
├── keyring              # the vault key, wrapped once per slot
├── vault-password       # only with a vault password: Argon2id salt and parameters, verifier, key check
└── records/<hash>       # one encrypted record per secret; the file name is a keyed hash of the name
```

`vault-password` holds nothing usable without the vault key: its verifier and key check are
keyed with the vault key. If a sync tool leaves two different
copies, every password operation refuses until you keep one (`The vault folder has two different
vault-password files (...)`); a byte-identical copy is deleted on the next password write (only a
file matching the sync tools' conflict-copy names, never `vault-password` itself; a sync tool that
propagates that deletion does no harm). A lone conflict copy with no `vault-password` file refuses
too, and asks you to rename it to `vault-password` if it holds this vault's password.

The tswap agent's socket lives in the vault user's run folder, never in the config or vault
folder: `/run/user/<uid>/tswap/agent-<16 hex>.sock` on Linux (else `~/.cache/tswap/run/`),
`~/Library/Caches/tswap/run/` on macOS, a named pipe on Windows; a password broker's control socket
is `broker-<16 hex>/control.sock` in the same folder.

A command that backs up `config.json` before it writes (`slot add`, `slot merge` and others) copies
it to `config.json.bak-<UTC timestamp>` beside it (for example `config.json.bak-20261105T120000123Z`,
with `-1`, `-2` added when two fall in one millisecond), never overwriting an earlier backup. Under
sudo the backup is written as the folder's owner, mode 0600.

On Linux and macOS the folders are created 0700 and the files 0600; an existing vault with wider
permissions is narrowed on the next write, with a notice (reads change nothing). Windows: the
profile folder's permissions apply.

