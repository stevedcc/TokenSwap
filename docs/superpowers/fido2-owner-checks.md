# FIDO2 slots: the owner's hardware checks (v0.3.0)

The checks of the FIDO2 slot work (branch `feat/fido2-slot`) that only real keys can answer. No
automated test creates a credential or asks for a PIN on a real key, so everything below is the
owner's, run by hand. **Record what happens; nothing here is a prediction to confirm.** Where the
expected line differs from what you see, paste what you see: that is the finding.

What a user sees is in [setup.md, FIDO2 slots](../setup.md#fido2-slots); the format and the seam are
in [hardware-backends.md](../design/hardware-backends.md#yubikey-fido2-slots-v030-issue-193).

- **(A) Safe checks** run on the daily key. A FIDO2 slot's credential is non-discoverable: it
  takes no space on the key and touches nothing else on it (no passkey, no slot 2). A wrong PIN
  costs a try, so type the PIN carefully in (A); tswap never retries it. A6 and A7 also use a
  second key (the spare, or the Token2 for A6) in ways that change nothing destructive; A7 may set
  a first FIDO2 PIN on the spare.
- **(B) Destructive checks** run on the **spare YubiKey 5C NFC only**: wrong-PIN counts, a key
  without a PIN, a FIDO2 reset, programming slot 2. Unplug the daily key for all of (B), except B6
  (below).
- **(C)** The Token2 PIN+ Dual (a non-YubiKey) is refused cleanly on every OS.
- **(D)** Optional: a Security Key or Bio, if one is to hand.

## Setup on each machine

Use a Release build of the branch head on each OS (the build commands are in the repo's
`AGENTS.md`, "Building and Running"; on macOS keep `libtswapse.dylib` next to `tswap`). Never point
these checks at a real vault: every check sets `TSWAP_CONFIG_DIR` to a throwaway folder.

Linux and macOS (bash or zsh):

```bash
T=/path/to/publish/tswap                    # this branch's build
W="$HOME/fido2-check"                       # throwaway; remove it at the end
mkdir -p "$W"
git -C /path/to/the/worktree rev-parse --short HEAD   # record which commit you built
```

Windows (PowerShell, a normal prompt unless a step says elevated):

```powershell
$T = "C:\path\to\publish\tswap.exe"
$W = "$env:USERPROFILE\fido2-check"
New-Item -ItemType Directory -Force $W | Out-Null
```

Commands that need sudo keep `TSWAP_CONFIG_DIR` with
`sudo --preserve-env=TSWAP_CONFIG_DIR "$T" ...`. On Windows they run from an elevated PowerShell
where `$T` and `$env:TSWAP_CONFIG_DIR` are set again.

To move a vault between machines, copy its vault folder (the `--folder` one, never a config
folder) by scp or USB, keeping its name, and join it there with `init --vault-dir` (A3).

**Paste back for every check:** the OS and version, the key (serial), the commands as run, and the
whole output, plus what you typed or touched where it differed from the steps.

## (A) Safe checks on the daily key

### A0. The read-only hardware tests

Linux, with the daily key plugged in, in the branch's worktree:

```bash
TSWAP_TEST_FIDO2=1 ./runtests.sh --yubikey
```

Expect `RealKey_ListsAYubicoFido2Key`, `RealKey_ListingTwiceGivesTheSameHandles` and
`RealKey_SilentProbeForAnUnknownCredentialFindsNoHolder` to pass (the OTP `RealKey_*` tests skip
without `TSWAP_TEST_YUBIKEY_SERIAL`). Watch the key during the probe test: it should not blink and
nothing should ask for a touch.

Then the same on the Mac, **with Input Monitoring turned off** for the terminal app (System
Settings → Privacy & Security → Input Monitoring): the FIDO2 listing must work without it.

Paste back: the summary line, and whether the key blinked.

### A1. Enrol and unlock on Linux

If you still have the helper script `fido2-check.sh` from the session that prepared this check,
it runs steps 1 to 5 (it was written for an earlier build of the branch; point its `T=` at the
current build). By hand:

```bash
export TSWAP_CONFIG_DIR="$W/linux-config"
"$T" init --fido2 --no-password --no-recovery --folder "$W/vault-linux"   # 1: PIN + touch, twice
"$T" slots                                                               # 2
"$T" create fido2-check 16                                               # 3: PIN + touch
echo hello > "$W/check.txt"; "$T" redact "$W/check.txt"; echo "exit $?"  # 4: PIN + touch
```

Expect:

1. `Enrolling a FIDO2 credential on YubiKey <serial> (its PIN and a touch, twice)...`, then twice:
   `FIDO2 PIN for YubiKey <serial>: ` (nothing echoed while you type), and only after Enter,
   `Touch your YubiKey when it blinks.` Then the completion box with `FIDO2 key:      YubiKey
   <serial>`, `Backend: YubiKey FIDO2 keyring (k = 1, 1 slot: this key only)`, the
   `--no-recovery` warning, and `A FIDO2 reset of YubiKey <serial> deletes this slot's credential
   and kills the slot: ...`.
2. One `machine` row ending `YubiKey <serial>, FIDO2: PIN + touch, no password`.
3. and 4. One PIN prompt each, the touch line on stderr after the PIN, then success; `redact`
   prints `hello` and `exit 0`.

Then, with the key **unplugged**:

```bash
"$T" names; echo "exit $?"
```

Expect no PIN prompt at all, and `The FIDO2 slot of YubiKey <serial>: plug it in.` in the error.

Keep `$W/vault-linux` for A3.

### A2. The PIN prompt at the terminal (Linux, then macOS)

The PIN is read from `/dev/tty` with echo off; these checks are what no automated test covers.
Use A1's vault on Linux and A3's macOS vault on the Mac. After each step, type a few characters at
the shell prompt to see whether the echo is back.

| Step | Do | Expect |
|---|---|---|
| a | `"$T" names`, type the PIN, Enter | nothing echoed while typing; the shell echoes again afterwards |
| b | `"$T" names`, type two characters, `Ctrl+C` | the command ends (exit 130); the shell echoes |
| c | `"$T" names`, type two characters, `Ctrl+Z`; at the shell type `echo visible`; then `fg`; type the PIN, Enter | `echo visible` shows as you type (echo back while stopped); after `fg` the PIN is not echoed (echo off again), and the unlock works; the shell echoes afterwards |
| d | `"$T" names`, `Ctrl+\` | the command ends (the shell may print `Quit`, with or without "core dumped"); the shell echoes. Remove any core file it leaves |
| e | `echo stdin-value \| "$T" ingest fido2-stdin` | the PIN is asked at the terminal although stdin is a pipe, then `✓ Secret 'fido2-stdin' ingested from stdin`; `"$T" names` (another PIN) lists it |

Step e is the `--recovery-key-stdin` case in small: stdin carries data and the PIN still comes from
the terminal.

Paste back: per step, the output and whether anything was echoed when it shouldn't be (or wasn't
when it should).

### A3. Cross-OS, in every direction

Each OS makes its own throwaway vault with the daily key, and the other two open it. Join a copied
folder with a fresh config folder:

```bash
# Linux / macOS (here: opening the Linux vault on the Mac)
export TSWAP_CONFIG_DIR="$W/join-linux-config"
"$T" init --vault-dir "$W/vault-linux"
"$T" names                      # PIN + touch: lists fido2-check
```

```powershell
# Windows
$env:TSWAP_CONFIG_DIR = "$W\join-linux-config"
& $T init --vault-dir "$W\vault-linux"
& $T names                      # Windows' dialog: PIN, touch
```

`init --vault-dir` doesn't unlock. Expect `✓ This machine now uses the shared vault folder ...
(1 slot(s), 1 of them YubiKeys).` Then `names` lists `fido2-check`: on the Mac after
`FIDO2 PIN for YubiKey <serial>: ` and the touch line; on Windows after
`Follow Windows' security key dialog: the key's PIN, then a touch.` and the dialog.

Make the other two vaults the same way as A1, on their own OS:

```bash
# macOS
export TSWAP_CONFIG_DIR="$W/mac-config"
"$T" init --fido2 --no-password --no-recovery --folder "$W/vault-mac"
"$T" create fido2-check 16
```

```powershell
# Windows
$env:TSWAP_CONFIG_DIR = "$W\win-config"
& $T init --fido2 --no-password --no-recovery --folder "$W\vault-win"
& $T create fido2-check 16
```

On Windows expect `Windows will ask for the key's PIN and a touch (twice). If the key has no FIDO2
PIN yet, Windows asks you to create one.`, then `Enrolling a FIDO2 credential on the key you pick
in Windows' dialog...`, the dialog line twice, and the dialog twice. `tswap slots` there shows the
slot by model (`YubiKey 5 NFC or 5C NFC, FIDO2: PIN + touch, no password`): Windows reports no
serial.

Then open each vault on the other two OSes:

| Made on | Open on Linux | Open on macOS | Open on Windows |
|---|---|---|---|
| Linux (`vault-linux`) | (made here, A1) | join + `names` | join + `names` |
| macOS (`vault-mac`) | join + `names` | (made here) | join + `names` |
| Windows (`vault-win`) | join + `names` | join + `names` | (made here) |

Paste back: the table filled in (opened / the error), and each `names` output.

**Re-check after the final-review change to the Windows salt.** Windows now hands `webauthn.dll` the
salt tswap computed, with the raw-salt flag set, instead of letting Windows hash the PRF input. A
Windows build from before that change proves nothing about it: run the Windows column (and the
Windows row) with a build that has it, and expect it to reproduce the Linux result, the vault made on
Linux opening on Windows and the other way round.

### A4. No terminal: refused without a PIN prompt or a dialog

With a FIDO2-only vault (A1's, A3's) and the key plugged in, run `names` with no terminal at all:

```bash
# Linux
setsid -w "$T" names < /dev/null > "$W/no-tty.txt" 2>&1; echo "exit $?"; cat "$W/no-tty.txt"
# macOS (no setsid there): a child that leaves the terminal's session
perl -MPOSIX -e 'if (fork) { wait; exit($? >> 8) } POSIX::setsid() or die "setsid: $!"; exec @ARGV' \
  "$T" names < /dev/null > "$W/no-tty.txt" 2>&1; echo "exit $?"; cat "$W/no-tty.txt"
```

```powershell
# Windows: stdin, stdout and stderr all redirected to files, so none of them is a console
New-Item -ItemType File -Force "$W\empty.txt" | Out-Null
$p = Start-Process -FilePath $T -ArgumentList names -NoNewWindow -Wait -PassThru `
  -RedirectStandardInput "$W\empty.txt" -RedirectStandardOutput "$W\no-tty.txt" -RedirectStandardError "$W\no-tty-err.txt"
"exit $($p.ExitCode)"; Get-Content "$W\no-tty.txt", "$W\no-tty-err.txt"
```

Expect a non-zero exit, no PIN prompt, no blink, no Windows dialog, and:
`A FIDO2 slot needs a person at a terminal to type the key's PIN and touch the key; there is no
terminal here, so the key was not used.`

Paste back: the exit code and the message, per OS, and whether anything appeared on screen.

### A5. Windows: an already-enrolled key at enrolment

Records which HRESULT Windows returns for the exclude list (mapped to `NTE_EXISTS` from the
header only). On Windows, in the joined Linux vault (A3), from an **elevated** PowerShell:

```powershell
$env:TSWAP_CONFIG_DIR = "$W\join-linux-config"
& $T -v slot add --fido2 --no-password
```

Run it with `-v` (before the command name, as above): a Windows failure then prints its own line,
`Windows HRESULT 0x........ (NAME)`, on stderr. The vault opens first (dialog: PIN, touch), then a
second dialog for the new credential, with
the same daily key. Expect, with nothing written: ``The key you picked: this key already has a
FIDO2 slot in this vault (one per key; `tswap slots` lists them). No slot was added.`` If you see
`The key you picked: the FIDO2 operation failed (HRESULT 0x........).` instead, the HRESULT is the
finding. Either way, paste the `Windows HRESULT` line. Note whether the dialog asked for a touch
before refusing.

### A6. Windows: a key with no slot of this vault

Records the HRESULT when the key picked holds none of the vault's credentials (mapped from
`NTE_NOT_FOUND`, medium confidence). Needs a second key that has no slot in the vault: the spare
(safe here: it only answers "not mine") or the Token2. With only that key plugged in:

```powershell
$env:TSWAP_CONFIG_DIR = "$W\join-linux-config"
& $T -v names
```

Run with `-v` and paste the `Windows HRESULT 0x........ (NAME)` line. Record which of these comes
back (each one tells which Windows result it was):

- ``The key you picked holds none of this vault's FIDO2 credentials: another key, or a FIDO2 reset
  deleted it (then enrol the key again with `tswap slot add --fido2`).`` (`NTE_NOT_FOUND`);
- `The key you picked: the FIDO2 PIN or touch was cancelled.` (a cancel: say whether you cancelled
  the dialog yourself, and what the dialog said before);
- `The key you picked: the FIDO2 operation failed (HRESULT 0x........).` (unmapped: paste the
  HRESULT).

The message names the HRESULT only in the last case; with `-v` the `Windows HRESULT` line shows it
in every case.

### A7. Windows: two FIDO2 slots in one dialog

The per-credential salt list (`pCredWithHmacSecretSaltList`) has never run. Needs a second key; the
spare is fine (an ordinary enrolment). On Linux, with both keys plugged in:

```bash
export TSWAP_CONFIG_DIR="$W/two-config"
"$T" init --fido2 --serial <daily serial> --no-password --no-recovery --folder "$W/vault-two"
"$T" create fido2-two 16
sudo --preserve-env=TSWAP_CONFIG_DIR "$T" slot add --fido2 --serial <spare serial> --no-password
"$T" slots                     # two machine rows, YubiKey <daily> and YubiKey <spare>, FIDO2: PIN + touch
```

`slot add` first opens the vault through the daily key's slot (its PIN and a touch), then enrols
the spare. If the spare has no FIDO2 PIN yet, tswap offers to set one (answer `yes` and type a new
PIN twice: an ordinary first PIN, nothing destructive). Copy `vault-two` to Windows, join it, then run `& $T names` three times:
only the daily key plugged in, only the spare, and both (pick each in the dialog in turn).

Expect each run to open the vault and list `fido2-two`, with one dialog per run. Paste back: per
run, the key used and the output.

### A8. NFC on Windows (only if a reader is available)

With A3's joined Linux vault: unplug every key, then `& $T names` and hold the daily key (a 5 NFC)
on the reader when the dialog asks. Credentials are offered for USB and NFC. Record whether the
dialog offers NFC, and the output.

### A9. Guided `init` on each OS

On each OS, with the daily key plugged in (OTP challenges on the daily key are read-only):

```bash
export TSWAP_CONFIG_DIR="$W/guided-config"
"$T" init --folder "$W/vault-guided"      # pick the key's OTP and FIDO2 entries; no password; recovery: your call; other machines: no
"$T" slots
"$T" names
```

Expect the list to read, per OS:

- Linux: `YubiKey <serial>, OTP slot (no PIN)`, `YubiKey <serial>, FIDO2 slot (PIN + touch)`, then
  `TPM`.
- macOS: `YubiKey <serial>, FIDO2 slot (PIN + touch; preferred on a Mac: no Input Monitoring
  needed)`, `YubiKey <serial>, OTP slot (no PIN; needs Input Monitoring for the terminal)`, then
  `Secure Enclave`.
- Windows: `TPM`, `YubiKey <serial>, OTP slot (no PIN)`, `a YubiKey's FIDO2 slot (Windows' dialog:
  pick the key, PIN, touch)`.

Under the list, on every OS: `Using a key on other machines too? An OTP slot needs Input Monitoring
...`. Picking both gives two `machine` rows in `slots` (the OTP one and `..., FIDO2: PIN + touch,
...`), and the FIDO2 reset warning after the FIDO2 slot. `names` then opens through the OTP slot
with no PIN (with a touch if the key's slot 2 requires one). On the Mac with Input Monitoring off, `names` should fall through to the FIDO2 slot
and ask for the PIN.

Paste back: the list as printed, the `slots` output and how `names` opened, per OS.

## (B) Destructive checks on the spare 5C NFC only

Unplug the daily key first (B6 is the one exception). Each check names what it changes on the
spare. `ykman` is useful here
for reading the PIN counter (`ykman --device <spare serial> fido info`) and for the reset; tswap
itself never resets a key.

### B1. A key without a FIDO2 PIN, on Linux

Start from a spare with no FIDO2 PIN (new, or after a reset in B4). Run it three times, answering
differently:

```bash
export TSWAP_CONFIG_DIR="$W/spare-config"
"$T" init --fido2 --no-password --no-recovery --folder "$W/vault-spare"
```

1. Answer `no` to `YubiKey <spare> has no FIDO2 PIN; a FIDO2 slot needs one. Set a FIDO2 PIN on it
   now? (yes/no): `. Expect `YubiKey <spare> has no FIDO2 PIN; a FIDO2 slot needs one. No PIN was
   set. No slot was added.` and no config written (`ls "$W/spare-config"`).
2. Answer `yes`, type `123` at `New FIDO2 PIN for YubiKey <spare>: `: expect `A FIDO2 PIN has at
   least 4 characters; type a longer one.` Then a 4-or-more PIN, and a different one at
   `Repeat the new FIDO2 PIN: `: expect `The two PINs differ; type the new PIN again.` Then press
   Enter on an empty prompt to cancel, and record what happens.
3. Answer `yes` and set the PIN properly: expect `✓ YubiKey <spare> has a FIDO2 PIN now.`, then the
   enrolment as in A1 (two PIN prompts with the new PIN).

Then `"$T" create spare-check 16` (one PIN) and keep the vault for B2.

### B2. Wrong-PIN counts and the re-insert after three

With B1's vault, run `"$T" names` and type a **wrong** PIN, three times in a row, then once more
without re-inserting. After each run: `ykman --device <spare serial> fido info`.

Expect after the first: ``YubiKey <spare>: wrong FIDO2 PIN; 7 tries left before this key's FIDO2 is
blocked (a key allows 8 wrong PINs in all). After three wrong PINs in a row, unplug the key and plug
it in again before the next try.`` and the counter at 7; after the second, 6 tries. The third
should say `YubiKey <spare>: three wrong FIDO2 PINs in a row. Unplug the key and plug it in again
before the next try; 5 tries left ...` (or another "wrong PIN" line: record which; CTAP keys differ
on whether the third wrong PIN or the next attempt reports the block). The fourth, without
re-inserting, should refuse again: record its text and whether the counter moved. Every run asks for the PIN once and never retries.

Then unplug and re-insert the spare, run `"$T" names` with the right PIN: expect it to open, and
`fido info` to show the counter back at 8.

### B3. A blocked PIN (optional; ends in a reset)

Continue B2 to eight wrong PINs, re-inserting after every three. Expect the last to say
`YubiKey <spare>: its FIDO2 PIN is blocked (8 wrong PINs). Only a FIDO2 reset unblocks it, ...
tswap never resets a key. ...`, and a further `names` the same (record whether it still asks for
the PIN first). Go on to B4.

### B4. A FIDO2 reset, reported as a dead slot (Linux, macOS, Windows)

Before the reset, copy `vault-spare` to the Mac and to Windows and join it there (A3). Then reset
the spare's FIDO2 application (this deletes every FIDO2 credential and the PIN on it):
`ykman --device <spare serial> fido reset` (within a few seconds of plugging it in), or Yubico
Authenticator.

- Linux and macOS: `"$T" names`. Expect no PIN prompt, and ``YubiKey <spare> is plugged in but no
  longer holds this slot's credential: a FIDO2 reset deleted it, and the slot can't be opened
  again. Enrol the key again with `tswap slot add --fido2`.``
- Windows: `& $T names`. Expect the "holds none" text of A6 (or record what comes back). The key now
  has no PIN: if the dialog asks to create one, cancel it and record that it asked (B5 needs the
  key without a PIN).

Paste back: each OS's output.

### B5. A key without a FIDO2 PIN, on macOS and on Windows

macOS, the spare after B4 (no PIN): run B1's three answers (`no`, the short and mismatched PINs,
then `yes`) with `"$W/spare-mac-config"` and `--folder "$W/vault-spare-mac"`. Expect the same texts
as B1.

Then reset the spare again (B4), and on Windows:

```powershell
$env:TSWAP_CONFIG_DIR = "$W\spare-win-config"
& $T init --fido2 --no-password --no-recovery --folder "$W\vault-spare-win"
```

tswap asks nothing itself there; expect Windows' dialog to ask you to create a PIN, then the
enrolment. Record exactly what the dialog asked, how many times, and the output; then
`& $T names` (one dialog) should open it.

### B6. Stage 1: programming slot 2 (`SpareKey_ProgrammedSlotMatchesYkmanSemantics`)

Overwrites the spare's slot 2 with a known test key (and leaves it so). **The one exception to
(B)'s rule: plug the daily key in too.** `runtests.sh --yubikey` also runs the read-only
`RealKey_*` tests, which use the key `TSWAP_TEST_YUBIKEY_SERIAL` names and fail if it isn't
plugged in. The spare-key test names the daily key only to refuse to program it: it programs only
the key with the spare's serial, and refuses to run while any key other than these two is
attached. Needs `ykman`:

```bash
TSWAP_TEST_YUBIKEY_SERIAL=<daily serial> TSWAP_TEST_SPARE_YUBIKEY_SERIAL=<spare serial> ./runtests.sh --yubikey
```

Expect the spare test to pass, and to ask for a touch at its last step (the touch-required
programming). Paste back the test output lines and the summary.

### B7. Stage 1: the busy message, and the FIDO2 one

1. The OTP one. Make an OTP vault on the spare (its slot 2 is touch-required after B6):

   ```bash
   export TSWAP_CONFIG_DIR="$W/busy-config"
   "$T" init --yubikey --no-password --no-recovery --folder "$W/vault-busy"   # entropy: 1; touch the spare
   ```

   Terminal 1: `"$T" names`, and don't touch the key. Terminal 2, with the same `T` and
   `TSWAP_CONFIG_DIR`: `"$T" names`. Expect in terminal 2 `YubiKey <spare> is busy (another tswap or
   app is waiting for a touch); try again when it's done.` (or record the busy text you get). Then
   touch the key for terminal 1.
2. The FIDO2 one. A FIDO2-only vault on the spare:

   ```bash
   export TSWAP_CONFIG_DIR="$W/busy-fido2-config"
   "$T" init --fido2 --no-password --no-recovery --folder "$W/vault-busy-fido2"
   ```

   Terminal 1: `"$T" names`, type the PIN, and don't touch the key. Terminal 2 (same settings):
   `"$T" names`. Record what terminal 2 says; expected: `YubiKey <spare> is busy: another program
   is using it. Try again when it's done.`, with no PIN prompt.

### B8. `yubikey setup --replace` with a FIDO2 slot

Reprograms the spare's slot 2. Give B7's OTP vault a FIDO2 slot of the same key, so its ways in
are the spare's OTP slot and its FIDO2 slot:

```bash
export TSWAP_CONFIG_DIR="$W/busy-config"
sudo --preserve-env=TSWAP_CONFIG_DIR "$T" slot add --fido2 --no-password   # a touch to open, then PIN + touch twice
```

1. Refusal: `"$T" yubikey setup --replace --touch --serial <spare>`, type the serial to confirm.
   Expect `Checking that the vault's FIDO2 slot still opens it (the key's FIDO2 PIN and a touch)...`
   and the PIN prompt. Press Enter on an empty PIN (a cancel). Expect `Refusing: apart from YubiKey
   <spare>, only the vault's FIDO2 slot (YubiKey <spare>) can open the vault in <config dir>, and it
   didn't open now: YubiKey <spare>: the FIDO2 PIN or touch was cancelled. Nothing was changed.`
   (`"$T" names` still opens through the OTP slot with a touch.)
2. Proceed: run it again and give the PIN and a touch. Expect setup to go on and program slot 2
   (touch for its check). Then `"$T" names`: the OTP slot is dead now (`slots` still lists it), so
   the unlock falls through to the FIDO2 slot and asks for the PIN.

## (C) The Token2 (not a YubiKey), refused on every OS

Plug in only the Token2 (with its own FIDO2 PIN set, or not).

- Linux and macOS: `TSWAP_CONFIG_DIR="$W/token2-config" "$T" init --fido2 --no-password --no-recovery
  --folder "$W/vault-token2"`. Expect `No YubiKey with FIDO2 detected. Please insert YubiKey.` with
  no PIN prompt and nothing written. The guided `init` shouldn't list it at all.
- Windows: the same `init --fido2`. The dialog runs (PIN, touch on the Token2), then expect
  `This security key is not a YubiKey (its FIDO2 model id is <AAGUID>): FIDO2 slots work with
  YubiKeys only for now (other keys: issue #193). No slot was added.` and nothing written
  (`Get-ChildItem "$W\token2-config"`). The Token2 keeps an unused non-discoverable credential.
  If instead you see `Windows didn't report which key this is (its FIDO2 model id came back as
  zeros) ...`, record that.
- Windows unlock: A6 with the Token2 as the "other key" (if not done there).

Paste back: the AAGUID Windows reported (for #193), and each OS's output.

## (D) Optional: a Security Key or Bio (no serial)

If one is to hand: A1 and A3 with it. Expect it listed and named by model (for example
`Security Key NFC by Yubico, FIDO2 slot (PIN + touch)` in guided `init`,
`Security Key NFC by Yubico, FIDO2: PIN + touch, no password` in `slots`), enrolment and unlock as
for the daily key, and `slot add --fido2` with the same key refused as a second slot. On a Bio,
Linux and macOS ask for the PIN, not the fingerprint; record what Windows' dialog offers.

## Clean up

```bash
rm -rf "$W"        # Linux, macOS
```

```powershell
Remove-Item -Recurse -Force $W     # Windows
```

The daily key keeps a few unused non-discoverable credentials, which take no space on it. The spare
ends with whatever B left on it (a reset, a PIN, slot 2 programmed).
