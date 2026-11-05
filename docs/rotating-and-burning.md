# Rotating and burning secrets

This page is for anyone who needs to replace a secret: on a schedule, or because it was exposed. It
covers `rotate` and `ingest --rotate`, the previous value and `restore`, and the step-by-step
response when a secret has been seen.

## Rotating a secret

```bash
tswap burned                              # what needs rotating
tswap rotate api-token 48                 # new random 48-char value, never displayed
kubectl get secret x -o json | jq -r '.data["token"]' | base64 -d | tswap ingest --rotate api-token
tswap run kubectl create secret generic x --from-literal=token={{api-token}} --dry-run=client -o yaml
```

- `rotate <name> [length]` writes a new random value for an existing secret as a newer version.
  Like `create`, the value is never shown, and the entropy mode from `init` applies.
- `ingest --rotate <name>` does the same with a value from stdin.
- There is no delete and no gap: the secret exists throughout. Remember to update the system that
  uses it.
- `create` and `ingest` without `--rotate` still refuse an existing name, and point to `rotate`.

### Sudo unless the secret is burned

A burned secret is already compromised, so replacing it is safe to leave to an agent and needs no
sudo. Rotating a secret that is **not** burned needs sudo, because the services using the old value
stop working until they get the new one.

### The burn is kept as history

On a record-store vault (what `init` makes since 0.2) the old version's burn stays in the record,
and `tswap burned` lists it under "Rotated" instead of as outstanding (`burned --json` marks it
`"status": "rotated"`).

A **classic vault** (one `secrets.json.enc`, from 0.1) keeps one burn per secret and no history.
tswap 0.2 refuses to rotate in it, as it refuses every command but `migrate` and `export`: convert
it first, see [upgrading-from-0.1.md](upgrading-from-0.1.md).

### The previous value

The record store keeps the previous value, one level back. Use `{{name:previous}}` in `run` (or
`# tswap: name:previous` in `apply`) to change the credential at the service while the old one still
authenticates. It is never displayed:

```bash
tswap rotate db-pw && tswap run psql "postgresql://app:{{db-pw:previous}}@db/app" -c "ALTER ROLE app PASSWORD '{{db-pw}}'"
```

This works without sudo only for a burned `db-pw`. If it isn't burned, the user runs the rotate,
with sudo (`sudo tswap rotate db-pw`); the `run` that follows needs no sudo.

`sudo tswap restore <name>` writes the previous value back as a new version (and if that value was
burned, its burn is outstanding again). So an agent's burn-then-rotate is visible (the burn stays in
the record) and reversible. A secret that was never rotated has no previous value.

## When a secret is exposed: burn and rotate

When a secret is exposed, whether through accidental command output, a log file, or an agent seeing
a plaintext value, follow these steps.

### Step 1: Burn immediately

Mark the secret as compromised. This is the **first** action, before anything else:

```bash
tswap burn <name> "reason: how it was exposed"
```

This records a timestamp and reason. `names` shows `[BURNED]` next to the secret, and `apply` and
`check` warn about it. Burning a secret that is already burned is rejected: the original incident
record is kept.

### Step 2: Assess scope

Check what else may be affected:

```bash
# List all burned secrets
tswap burned

# Check which files reference the burned secret
tswap check /path/to/project
```

Find out:

- **How was it exposed?** (command output, log file, agent context, error message)
- **Who or what saw it?** (AI agent, CI log, terminal session)
- **Is it in use anywhere?** (running services, config files, CI/CD pipelines)

### Step 3: Rotate at the source

Rotate the credential at whatever system issued it. This is provider-specific:

| Provider | Rotation action |
|----------|----------------|
| Database password | `ALTER USER app WITH PASSWORD '...'` (use `tswap run` with a new secret) |
| API key | Regenerate in provider dashboard, revoke the old key |
| Kubernetes secret | `kubectl create secret` with new value, rollout restart |
| Cloud credentials | Rotate via IAM console or CLI, deactivate old key |

### Step 4: Replace the secret

Keep the name, or create a replacement under a new one.

**Same name:** `rotate` or `ingest --rotate`, as in [Rotating a secret](#rotating-a-secret). A
burned secret needs no sudo, and `{{name:previous}}` lets you change the credential at the service
while the old value still works.

```bash
tswap rotate db-password 48
```

**New name:**

```bash
# Option A: Generate a new random secret
tswap create db-password-v2 48

# Option B: Ingest from an external source
kubectl get secret new-creds -n prod -o json \
  | jq -r '.data["password"] // empty' \
  | base64 -d \
  | tswap ingest db-password-v2
```

### Step 5: Update references

With a new name, update all files and commands that referenced the old secret name:

```bash
# Find all references to the old secret
tswap check /path/to/project

# Update # tswap: markers in config files
# (manually change db-password → db-password-v2 in marker comments)

# Verify the new references
tswap check /path/to/project
```

### Step 6: Verify and clean up

```bash
# Confirm no burned secrets remain unrotated
tswap burned

# Delete the old burned secret (operator action, requires sudo)
sudo tswap delete db-password
```

A secret rotated under the same name shows under "Rotated" in `tswap burned`; there is no old
secret to delete.

Every command used on this page, with its full usage, is in [commands.md](commands.md).
