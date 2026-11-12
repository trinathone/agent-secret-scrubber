# agent-secrets

Find and scrub the passwords and API keys that AI coding agents quietly write
into config files, before they reach GitHub.

## The problem

When Claude Code asks permission to run a command and you pick "don't ask
again", it saves that exact command as an allow-rule in
`.claude/settings.local.json`. If the command had a password in it, the
password is now stored in plain text in a JSON file in your repo. The same
thing happens with MCP server configs (API keys pasted into `env` blocks) and
with session transcripts.

Those files get committed. Apiiro's research (Nov 5, 2026) looked at 104,185
public copies of `.claude/settings.local.json`:

- 1,122 of them held a real secret.
- In total they found 2,539 secrets across 1,994 repositories.
- gitleaks flagged only 564 of the 1,122 files and TruffleHog flagged 643.
  215 were caught by neither, usually because the secret was a plain password
  typed after `PGPASSWORD=`, `sshpass -p` or `mysql -p` rather than a token
  with a recognisable format.

GitGuardian separately found 24,008 unique secrets in public MCP config
files, 2,117 of them still valid.

Generic scanners look for token shapes. `agent-secrets` also understands the
agent file formats: it parses allow-rules as shell commands, reads MCP `env`
blocks and `args`, and knows what an inline database password looks like.

## What it does

| Command | What it does | Modifies files? |
|---|---|---|
| `scan <path>...` | Reports inline secrets with redacted previews | No |
| `scrub <path>` | Moves secrets out of agent configs into `.env.local` and leaves `${VAR}` references behind | Yes, with backups |
| `history <path>` | Scans every line ever added in the git history | No |

Files it understands:

- `.claude/settings*.json`, plus any `settings.json` / `settings.local.json`:
  each `permissions.allow` / `deny` / `ask` entry is checked as a shell command,
  and the raw text is scanned too.
- MCP configs (`mcp.json`, `.mcp.json`, `claude_desktop_config.json`, or any
  `*.json` with `"mcpServers"`): `env` and `headers` values and `args`
  (including `["--api-key", "<value>"]` pairs).
- `.env` and `.env.*` files (`KEY=value` lines).
- Transcripts and logs: `*.jsonl`, `*.txt`, `*.log`.
- Any other text file under 2 MB, using the generic detectors.

It skips `.git`, `node_modules`, `__pycache__`, `.venv`, its own
`.agent-secrets-backup/` directory, binary files and symlinks.

Detectors (all deterministic regex and heuristics):

- Known prefixes: OpenAI/Anthropic `sk-` keys, GitHub `ghp_` / `github_pat_`,
  AWS `AKIA`, Slack `xoxb-` / `xoxp-`, Google `AIza`, GitLab `glpat-`,
  `Authorization: Bearer` headers.
- Inline command secrets: `PGPASSWORD=`, `MYSQL_PWD=`, `SSHPASS=`,
  `sshpass -p`, `mysql -p<pw>` (and `-p <pw>` when another argument follows),
  passwords in `postgres://` / `mysql://` / `mongodb://` / `redis://` URLs,
  and `--password` / `--api-key` / `--token` flags.
- Named assignments: a variable whose name contains KEY, TOKEN, SECRET,
  PASSWORD, PASSWD, PWD or AUTH, assigned with `=`, `:` or JSON `"key": "value"`,
  where the value is 8+ characters and not a placeholder.
- High-entropy values (24+ chars, entropy >= 3.5) assigned to secret-named
  variables.

Never flagged: env references (`$VAR`, `${VAR}`, `{env:VAR}`, `%VAR%`),
placeholders (`changeme`, `your-key-here`, `<...>`, `xxxx`, empty), and prose
that mentions the word "password" without assigning a value.

Output never contains a full secret. Previews show the first 3 and last 2
characters, e.g. `Sup***ss`. Values shorter than 8 characters show as `***`.

## Install

Nothing to install. Python 3.9+ standard library only, no network access.
Copy `agent_secrets.py` anywhere and run it.

## Usage

```sh
python3 agent_secrets.py scan .
python3 agent_secrets.py scan . --json        # JSON array of {file, line, kind, preview}
python3 agent_secrets.py scrub .
python3 agent_secrets.py history .            # all commits on all branches
python3 agent_secrets.py history . --json
python3 agent_secrets.py --version
```

Example scan output:

```
.claude/settings.local.json:4: pgpassword: Sup***ss
mcp.json:1: openai-key: sk-***cd
projects/session.jsonl:2: github-token: ghp***34
```

Exit codes:

| Code | Meaning |
|---|---|
| 0 | No findings (or `scrub` succeeded) |
| 1 | Findings reported (`scan`, `history`) |
| 2 | Usage error, missing path, not a git repo, git not installed |

### Pre-commit hook

`scan` accepts individual files, so a hook can check just what is staged.
Save as `.git/hooks/pre-commit` and `chmod +x` it:

```sh
#!/bin/sh
# Block commits that add inline secrets to agent configs, .env files or transcripts.
files=$(git diff --cached --name-only --diff-filter=ACM)
[ -z "$files" ] && exit 0
# shellcheck disable=SC2086
python3 /path/to/agent_secrets.py scan $files || {
  echo "agent-secrets: inline secrets found; run 'agent_secrets.py scrub .' or fix by hand." >&2
  exit 1
}
```

(Filenames with spaces need a `-z` / `xargs -0` variant.)

## What `scrub` changes

`scrub` rewrites agent config files only: JSON settings under `.claude/`, any
`settings*.json`, and MCP configs. For each inline secret it:

1. Writes the value to `<target>/.env.local` as `KEY=value`. The file is
   created if needed, only keys that are missing are appended, and it is set
   to mode `600`.
2. Backs up the original config to `<target>/.agent-secrets-backup/<same
   relative path>`, but only if no backup of that file exists yet, so the
   first, pristine copy is never overwritten.
3. Replaces the secret in the JSON with an environment variable reference:
   - `env` block values use their own key: `"OPENAI_API_KEY": "${OPENAI_API_KEY}"`
   - `PGPASSWORD=<pw>` becomes `PGPASSWORD=${PGPASSWORD}`
   - `sshpass -p` / `mysql -p` values become `${DB_PASSWORD}`
   - database URLs keep everything except the password: `postgres://app:${DB_PASSWORD}@db/app`
   - other named secrets use the variable name in upper case.

   If two different values want the same name, the second becomes
   `DB_PASSWORD_2` and so on. The JSON is re-serialised with 2-space indentation.
4. Makes sure `<target>/.gitignore` contains `.env.local`,
   `.claude/settings.local.json` and `.agent-secrets-backup/`, plus any `.env`
   file that held secrets. It only adds missing lines and never duplicates them.

**`.env` files are not blanked.** A `.env` file already is a secret store, and
emptying it would break your app. For `.env` files, scrub copies the secret
values into `.env.local` (keys already there are left alone, and a different
existing value is reported as a conflict) and makes sure the `.env` file is
gitignored. The file itself is left as it is.

**Transcripts are report-only.** `*.jsonl` / `*.txt` / `*.log` files and other
text files are never edited. Scrub tells you how many findings they contain.
Run `scan` to list them, then rotate those credentials.

Safety properties:

- **Backups:** every rewritten file has a pristine copy in `.agent-secrets-backup/`.
- **Idempotent:** a second run changes nothing. The configs now hold `${...}`
  references, which the detectors skip, `.env.local` already has the keys,
  `.gitignore` already has the lines, and backups already exist.
- **Store before rewrite:** `.env.local` is written before any config is
  rewritten, so a crash part-way cannot lose a value.
- **Never prints secrets:** the summary shows redacted previews only.

Note that after a scrub, `scan` still reports the values now held in
`.env.local` (and in any `.env` files). That is intentional, since they are
real secrets on disk. They are gitignored, and the pre-commit hook above only
scans staged files.

## Ignoring paths: `.agent-secrets-ignore`

Put a `.agent-secrets-ignore` file in the directory you scan. Each line is an
fnmatch glob matched against paths relative to that directory, and `#` starts
a comment. A pattern ending in `/` or `/**` matches a whole directory, and a
pattern without a `/` matches any path component. `scan`, `scrub` and
`history` all honour it (`history` reads it from the repository root).

This project ships one that ignores `tests/fixtures/**`, because those files
are intentional fake secrets that the tests need the detectors to find.
Scanning the fixtures directly, or a copy of them without the ignore file,
still reports them, and a test checks this.

## Limitations

- Detection is deterministic patterns and heuristics. There is no validation
  against providers and no ML. Unusual formats will be missed and some
  password-looking values will be flagged. In free text, a named value needs a
  digit or symbol to count, so an all-letters password in prose is missed.
- Inline values containing whitespace are not reported, because they are
  almost always code fragments.
- `mysql -p <value>` with a space is only reported when another argument
  follows, because `mysql -p dbname` is the normal way to get a password prompt.
- Transcripts and arbitrary files are report-only. Scrub only edits JSON
  agent configs.
- Rewriting an allow-rule changes the command it matches. The new rule
  matches commands that use the env var, which is what you want going forward.
- **A history finding means rotate the credential.** Deleting the file, or
  even rewriting git history, does not un-leak a secret that was pushed:
  forks, clones, caches and scrapers already have it. Revoke it with the
  provider, then clean up.

## Development

Run the test suite from the project root (stdlib `unittest`; the git history
tests are skipped if `git` is not installed):

```sh
python3 -m unittest discover -s tests -v
```

Self-check that the project is clean:

```sh
python3 agent_secrets.py scan .
```

Note: the leaky-settings fixture lives at
`tests/fixtures/leaky_settings/.claude/settings.local.json`, exactly like the
real file it imitates, and the tests also copy it into a fresh `.claude/`
directory inside a temp dir for the scrub and history tests. A file named
`settings.local.json` is classified as a settings file wherever it lives, so
scanning the fixture directly works too.
