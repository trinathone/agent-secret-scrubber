# agent-secrets

### Your AI agent saved your database password into a JSON file. Then you pushed it to GitHub.

`agent-secrets` finds those passwords and API keys hiding in AI agent config files, and scrubs them out before anyone else finds them.

One Python file. Standard library only. No install, no network, no AI, no account. It runs in about a second.

```sh
python3 agent_secrets.py scan .
```

```
.claude/settings.local.json:4: pgpassword: Sup***ss
.claude/settings.local.json:6: sshpass: Hun***ss
.claude/settings.local.json:7: mysql-password: Fak***42
mcp.json:1: openai-key: sk-***cd
session.jsonl:2: github-token: ghp***34

5 finding(s) in 3 file(s). Values are redacted.
```

That output is real, from the test fixtures in this repo. Your repo may look exactly like it.

---

## How does a password even get in there?

You did not type it into a config file. Your agent did.

In Claude Code, when a command asks for permission and you click **"don't ask again"**, the exact command is saved as an allow-rule in `.claude/settings.local.json`. If that command contained a password, the password is now sitting in plain text in a JSON file inside your project:

```json
"permissions": {
  "allow": ["Bash(PGPASSWORD=<password> psql -h db.internal -U app)"]
}
```

The same leak happens two other ways:

- **MCP configs.** You paste an API key into the `env` block of `mcp.json` to make a server work. It stays there, in plain text, forever.
- **Transcripts.** Session logs record the commands and tokens that flew past, including the one-time ones.

And then `.claude/` and `mcp.json` get committed like any other project file, because nobody thinks of them as secret stores. They are.

## This is not hypothetical. It is measured.

Apiiro's research (November 5, 2026) examined 104,185 public copies of `.claude/settings.local.json`:

- **1,122 of them held a real secret.**
- **2,539 secrets** were found across **1,994 repositories**.
- gitleaks flagged only 564 of those 1,122 files. TruffleHog flagged 643.
- **215 files were caught by neither scanner.**

GitGuardian separately found **24,008 unique secrets** in public MCP config files, **2,117 of them still valid**.

Why do the big scanners miss these? They look for token shapes. A database password after `PGPASSWORD=`, `sshpass -p`, or `mysql -p` has no recognisable shape. It is just a word, in exactly the file nobody thought to check. `agent-secrets` was built to understand those files: it parses allow-rules as shell commands, reads MCP `env` blocks and `args`, and knows what an inline password looks like.

## Where and when to use it

| Moment | Run | Why |
|---|---|---|
| Right now, on every repo where you use an AI agent | `scan .` | Takes a second. Find out if you are already exposed. |
| After a long agent session, before you commit | `scan .` | "Don't ask again" clicks accumulate allow-rules quietly. |
| Before making a repo public, or open-sourcing anything | `scan .` then `history .` | The working tree is only half the story. History remembers everything. |
| As a pre-commit hook | `scan` on staged files | Exit code 1 blocks the commit before the secret lands. Snippet below. |
| In CI | `scan . --json` | Machine-readable findings, proper exit codes, nothing to install. |
| After a leak, before you relax | `history .` | If a secret was ever committed, it names the commits. Then rotate the credential. Deleting the file does not un-leak it. |
| On a dotfiles repo or a config you are about to share | `scan <path>` | Dotfiles repos are where agent configs go to be copied by everyone. |

**Who this is for:** anyone running Claude Code, Cursor, or MCP servers in a real repo. Solo devs with dotfiles, teams sharing `.claude/` settings, and anyone who has ever clicked "don't ask again" without reading the command twice.

## The three commands

| Command | What it does | Changes files? |
|---|---|---|
| `scan <path>...` | Reports every inline secret it finds, with redacted previews | No |
| `scrub <path>` | Moves the secrets into `.env.local` and leaves `${VAR}` references in the configs | Yes, with backups first |
| `history <path>` | Scans every line ever added in git history and names the commits | No |

Exit codes: `0` clean, `1` findings, `2` usage error. Made for hooks and CI.

## What `scrub` actually does (and why it is safe)

Scrub is the part people are scared of, so here is exactly what happens:

1. **Your values are stored before anything is rewritten.** Each secret goes into `.env.local` as `KEY=value`, and that file is set to mode `600` (only you can read it).
2. **Every original file is backed up** to `.agent-secrets-backup/`. The first, pristine copy is never overwritten.
3. **The config is rewritten with a reference, not a hole.** `PGPASSWORD=<password>` becomes `PGPASSWORD=${PGPASSWORD}`. An MCP env value becomes `"OPENAI_API_KEY": "${OPENAI_API_KEY}"`. Database URLs keep everything except the password: `postgres://app:${DB_PASSWORD}@db/app`.
4. **`.gitignore` is fixed for you.** `.env.local`, `.claude/settings.local.json`, and the backup folder are added, only if missing, never duplicated.

Run it twice: the second run changes nothing. It is idempotent, and a test proves it.

Two deliberate choices:

- **`.env` files are never blanked.** A `.env` already is a secret store; emptying it would break your app. Scrub makes sure it is gitignored and reports conflicts instead.
- **Transcripts are report-only.** Scrub will not rewrite your session logs. It tells you what is in them. If a token in a transcript was ever committed, rotate it.

After a scrub, `scan` will still list the values sitting in `.env.local`. That is intentional: they are real secrets on disk, now in the right place, gitignored. The pre-commit hook below only scans staged files, so it stays quiet.

## Install

There is nothing to install.

```sh
# copy one file, that is the whole setup
curl -O https://raw.githubusercontent.com/trinathone/agent-secret-scrubber/main/agent_secrets.py
python3 agent_secrets.py scan .
```

Needs Python 3.9 or newer. It never opens a network connection, which you can verify by reading it: it is one file, and it is short enough to audit.

## Pre-commit hook

Save as `.git/hooks/pre-commit`, then `chmod +x` it:

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

## What it detects

Files it understands:

- `.claude/settings*.json` and any `settings.json` / `settings.local.json`: every `permissions.allow` / `deny` / `ask` entry is checked as a shell command, and the raw text is scanned too.
- MCP configs (`mcp.json`, `.mcp.json`, `claude_desktop_config.json`, or any `*.json` containing `"mcpServers"`): `env` and `headers` values, and `args` including `["--api-key", "<value>"]` pairs.
- `.env` and `.env.*` files.
- Transcripts and logs: `*.jsonl`, `*.txt`, `*.log`.
- Any other text file under 2 MB, with the generic detectors.

Detectors, all deterministic:

- Known prefixes: OpenAI and Anthropic `sk-` keys, GitHub `ghp_` and `github_pat_`, AWS `AKIA`, Slack `xoxb-` and `xoxp-`, Google `AIza`, GitLab `glpat-`, `Authorization: Bearer` headers.
- Inline command secrets: `PGPASSWORD=`, `MYSQL_PWD=`, `SSHPASS=`, `sshpass -p`, `mysql -p<pw>`, passwords inside `postgres://`, `mysql://`, `mongodb://`, and `redis://` URLs, and `--password`, `--api-key`, `--token` flags.
- Named assignments: a variable whose name contains KEY, TOKEN, SECRET, PASSWORD, PASSWD, PWD, or AUTH, with a value of 8 or more characters that is not a placeholder.
- High-entropy values (24+ characters, entropy 3.5 or higher) assigned to secret-named variables.

Never flagged: environment references (`$VAR`, `${VAR}`, `{env:VAR}`, `%VAR%`), placeholders (`changeme`, `your-key-here`, `<...>`, `xxxx`, empty values), and prose that mentions the word "password" without assigning one.

Output never contains a full secret. Previews show the first 3 and last 2 characters, like `Sup***ss`. Anything shorter than 8 characters shows as `***`.

## Why not just run gitleaks?

Run both. gitleaks and TruffleHog are excellent at what they do: finding formatted tokens anywhere in a repo. This tool exists for the gap they measured themselves, the 215 settings files neither one caught, because the secret was a plain password inside a shell command inside a JSON allow-rule. `agent-secrets` is format-aware for agent files, it cleans up after itself with `scrub` instead of only reporting, and it needs no binary, no config, and no network. Different layer, same defence.

## Ignoring paths

Drop a `.agent-secrets-ignore` file in the folder you scan. Each line is an fnmatch glob relative to that folder, `#` starts a comment, a pattern ending in `/` or `/**` matches a whole folder, and a pattern without a `/` matches any path component. `scan`, `scrub`, and `history` all honour it.

This repo ships one ignoring `tests/fixtures/**`, because the fixtures are intentional fake secrets the tests need the detectors to catch. Scan a copy of them without the ignore file and they light up again. A test checks exactly that.

## Honest limitations

- Detection is patterns and heuristics. There is no provider validation and no machine learning. A secret in a format nobody has named will be missed, and some password-looking values will be flagged. That is the nature of a deterministic v1.
- A value containing spaces inside a command is not flagged, because it is almost always a code fragment, not a secret.
- `mysql -p <value>` with a space only counts when another argument follows, because `mysql -p dbname` is how you ask for a password prompt.
- Scrub edits JSON agent configs only. Everything else is report-only.
- Rewriting an allow-rule changes the command it matches. The new rule matches the command using the env var, which is what you want from then on.
- **If `history` finds something, rotate the credential first.** Forks, clones, caches, and scrapers keep copies. Rewriting history is cleanup; revocation is the fix.

## Tests

21 tests, standard library `unittest`, including leaky settings, leaky MCP, and leaky transcript fixtures, a clean control set that must produce zero findings, a false-positive set, scrub idempotency, backup behaviour, and git history attribution.

```sh
python3 -m unittest discover -s tests
python3 agent_secrets.py scan .   # this repo scans clean
```

## The one-sentence version

Agents write secrets into config files as a side effect of being helpful. This tool reads those files the way the agent wrote them, finds the secrets, and puts them where secrets belong.

If it catches one real password in your repo, star the repo so the next person finds the tool before their leak does.
