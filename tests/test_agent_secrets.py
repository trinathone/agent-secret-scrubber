"""Tests for agent-secrets. Run from the project root:

    python3 -m unittest discover -s tests -v

Fake secrets are assembled from pieces so this file never contains a whole
one and the project's self-scan stays clean.
"""
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIXTURES = os.path.join(HERE, "fixtures")
TOOL = os.path.join(ROOT, "agent_secrets.py")
sys.path.insert(0, ROOT)

import agent_secrets as A  # noqa: E402

FAKE_PG = "Sup3r" + "SecretDbPass"
FAKE_SSH = "Hunter2" + "FakePass"
FAKE_MYSQL = "FakeMy" + "sql42"
FAKE_OPENAI = "sk-proj-" + "FAKEFAKEFAKEFAKE" + "1234567890abcd"
FAKE_GH = "ghp_" + "FakeFakeFakeFakeFakeFakeFakeFake1234"
ALL_FAKES = [FAKE_PG, FAKE_SSH, FAKE_MYSQL, FAKE_OPENAI, FAKE_GH]


def run_cli(*args, cwd=ROOT):
    return subprocess.run([sys.executable, TOOL] + list(args), cwd=cwd,
                          capture_output=True, text=True)


def scan_json(path):
    proc = run_cli("scan", path, "--json")
    return proc, json.loads(proc.stdout)


def build_leaky_tree(dest):
    """Lay the leaky fixtures out the way a real project would have them."""
    os.makedirs(os.path.join(dest, ".claude"))
    shutil.copy(os.path.join(FIXTURES, "leaky_settings", ".claude", "settings.local.json"),
                os.path.join(dest, ".claude", "settings.local.json"))
    shutil.copy(os.path.join(FIXTURES, "leaky_mcp", "mcp.json"), os.path.join(dest, "mcp.json"))
    os.makedirs(os.path.join(dest, "projects"))
    shutil.copy(os.path.join(FIXTURES, "leaky_transcript", "session.jsonl"),
                os.path.join(dest, "projects", "session.jsonl"))


def snapshot(root):
    snap = {}
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            p = os.path.join(dirpath, name)
            with open(p, "rb") as fh:
                snap[os.path.relpath(p, root)] = (fh.read(), stat.S_IMODE(os.stat(p).st_mode))
    return snap


class DetectorTests(unittest.TestCase):
    def kinds(self, text, **kw):
        return [h.kind for h in A.detect_text(text, **kw)]

    def test_redact(self):
        self.assertEqual(A.redact(FAKE_PG), "Sup***ss")
        self.assertEqual(A.redact("short"), "***")

    def test_inline_command_secrets(self):
        self.assertEqual(self.kinds("PGPASSWORD=" + FAKE_PG + " psql -h db"), ["pgpassword"])
        self.assertEqual(self.kinds("sshpass -p '" + FAKE_SSH + "' ssh host"), ["sshpass"])
        self.assertEqual(self.kinds("mysql -u root -p" + FAKE_MYSQL + " appdb"), ["mysql-password"])
        self.assertEqual(self.kinds("mysql -u root -p " + FAKE_MYSQL + " appdb"), ["mysql-password"])
        self.assertEqual(self.kinds("psql postgres://app:" + FAKE_PG + "@db.internal/app"),
                         ["db-url-password"])
        self.assertEqual(self.kinds("tool --api-key " + FAKE_PG), ["cli-flag-secret"])
        hdr = 'curl -H "Authorization: Bearer ' + "abcDEF1234567890" + 'xyzXYZ" https://x'
        self.assertEqual(self.kinds(hdr), ["bearer-token"])

    def test_prefixes(self):
        self.assertEqual(self.kinds("key " + FAKE_OPENAI), ["openai-key"])
        self.assertEqual(self.kinds("t=" + FAKE_GH), ["github-token"])
        self.assertEqual(self.kinds("AKIA" + "ABCDEFGHIJKLMNOP"), ["aws-key"])
        self.assertEqual(self.kinds("glpat-" + "abcdefghij1234567890"), ["gitlab-token"])

    def test_named_and_entropy(self):
        self.assertEqual(self.kinds("export DB_PASSWORD=" + FAKE_PG), ["named-secret"])
        self.assertEqual(self.kinds('"content": "run export DB_PASSWORD=' + FAKE_PG + ' now"'),
                         ["named-secret"])
        high = "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9" + "xC2"
        self.assertEqual(self.kinds("SERVICE_TOKEN=" + high), ["high-entropy-secret"])

    def test_no_false_positives(self):
        for text in [
            "Always rotate your password every 90 days.",
            'echo "enter password:" && read -s pw',
            "Password: see the team vault.",
            "PGPASSWORD=$DB_PASSWORD psql -h db",
            "PGPASSWORD=${DB_PASSWORD} psql -h db",
            "API_KEY={env:API_KEY}",
            "API_KEY=%API_KEY%",
            "API_KEY=your-key-here",
            "DB_PASSWORD=changeme",
            "mysql -u root -p appdb",
            "PASSWORD_FILE=/run/secrets/db",
            "max_tokens: 4096",
            "docker login --password-stdin",
        ]:
            self.assertEqual(A.detect_text(text), [], text)


class ScanFixtureTests(unittest.TestCase):
    def test_leaky_settings(self):
        proc, findings = scan_json(os.path.join(FIXTURES, "leaky_settings"))
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(sorted(f["kind"] for f in findings),
                         ["mysql-password", "pgpassword", "sshpass"])
        self.assertTrue(all(f["file"] == ".claude/settings.local.json" for f in findings))
        pg = [f for f in findings if f["kind"] == "pgpassword"][0]
        self.assertEqual(pg["line"], 4)
        self.assertEqual(pg["preview"], "Sup***ss")

    def test_leaky_mcp_only_the_key(self):
        proc, findings = scan_json(os.path.join(FIXTURES, "leaky_mcp"))
        self.assertEqual(proc.returncode, 1)
        self.assertEqual([(f["file"], f["kind"]) for f in findings], [("mcp.json", "openai-key")])

    def test_leaky_transcript(self):
        proc, findings = scan_json(os.path.join(FIXTURES, "leaky_transcript"))
        self.assertEqual(proc.returncode, 1)
        self.assertEqual([(f["kind"], f["line"]) for f in findings], [("github-token", 2)])

    def test_clean_and_false_positive_dirs(self):
        for name in ("clean", "false_positive"):
            proc, findings = scan_json(os.path.join(FIXTURES, name))
            self.assertEqual(findings, [], name)
            self.assertEqual(proc.returncode, 0, name)

    def test_full_secrets_never_printed(self):
        for name in ("leaky_settings", "leaky_mcp", "leaky_transcript"):
            for extra in ([], ["--json"]):
                proc = run_cli("scan", os.path.join(FIXTURES, name), *extra)
                for secret in ALL_FAKES:
                    self.assertNotIn(secret, proc.stdout + proc.stderr)

    def test_settings_under_dot_claude(self):
        with tempfile.TemporaryDirectory() as tmp:
            build_leaky_tree(tmp)
            findings = A.scan_paths([tmp])
            files = {f.file for f in findings}
            self.assertIn(".claude/settings.local.json", files)
            self.assertIn("mcp.json", files)
            self.assertIn("projects/session.jsonl", files)

    def test_usage_errors(self):
        self.assertEqual(run_cli("scan", os.path.join(FIXTURES, "missing-dir")).returncode, 2)
        self.assertEqual(run_cli().returncode, 2)
        proc = run_cli("--version")
        self.assertEqual(proc.stdout.strip(), "agent-secrets 1.0.0")


class IgnoreFileTests(unittest.TestCase):
    def test_project_self_scan_is_clean(self):
        proc = run_cli("scan", ROOT, "--json")
        self.assertEqual(json.loads(proc.stdout), [])
        self.assertEqual(proc.returncode, 0)

    def test_fixtures_still_flagged_without_ignore_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copytree(FIXTURES, os.path.join(tmp, "tests", "fixtures"))
            self.assertGreaterEqual(len(A.scan_paths([tmp])), 5)

    def test_ignore_file_patterns(self):
        with tempfile.TemporaryDirectory() as tmp:
            build_leaky_tree(tmp)
            with open(os.path.join(tmp, A.IGNORE_FILE), "w") as fh:
                fh.write("# intentional fake data\nprojects/**\nmcp.json\n")
            files = {f.file for f in A.scan_paths([tmp])}
            self.assertEqual(files, {".claude/settings.local.json"})


class ScrubTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        build_leaky_tree(self.tmp)
        self.settings = os.path.join(self.tmp, ".claude", "settings.local.json")
        with open(self.settings, "rb") as fh:
            self.original = fh.read()

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def scrub(self):
        proc = run_cli("scrub", self.tmp)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        for secret in ALL_FAKES:
            self.assertNotIn(secret, proc.stdout + proc.stderr)
        return proc

    def test_scrub_rewrites_configs(self):
        proc = self.scrub()
        self.assertIn("report-only", proc.stdout)
        with open(self.settings) as fh:
            text = fh.read()
        data = json.loads(text)
        allow = data["permissions"]["allow"]
        self.assertNotIn(FAKE_PG, text)
        self.assertNotIn(FAKE_SSH, text)
        self.assertNotIn(FAKE_MYSQL, text)
        self.assertIn("Bash(PGPASSWORD=${PGPASSWORD} psql -h db.internal -U app appdb)", allow)
        self.assertIn("Bash(npm run test:*)", allow)
        with open(os.path.join(self.tmp, "mcp.json")) as fh:
            mcp = json.load(fh)
        env = mcp["mcpServers"]["demo"]["env"]
        self.assertEqual(env["DEMO_API_KEY"], "${DEMO_API_KEY}")
        self.assertEqual(env["PLAIN_SETTING"], "hello")

        env_local = os.path.join(self.tmp, ".env.local")
        self.assertEqual(stat.S_IMODE(os.stat(env_local).st_mode), 0o600)
        stored = A.read_env_file(env_local)
        self.assertEqual(stored["PGPASSWORD"], FAKE_PG)
        self.assertEqual(stored["DEMO_API_KEY"], FAKE_OPENAI)
        self.assertEqual(sorted(v for k, v in stored.items() if k.startswith("DB_PASSWORD")),
                         sorted([FAKE_SSH, FAKE_MYSQL]))

        with open(os.path.join(self.tmp, ".gitignore")) as fh:
            lines = fh.read().splitlines()
        for required in (".env.local", ".claude/settings.local.json", ".agent-secrets-backup/"):
            self.assertEqual(lines.count(required), 1, required)

        backup = os.path.join(self.tmp, ".agent-secrets-backup", ".claude", "settings.local.json")
        with open(backup, "rb") as fh:
            self.assertEqual(fh.read(), self.original)

        # Configs are clean now; only the report-only transcript remains.
        remaining = A.scan_paths([self.tmp])
        self.assertEqual({f.file for f in remaining if f.file != ".env.local"},
                         {"projects/session.jsonl"})

    def test_scrub_is_idempotent(self):
        self.scrub()
        first = snapshot(self.tmp)
        self.scrub()
        self.assertEqual(snapshot(self.tmp), first)

    def test_env_files_are_kept_and_gitignored(self):
        env_path = os.path.join(self.tmp, ".env")
        content = "APP_NAME=demo\nDB_PASSWORD=" + FAKE_PG + "x\n"
        with open(env_path, "w") as fh:
            fh.write(content)
        self.scrub()
        with open(env_path) as fh:
            self.assertEqual(fh.read(), content)
        self.assertEqual(A.read_env_file(os.path.join(self.tmp, ".env.local"))["DB_PASSWORD"],
                         FAKE_PG + "x")
        with open(os.path.join(self.tmp, ".gitignore")) as fh:
            self.assertIn(".env", fh.read().splitlines())

    def test_scrub_rejects_missing_dir(self):
        self.assertEqual(run_cli("scrub", os.path.join(self.tmp, "nope")).returncode, 2)


@unittest.skipUnless(shutil.which("git"), "git not installed")
class HistoryTests(unittest.TestCase):
    def git(self, *args):
        return subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@invalid",
                               "-c", "commit.gpgsign=false", "-C", self.tmp] + list(args),
                              capture_output=True, text=True, check=True).stdout.strip()

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_history_reports_introducing_commit(self):
        self.git("init", "-q")
        with open(os.path.join(self.tmp, "README.md"), "w") as fh:
            fh.write("hello\n")
        self.git("add", ".")
        self.git("commit", "-q", "-m", "init")
        build_leaky_tree(self.tmp)
        self.git("add", ".")
        self.git("commit", "-q", "-m", "add agent settings")
        leaky = self.git("rev-parse", "HEAD")
        os.remove(os.path.join(self.tmp, ".claude", "settings.local.json"))
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "remove settings")

        rows = A.history_path(self.tmp)
        pg = [r for r in rows if r["kind"] == "pgpassword"]
        self.assertEqual(len(pg), 1)
        self.assertTrue(leaky.startswith(pg[0]["commit"]))
        self.assertEqual(pg[0]["file"], ".claude/settings.local.json")

        proc = run_cli("history", self.tmp, "--json")
        self.assertEqual(proc.returncode, 1)
        self.assertTrue(any(r["kind"] == "openai-key" for r in json.loads(proc.stdout)))
        for secret in ALL_FAKES:
            self.assertNotIn(secret, proc.stdout)
        self.assertEqual(self.git("status", "--porcelain"), "")   # read-only

    def test_history_not_a_repo(self):
        proc = run_cli("history", self.tmp)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("not a git repository", proc.stderr)


if __name__ == "__main__":
    unittest.main()
