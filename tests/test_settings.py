"""Dashboard settings: switching protections and adding disallowed actions at run time.

Run with: python3 -m unittest discover -t . -s tests
"""
import pathlib
import unittest

from gateway import policy, settings
from gateway.inspector import ToolCall

ROOT = pathlib.Path(__file__).resolve().parent.parent


def call(name, **inp):
    return ToolCall(id="toolu_t", name=name, input=inp)


def fresh():
    return settings.Settings(policy.load(ROOT / "policy" / "default.toml"))


class ProtectionTests(unittest.TestCase):
    def test_eight_categories_all_on_by_default(self):
        snap = fresh().snapshot()
        self.assertEqual(sorted({p["category"] for p in snap["protections"]}), list(range(8)))
        self.assertTrue(all(p["enabled"] for p in snap["protections"]))
        self.assertEqual(snap["custom_rules"], [])

    def test_default_effective_policy_matches_the_file(self):
        p = fresh().effective()
        self.assertTrue(p.judge(call("Edit", file_path=".github/workflows/ci.yml")).blocked)
        self.assertTrue(p.judge_egress("evil.example.com", tainted=False).blocked)
        self.assertTrue(p.judge_egress("pypi.org", tainted=True).blocked)

    def test_switch_off_a_rule(self):
        s = fresh()
        change = s.set_protection("protected_config", False)
        self.assertIn("Turned OFF", change)
        p = s.effective()
        self.assertFalse(p.judge(call("Edit", file_path=".github/workflows/ci.yml")).blocked)
        self.assertTrue(p.version.endswith("+dash.1"))
        self.assertIsNone(s.set_protection("protected_config", False))  # no-op: no new revision
        s.set_protection("protected_config", True)
        self.assertTrue(s.effective().judge(call("Edit", file_path=".github/workflows/ci.yml")).blocked)

    def test_switch_off_trifecta_and_allowlist(self):
        s = fresh()
        s.set_protection("trifecta", False)
        self.assertFalse(s.effective().judge_egress("pypi.org", tainted=True).blocked)
        s.set_protection("egress_allowlist", False)
        self.assertFalse(s.effective().judge_egress("evil.example.com", tainted=False).blocked)

    def test_switch_off_taint_source(self):
        s = fresh()
        s.set_protection("secrets_sensitive", False)
        tags = [h.tag for h in s.effective().classify_taint(call("Read", file_path=".env"))]
        self.assertEqual(tags, [])

    def test_locked_and_unknown_protections_refused(self):
        s = fresh()
        with self.assertRaises(settings.SettingsError):
            s.set_protection("credential_broker", False)
        with self.assertRaises(settings.SettingsError):
            s.set_protection("nope", False)

    def test_broken_policy_stays_closed(self):
        s = settings.Settings(policy.load("/nonexistent.toml"))
        self.assertTrue(s.effective().judge(call("Read", file_path="a.py")).blocked)
        with self.assertRaises(settings.SettingsError):
            s.set_protection("protected_config", False)


class CustomRuleTests(unittest.TestCase):
    def test_command_rule_blocks_literal_text(self):
        s = fresh()
        rule, change = s.add_rule({"kind": "command", "pattern": "rm -rf", "verdict": "block"})
        self.assertEqual(rule["id"], "custom_1")
        self.assertIn("rm -rf", change)
        p = s.effective()
        d = p.judge(call("Bash", command="cd /tmp && RM -RF build"))
        self.assertEqual((d.verdict, d.rule), ("block", "custom_1"))
        self.assertFalse(p.judge(call("Bash", command="ls -la")).blocked)
        # regex characters are literal, not patterns
        s.add_rule({"kind": "command", "pattern": "a.b", "verdict": "block"})
        self.assertFalse(s.effective().judge(call("Bash", command="axb")).blocked)

    def test_custom_rules_never_loosen(self):
        s = fresh()
        s.add_rule({"kind": "write", "pattern": ".github/workflows/*", "verdict": "ask"})
        d = s.effective().judge(call("Edit", file_path=".github/workflows/ci.yml"))
        self.assertEqual((d.verdict, d.rule), ("block", "protected_config"))  # the file's block still wins
        s.set_protection("protected_config", False)
        d = s.effective().judge(call("Edit", file_path=".github/workflows/ci.yml"))
        self.assertEqual((d.verdict, d.rule), ("ask", "custom_1"))

    def test_custom_block_decides_first(self):
        s = fresh()
        s.add_rule({"kind": "write", "pattern": "CLAUDE.md", "verdict": "block", "reason": "mine"})
        d = s.effective().judge(call("Write", file_path="CLAUDE.md"))
        self.assertEqual((d.rule, d.reason), ("custom_1", "mine"))

    def test_read_rule_matches_anywhere(self):
        s = fresh()
        s.add_rule({"kind": "read", "pattern": "secrets.json"})
        p = s.effective()
        self.assertTrue(p.judge(call("Read", file_path="config/secrets.json")).blocked)
        self.assertTrue(p.judge(call("Read", file_path="/workspace/secrets.json")).blocked)
        self.assertFalse(p.judge(call("Write", file_path="secrets.json")).blocked)
        d = p.judge(call("Bash", command="cat config/secrets.json"))  # the shell way round it
        self.assertEqual((d.verdict, d.rule, d.advisory), ("block", "custom_1", True))
        self.assertFalse(p.judge(call("Bash", command="ls config")).blocked)

    def test_tool_rule(self):
        s = fresh()
        s.add_rule({"kind": "tool", "pattern": "mcp__*"})
        p = s.effective()
        self.assertTrue(p.judge(call("mcp__github__create_issue", title="x")).blocked)
        self.assertFalse(p.judge(call("Read", file_path="a.py")).blocked)

    def test_host_rule_blocks_webfetch_and_egress(self):
        s = fresh()
        s.add_rule({"kind": "host", "pattern": "*.GitHub.com"})
        p = s.effective()
        self.assertTrue(p.judge(call("WebFetch", url="https://api.github.com/x", prompt="p")).blocked)
        self.assertFalse(p.judge(call("WebFetch", url="https://pypi.org/", prompt="p")).blocked)
        d = p.judge_egress("api.github.com", tainted=False)  # on the allowlist, but the operator said no
        self.assertEqual((d.verdict, d.rule), ("block", "custom_1"))

    def test_remove_rule(self):
        s = fresh()
        s.add_rule({"kind": "command", "pattern": "npm publish"})
        s.remove_rule("custom_1")
        self.assertFalse(s.effective().judge(call("Bash", command="npm publish")).blocked)
        with self.assertRaises(settings.SettingsError):
            s.remove_rule("custom_1")

    def test_bad_rules_refused(self):
        s = fresh()
        for spec in [{"kind": "x", "pattern": "a"}, {"kind": "command", "pattern": "  "},
                     {"kind": "command", "pattern": "a\nb"}, {"kind": "command", "pattern": "a" * 300},
                     {"kind": "tool", "pattern": "Bash; rm"}, {"kind": "host", "pattern": "http://x.com/"},
                     {"kind": "command", "pattern": "a", "verdict": "allow"}, "nope"]:
            with self.assertRaises(settings.SettingsError, msg=spec):
                s.add_rule(spec)
        self.assertEqual(s.custom, [])


if __name__ == "__main__":
    unittest.main()
