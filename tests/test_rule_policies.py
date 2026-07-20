import json
import os
import tempfile
import unittest
from datetime import datetime
from unittest import mock

import web_panel as panel


def stamp(year, month, day, hour=10, minute=0):
    return int(datetime(year, month, day, hour, minute, tzinfo=panel.POLICY_TIMEZONE).timestamp())


def counter(upload=0, download=0):
    return {
        "upload": {"packets": 0, "bytes": upload},
        "download": {"packets": 0, "bytes": download},
    }


class RulePolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_paths = {
            name: getattr(panel, name)
            for name in ("CONF_DIR", "CONF_FILE", "POLICIES_FILE", "FIREWALL_PORTS_FILE")
        }
        panel.CONF_DIR = self.temp.name
        panel.CONF_FILE = os.path.join(self.temp.name, "port-forward.conf")
        panel.POLICIES_FILE = os.path.join(self.temp.name, "rule-policies.json")
        panel.FIREWALL_PORTS_FILE = os.path.join(self.temp.name, "firewall-ports.db")
        self.rule = {
            "lport": 21001,
            "ip": "104.251.236.83",
            "dport": 21001,
            "enabled": True,
            "statsMode": "total",
        }

    def tearDown(self):
        for name, value in self.old_paths.items():
            setattr(panel, name, value)
        self.temp.cleanup()

    def test_three_month_expiry_uses_full_calendar_months(self):
        now = stamp(2026, 1, 15)
        policy = panel.policy_payload(
            {"lifetimeMode": "limited", "expiryMode": "months", "durationMonths": 3},
            self.rule,
            now=now,
        )
        self.assertEqual(policy["expiresAt"], stamp(2026, 4, 15))

    def test_month_end_anchor_returns_to_day_31(self):
        policy = panel.default_rule_policy(self.rule, now=stamp(2026, 1, 31))
        policy.update({"quotaEnabled": True, "resetAnchorDay": 31, "resetHour": 10, "resetMinute": 0})
        february = panel.next_monthly_reset(stamp(2026, 1, 31), policy)
        march = panel.next_monthly_reset(february, policy)
        self.assertEqual(february, stamp(2026, 2, 28))
        self.assertEqual(march, stamp(2026, 3, 31))

    def test_legacy_rule_migrates_to_permanent_unlimited(self):
        policies = panel.read_rule_policies([self.rule], now=stamp(2026, 1, 15))
        policy = policies["21001"]
        self.assertEqual(policy["lifetimeMode"], "permanent")
        self.assertFalse(policy["quotaEnabled"])
        self.assertTrue(policy["desiredEnabled"])
        with open(panel.POLICIES_FILE, encoding="utf-8") as source:
            saved = json.load(source)
        self.assertIn("21001", saved["policies"])

    def test_quota_exhaustion_resets_and_reopens(self):
        reset_at = stamp(2026, 2, 15)
        policy = panel.default_rule_policy(self.rule, now=stamp(2026, 1, 15))
        policy.update({
            "quotaEnabled": True,
            "quotaBytes": 100,
            "quotaMode": "total",
            "nextResetAt": reset_at,
            "resetAnchorDay": 15,
            "resetHour": 10,
            "resetMinute": 0,
        })
        self.assertEqual(panel.rule_policy_status(policy, counter(60, 40), now=reset_at - 1)[0], "quota_exhausted")
        self.assertTrue(panel.advance_policy_reset(policy, reset_at, counter(60, 40)))
        self.assertEqual(panel.rule_policy_status(policy, counter(60, 40), now=reset_at)[0], "running")
        self.assertEqual(policy["nextResetAt"], stamp(2026, 3, 15))

    def test_expiry_wins_even_when_quota_resets(self):
        expired_at = stamp(2026, 4, 15)
        policy = panel.default_rule_policy(self.rule, now=stamp(2026, 1, 15))
        policy.update({
            "lifetimeMode": "limited",
            "expiresAt": expired_at,
            "quotaEnabled": True,
            "quotaBytes": 100,
            "nextResetAt": expired_at,
            "resetAnchorDay": 15,
            "resetHour": 10,
            "resetMinute": 0,
        })
        panel.advance_policy_reset(policy, expired_at, counter(100, 0))
        self.assertEqual(panel.rule_policy_status(policy, counter(100, 0), now=expired_at)[0], "expired")

    def test_manual_off_has_priority_over_available_quota(self):
        policy = panel.default_rule_policy(self.rule, now=stamp(2026, 1, 15))
        policy["desiredEnabled"] = False
        self.assertEqual(panel.rule_policy_status(policy, counter(), now=stamp(2026, 1, 16))[0], "manual_off")

    def test_expired_rule_can_be_extended_without_being_deleted(self):
        now = stamp(2026, 4, 16)
        old = panel.default_rule_policy(self.rule, now=stamp(2026, 1, 15))
        old.update({"lifetimeMode": "limited", "expiresAt": stamp(2026, 4, 15)})
        updated = panel.policy_payload(
            {
                "lifetimeMode": "limited",
                "expiryMode": "custom",
                "expiresAt": "2026-05-15T10:00",
                "quotaEnabled": False,
            },
            self.rule,
            old_policy=old,
            now=now,
        )
        self.assertEqual(panel.rule_policy_status(updated, counter(), now=now)[0], "running")

    def test_custom_reset_must_precede_expiry(self):
        with self.assertRaisesRegex(ValueError, "下次重置时间必须早于到期时间"):
            panel.policy_payload(
                {
                    "lifetimeMode": "limited",
                    "expiryMode": "custom",
                    "expiresAt": "2026-04-15T10:00",
                    "quotaEnabled": True,
                    "quotaGb": 100,
                    "quotaMode": "total",
                    "resetMode": "custom",
                    "nextResetAt": "2026-04-15T10:00",
                },
                self.rule,
                now=stamp(2026, 1, 15),
            )

    def test_imported_policy_keeps_limits_but_starts_fresh_usage(self):
        content = json.dumps({
            "format": "nft-manager-config",
            "schemaVersion": 2,
            "targets": [{"alias": "RFC", "ip": "104.251.236.83"}],
            "rules": [{
                **self.rule,
                "policy": {
                    "desiredEnabled": True,
                    "lifetimeMode": "permanent",
                    "quotaEnabled": True,
                    "quotaBytes": 100,
                    "quotaMode": "total",
                    "nextResetAt": stamp(2026, 8, 15),
                    "baselineUpload": 9999,
                    "baselineDownload": 8888,
                },
            }],
        })
        imported = panel.normalized_config_payload(content)["rules"][0]["_policy"]
        self.assertTrue(imported["quotaEnabled"])
        self.assertEqual(imported["quotaBytes"], 100)
        self.assertEqual(imported["baselineUpload"], 0)
        self.assertEqual(imported["baselineDownload"], 0)

    def test_schema_one_import_remains_permanent_and_unlimited(self):
        content = json.dumps({
            "format": "nft-manager-config",
            "schemaVersion": 1,
            "targets": [],
            "rules": [self.rule],
        })
        imported = panel.normalized_config_payload(content)["rules"][0]
        policy = panel.default_rule_policy(imported, managed_ports=set())
        self.assertEqual(policy["lifetimeMode"], "permanent")
        self.assertFalse(policy["quotaEnabled"])

    def test_policy_is_persistent_across_reload(self):
        policy = panel.default_rule_policy(self.rule, now=stamp(2026, 1, 15))
        policy.update({"quotaEnabled": True, "quotaBytes": 100, "baselineUpload": 25})
        panel.save_rule_policies({"21001": policy})
        loaded = panel.read_rule_policies([self.rule], now=stamp(2026, 1, 16))["21001"]
        self.assertTrue(loaded["quotaEnabled"])
        self.assertEqual(loaded["quotaBytes"], 100)
        self.assertEqual(loaded["baselineUpload"], 25)

    def test_enforcement_disables_rule_without_deleting_it(self):
        policy = panel.default_rule_policy(self.rule, now=stamp(2026, 1, 15))
        policy.update({"quotaEnabled": True, "quotaBytes": 100, "manageFirewall": True})
        panel.save_rule_policies({"21001": policy})
        written = []
        firewall = []
        with mock.patch.object(panel, "parse_rules", return_value=[dict(self.rule)]), \
             mock.patch.object(panel, "write_rules", side_effect=lambda rules: written.extend(rules)), \
             mock.patch.object(panel, "reload_rules"), \
             mock.patch.object(panel, "sync_policy_firewall", side_effect=lambda opened, closed: firewall.append((set(opened), set(closed)))):
            rules, _ = panel.enforce_rule_policies(
                counters={panel.rule_counter_key(self.rule): counter(75, 25)},
                now=stamp(2026, 1, 16),
            )
        self.assertEqual(len(rules), 1)
        self.assertFalse(rules[0]["enabled"])
        self.assertEqual(len(written), 1)
        self.assertIn(21001, firewall[0][1])


if __name__ == "__main__":
    unittest.main()
