import unittest
import json
from policy_sentry.writing.sid_group import SidGroup
from policy_sentry.util.policy_files import get_actions_from_policy


class DenyEffectCrudTestCase(unittest.TestCase):
    """Test that the Deny effect works in CRUD mode"""

    def test_deny_effect_crud_mode(self):
        """Generate a Deny policy via CRUD mode"""
        cfg = {
            "mode": "crud",
            "name": "DenyS3Read",
            "effect": "Deny",
            "read": [
                "arn:aws:s3:::example-org-s3-access-logs",
            ],
        }
        sid_group = SidGroup()
        output = sid_group.process_template(cfg)
        print(json.dumps(output, indent=4))
        self.assertEqual(output["Version"], "2012-10-17")
        for statement in output["Statement"]:
            self.assertEqual(statement["Effect"], "Deny")

    def test_default_allow_crud_mode(self):
        """Verify default is still Allow when effect is not specified"""
        cfg = {
            "mode": "crud",
            "name": "AllowS3Read",
            "read": [
                "arn:aws:s3:::example-org-s3-access-logs",
            ],
        }
        sid_group = SidGroup()
        output = sid_group.process_template(cfg)
        print(json.dumps(output, indent=4))
        self.assertEqual(output["Version"], "2012-10-17")
        for statement in output["Statement"]:
            self.assertEqual(statement["Effect"], "Allow")


class DenyEffectActionsTestCase(unittest.TestCase):
    """Test that the Deny effect works in Actions mode"""

    def test_deny_effect_actions_mode(self):
        """Generate a Deny policy via Actions mode"""
        cfg = {
            "mode": "actions",
            "name": "DenyEc2Actions",
            "effect": "Deny",
            "actions": [
                "ec2:AuthorizeSecurityGroupEgress",
                "ec2:AuthorizeSecurityGroupIngress",
            ],
        }
        sid_group = SidGroup()
        output = sid_group.process_template(cfg)
        print(json.dumps(output, indent=4))
        self.assertEqual(output["Version"], "2012-10-17")
        for statement in output["Statement"]:
            self.assertEqual(statement["Effect"], "Deny")

    def test_default_allow_actions_mode(self):
        """Verify default is still Allow when effect is not specified in actions mode"""
        cfg = {
            "mode": "actions",
            "name": "AllowEc2Actions",
            "actions": [
                "ec2:AuthorizeSecurityGroupEgress",
                "ec2:AuthorizeSecurityGroupIngress",
            ],
        }
        sid_group = SidGroup()
        output = sid_group.process_template(cfg)
        print(json.dumps(output, indent=4))
        self.assertEqual(output["Version"], "2012-10-17")
        for statement in output["Statement"]:
            self.assertEqual(statement["Effect"], "Allow")


class InvalidEffectTestCase(unittest.TestCase):
    """Test that invalid effect values raise errors"""

    def test_invalid_effect_raises_error(self):
        """Test invalid effect value raises ValueError"""
        cfg = {
            "mode": "crud",
            "name": "InvalidEffect",
            "effect": "Something",
            "read": [
                "arn:aws:s3:::example-org-s3-access-logs",
            ],
        }
        sid_group = SidGroup()
        with self.assertRaises(ValueError) as context:
            sid_group.process_template(cfg)
        self.assertIn("Invalid effect", str(context.exception))


class DenyNotOverriddenRegressionTestCase(unittest.TestCase):
    """Regression tests guarding that an explicit Deny is never silently downgraded to Allow."""

    def test_add_by_list_of_actions_does_not_pin_allow(self):
        """The library API must not render an Allow policy before the caller can request Deny."""
        sid_group = SidGroup()
        # add_by_list_of_actions used to call get_rendered_policy() with the default Allow effect.
        sid_group.add_by_list_of_actions(["ec2:AuthorizeSecurityGroupIngress"])
        deny_policy = sid_group.get_rendered_policy(effect="Deny")
        self.assertTrue(deny_policy["Statement"])
        self.assertTrue(
            all(statement["Effect"] == "Deny" for statement in deny_policy["Statement"])
        )

    def test_minimize_keeps_deny_on_merged_statements(self):
        """Minimization merges same-resource SIDs but must keep the Deny effect on every merge."""
        cfg = {
            "mode": "crud",
            "name": "DenyMinimize",
            "effect": "Deny",
            "read": ["arn:aws:s3:::shared-bucket"],
            "write": ["arn:aws:s3:::shared-bucket"],
            "list": ["arn:aws:s3:::shared-bucket"],
        }
        sid_group = SidGroup()
        output = sid_group.process_template(cfg, minimize=0)
        self.assertTrue(output["Statement"])
        self.assertTrue(
            all(statement["Effect"] == "Deny" for statement in output["Statement"])
        )

    def test_same_action_resource_allow_and_deny_both_survive_merge(self):
        """An Allow and an explicit Deny for the same action/resource render as separate
        statements (which may share a Sid); the Deny must remain present and name the action,
        because IAM resolves the overlap in favor of the Deny at evaluation time."""
        allow_cfg = {
            "mode": "actions",
            "name": "AllowObject",
            "actions": ["s3:GetObject", "s3:PutObject"],
        }
        deny_cfg = {
            "mode": "actions",
            "name": "DenyObject",
            "effect": "Deny",
            "actions": ["s3:PutObject"],
        }
        allow_policy = SidGroup().process_template(allow_cfg)
        deny_policy = SidGroup().process_template(deny_cfg)

        combined_statements = allow_policy["Statement"] + deny_policy["Statement"]
        allow_statements = [s for s in combined_statements if s["Effect"] == "Allow"]
        deny_statements = [s for s in combined_statements if s["Effect"] == "Deny"]

        # The explicit Deny is a distinct statement and still targets the guarded action.
        self.assertTrue(deny_statements, "The explicit Deny statement was dropped")
        self.assertTrue(
            any("s3:PutObject" in statement["Action"] for statement in deny_statements)
        )
        # The Allow is untouched, so both constraints are represented in the final JSON.
        self.assertTrue(
            any("s3:PutObject" in statement["Action"] for statement in allow_statements)
        )
        # The analyzer deliberately evaluates Allow statements only, so it never mistakes
        # the Deny for a grant and reports the action once per Allow statement that names it.
        combined = {"Version": "2012-10-17", "Statement": combined_statements}
        allow_only = get_actions_from_policy(combined)
        allow_only_count = len(
            [s for s in allow_statements if "s3:PutObject" in s["Action"]]
        )
        self.assertEqual(allow_only.count("s3:PutObject"), allow_only_count)
        self.assertIn("s3:GetObject", allow_only)

    def test_same_sid_name_can_carry_distinct_effects(self):
        """Two independent renders can produce the same Sid with different Effects; the Sid name
        alone must not cause one statement to clobber the other."""
        cfg = {"mode": "actions", "name": "SameActions", "actions": ["s3:PutObject"]}
        allow_policy = SidGroup().process_template(dict(cfg, effect="Allow"))
        deny_policy = SidGroup().process_template(dict(cfg, effect="Deny"))
        self.assertEqual(
            [s["Sid"] for s in allow_policy["Statement"]],
            [s["Sid"] for s in deny_policy["Statement"]],
        )
        self.assertTrue(
            all(s["Effect"] == "Allow" for s in allow_policy["Statement"])
        )
        self.assertTrue(
            all(s["Effect"] == "Deny" for s in deny_policy["Statement"])
        )


if __name__ == "__main__":
    unittest.main()
