import json
import unittest

from policy_sentry.querying.all import get_all_actions
from policy_sentry.util.policy_files import get_sid_names_from_policy
from policy_sentry.writing.minimize import (
    get_last_conservative_report,
    minimize_statement_actions,
)
from policy_sentry.writing.sid_group import SidGroup

# Two tiny synthetic service catalogs. Catalog v2 simulates AWS shipping new
# actions that share a prefix with actions already approved in catalog v1.
CATALOG_V1 = {
    "foo:getuser",
    "foo:getrole",
    "foo:putrecord",
    "bar:listthings",
    "bar:listwidgets",
    "bar:deletewidget",
}
CATALOG_V2 = CATALOG_V1 | {"foo:getaccount", "bar:listaccounts"}


class ConservativeMinimizeTestCase(unittest.TestCase):
    def test_open_prefix_is_kept_explicit_against_future_actions(self):
        # The two approved foo Get* actions would compress to "foo:g*" by
        # default, but that open prefix would also absorb a future same-prefix
        # action, so conservative mode keeps them explicit.
        actions = ["Foo:GetUser", "Foo:GetRole"]
        normal = minimize_statement_actions(actions, CATALOG_V1)
        conservative = minimize_statement_actions(actions, CATALOG_V1, conservative=True)
        self.assertEqual(normal, ["foo:g*"])
        self.assertEqual(conservative, ["foo:getrole", "foo:getuser"])
        self.assertEqual(
            get_last_conservative_report(),
            {"foo:g*": {"reason": "open_prefix_future_actions", "blocked_by": []}},
        )

    def test_new_same_prefix_action_is_reported_as_over_grant(self):
        # After AWS adds foo:GetAccount, the would-be prefixes now match a
        # known unapproved action and must be reported with that action.
        actions = ["Foo:GetUser", "Foo:GetRole"]
        conservative = minimize_statement_actions(actions, CATALOG_V2, conservative=True)
        self.assertEqual(conservative, ["foo:getrole", "foo:getuser"])
        report = get_last_conservative_report()
        self.assertEqual(report["foo:getu*"]["reason"], "unapproved_actions_matched")
        self.assertEqual(report["foo:getu*"]["blocked_by"], ["foo:getaccount"])
        self.assertEqual(report["foo:getr*"]["blocked_by"], ["foo:getaccount"])

    def test_explicit_exclusion_keeps_the_action_detail(self):
        # Only GetUser is approved; GetRole and the newly added GetAccount are
        # effectively excluded. The wildcard that would cover them is rejected
        # and the concrete blocked actions are named.
        conservative = minimize_statement_actions(["foo:GetUser"], CATALOG_V2, conservative=True)
        self.assertEqual(conservative, ["foo:getuser"])
        report = get_last_conservative_report()
        self.assertEqual(report["foo:getu*"]["reason"], "unapproved_actions_matched")
        self.assertEqual(
            report["foo:getu*"]["blocked_by"],
            ["foo:getaccount", "foo:getrole"],
        )

    def test_mixed_services_are_evaluated_independently(self):
        actions = ["Foo:GetUser", "bar:ListThings"]
        conservative = minimize_statement_actions(actions, CATALOG_V2, conservative=True)
        self.assertEqual(conservative, ["bar:listthings", "foo:getuser"])
        report = get_last_conservative_report()
        self.assertIn("foo:getu*", report)
        self.assertIn("bar:listt*", report)
        # A foo prefix never reports bar actions and vice versa.
        self.assertTrue(all(item.startswith("foo:") for item in report["foo:getu*"]["blocked_by"]))
        self.assertTrue(all(item.startswith("bar:") for item in report["bar:listt*"]["blocked_by"]))

    def test_whole_service_approval_keeps_service_wildcard(self):
        # Approving every known foo action is an explicit, fixed intent, so the
        # service-wide wildcard is the one wildcard conservative mode allows.
        foo_actions = sorted(action for action in CATALOG_V2 if action.startswith("foo:"))
        conservative = minimize_statement_actions(foo_actions, CATALOG_V2, conservative=True)
        self.assertEqual(conservative, ["foo:*"])
        self.assertEqual(get_last_conservative_report(), {})

    def test_conservative_does_not_change_default_output(self):
        # The flag is opt-in: without it the historical minimization is intact.
        actions = ["Foo:GetUser", "Foo:GetRole"]
        self.assertEqual(
            minimize_statement_actions(actions, CATALOG_V2),
            ["foo:getr*", "foo:getu*"],
        )


class MinimizeWildcardActionsTestCase(unittest.TestCase):
    def test_minimize_statement_actions(self):
        actions_to_minimize = [
            "kms:CreateGrant",
            "kms:CreateCustomKeyStore",
            "ec2:AuthorizeSecurityGroupEgress",
            "ec2:AuthorizeSecurityGroupIngress",
        ]
        desired_result = ["ec2:authorizes*", "kms:createc*", "kms:createg*"]
        all_actions = get_all_actions(lowercase=True)
        minchars = None
        self.maxDiff = None
        # minimized_actions_list = minimize_statement_actions(desired_actions, all_actions, minchars)
        self.assertListEqual(
            sorted(minimize_statement_actions(actions_to_minimize, all_actions, minchars)),
            sorted(desired_result),
        )

    def test_minimize_statement_actions_funky_case(self):
        actions_to_minimize = [
            "kms:creategrant",
            "kms:createcustomkeystore",
            "ec2:authorizesecuritygroupegress",
            "ec2:authorizesecuritygroupingress",
        ]
        desired_result = ["ec2:authorizes*", "kms:createc*", "kms:createg*"]
        all_actions = get_all_actions(lowercase=True)
        minchars = None
        self.maxDiff = None
        # minimized_actions_list = minimize_statement_actions(desired_actions, all_actions, minchars)
        self.assertListEqual(
            sorted(minimize_statement_actions(actions_to_minimize, all_actions, minchars)),
            sorted(desired_result),
        )

    def test_minimize_statement_actions_with_min_chars(self):
        actions_to_minimize = [
            "ec2:AuthorizeSecurityGroupEgress",
            "ec2:AuthorizeSecurityGroupIngress",
        ]
        desired_result = ["ec2:authorizesecurity*"]
        all_actions = get_all_actions(lowercase=True)
        minchars = 17
        self.maxDiff = None
        self.assertListEqual(
            sorted(minimize_statement_actions(actions_to_minimize, all_actions, minchars)),
            sorted(desired_result),
        )

    def test_minimize_statement_actions_with_wildcard(self):
        actions_to_minimize = ["ec2:*"]
        desired_result = ["ec2:*"]
        all_actions = get_all_actions(lowercase=True)
        minchars = None
        self.maxDiff = None
        self.assertListEqual(
            sorted(minimize_statement_actions(actions_to_minimize, all_actions, minchars)),
            sorted(desired_result),
        )

    def test_minimize_rw_same_one(self):
        cfg = {
            "mode": "crud",
            "name": "",
            "read": [
                "arn:aws:ssm:us-east-1:123456789012:parameter/myparameter",
            ],
            "write": [
                "arn:aws:ssm:us-east-1:123456789012:parameter/myparameter",
            ],
        }
        sid_grp = SidGroup()
        write_format = sid_grp.process_template(cfg, minimize=0)

        """
        Expected result:
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "SsmMultParametermyparameter",
                    "Effect": "Allow",
                    "Action": [
                        "ssm:getpar*",
                        "ssm:deletepar*",
                        "ssm:la*",
                        "ssm:putp*"
                    ],
                    "Resource": [
                        "arn:aws:ssm:us-east-1:123456789012:parameter/myparameter"
                    ]
                }
            ]
        }
        """
        # To future-proof this unit test...
        # (1) check that there is only one SID so it was combined during minimization
        sid_names = get_sid_names_from_policy(write_format)
        self.assertEqual(len(sid_names), 1, "More than one statement returned, expected 1")

    def test_minimize_rw_same(self):
        cfg = {
            "mode": "crud",
            "name": "",
            "read": [
                "arn:aws:ssm:us-east-1:123456789012:parameter/myparameter",
                "arn:aws:ssm:us-east-1:123456789012:parameter/myparameter2",
            ],
            "write": [
                "arn:aws:ssm:us-east-1:123456789012:parameter/myparameter",
                "arn:aws:ssm:us-east-1:123456789012:parameter/myparameter2",
            ],
        }
        sid_grp = SidGroup()
        write_format = sid_grp.process_template(cfg, minimize=1)
        # print(json.dumps(write_format, indent=4))
        """
        the output will look like:

        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "SsmParameterMyparameter",
                    "Effect": "Allow",
                    "Action": [
                        "ssm:getpar*",
                        "ssm:deletepar*",
                        "ssm:la*",
                        "ssm:putp*"
                    ],
                    "Resource": [
                        "arn:aws:ssm:us-east-1:123456789012:parameter/myparameter",
                        "arn:aws:ssm:us-east-1:123456789012:parameter/myparameter2"
                    ]
                }
            ]
        }
        """
        # To future-proof this unit test...
        # (1) check that there is only one SID so it was combined during minimization
        sid_names = get_sid_names_from_policy(write_format)
        self.assertEqual(len(sid_names), 1, "More than one statement returned, expected 1")

        # (2) Check for the presence of certain actions that we know will be there
        self.assertEqual(
            write_format["Statement"][0]["Action"],
            ["ssm:deletepar*", "ssm:getpar*", "ssm:la*", "ssm:putp*", "ssm:un*"],
            "extra actions are returned",
        )
        self.assertEqual(
            write_format["Statement"][0]["Resource"],
            cfg["read"],
            "Wrong resources were returned",
        )

    def test_minimize_rw_different(self):
        cfg = {
            "mode": "crud",
            "name": "",
            "read": [
                "arn:aws:ssm:us-east-1:123456789012:parameter/myparameter",
                "arn:aws:ssm:us-east-1:123456789012:parameter/myparameter2",
            ],
            "write": [
                "arn:aws:ssm:us-east-1:123456789012:parameter/myparameter",
                "arn:aws:ssm:us-east-1:123456789012:parameter/myparameter10",
            ],
        }
        sid_grp = SidGroup()
        write_format = sid_grp.process_template(cfg, minimize=1)
        """
        Expected result:

        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "SsmReadParameter",
                    "Effect": "Allow",
                    "Action": [
                        "ssm:getpar*"
                    ],
                    "Resource": [
                        "arn:aws:ssm:us-east-1:123456789012:parameter/myparameter",
                        "arn:aws:ssm:us-east-1:123456789012:parameter/myparameter2"
                    ]
                },
                {
                    "Sid": "SsmWriteParameter",
                    "Effect": "Allow",
                    "Action": [
                        "ssm:deletepar*",
                        "ssm:la*",
                        "ssm:putp*"
                    ],
                    "Resource": [
                        "arn:aws:ssm:us-east-1:123456789012:parameter/myparameter",
                        "arn:aws:ssm:us-east-1:123456789012:parameter/myparameter10"
                    ]
                }
            ]
        }
        """
        self.assertEqual(
            len(write_format["Statement"]),
            2,
            "More than two statements returned, expected 2",
        )
        self.assertEqual(
            write_format["Statement"][0]["Action"],
            ["ssm:getpar*"],
            "extra actions are returned",
        )
        self.assertEqual(
            write_format["Statement"][0]["Resource"],
            cfg["read"],
            "Wrong resources were returned",
        )
        self.assertEqual(
            write_format["Statement"][1]["Action"],
            ["ssm:deletepar*", "ssm:la*", "ssm:putp*", "ssm:un*"],
            "extra actions are returned",
        )
        self.assertEqual(
            write_format["Statement"][1]["Resource"],
            cfg["write"],
            "Wrong resources were returned",
        )

    def test_minimize_arn_case_bucket(self):
        cfg = {
            "mode": "crud",
            "read": ["arn:aws:s3:::bucket_name"],
            "write": ["arn:aws:s3:::bucket_name"],
        }
        sid_group = SidGroup()
        results = sid_group.process_template(cfg, minimize=0)

        # print(json.dumps(results, indent=4))
        # To future-proof this unit test...
        # (1) check that there is only one SID so it was combined during minimization
        sid_names = get_sid_names_from_policy(results)
        # For S3, it does require iam:PassRole lol because of s3:PutReplicationConfiguration requiring it as an action
        self.assertEqual(len(sid_names), 2, "More than 2 statements returned, expected 2")

    def test_minimize_arn_case_1(self):
        """minimization test with ARN types from test_does_arn_match_case_1"""
        cfg = {
            "mode": "crud",
            "read": ["arn:aws:codecommit:us-east-1:123456789012:MyDemoRepo"],
            "write": ["arn:aws:codecommit:us-east-1:123456789012:MyDemoRepo"],
        }
        sid_group = SidGroup()
        results = sid_group.process_template(cfg, minimize=0)
        sid_names = get_sid_names_from_policy(results)
        self.assertEqual(len(sid_names), 1, "More than one statement returned, expected 1")

    def test_minimize_arn_case_3(self):
        """minimization test with ARN types from test_does_arn_match_case_3"""
        cfg = {
            "mode": "crud",
            "read": [
                "arn:aws:kinesis:us-east-1:account-id:firehose/myfirehose/consumer/someconsumer:${ConsumerCreationTimpstamp}"
            ],
            "write": [
                "arn:aws:kinesis:us-east-1:account-id:firehose/myfirehose/consumer/someconsumer:${ConsumerCreationTimpstamp}"
            ],
        }
        sid_group = SidGroup()
        results = sid_group.process_template(cfg, minimize=0)
        sid_names = get_sid_names_from_policy(results)
        self.assertEqual(len(sid_names), 1, "More than one statement returned, expected 1")

    def test_minimize_arn_case_4(self):
        """minimization test with ARN types from test_does_arn_match_case_4"""
        cfg = {
            "mode": "crud",
            "read": ["arn:aws:batch:region:account-id:job-definition/job-name:revision"],
            "write": ["arn:aws:batch:region:account-id:job-definition/job-name:revision"],
        }
        sid_group = SidGroup()
        results = sid_group.process_template(cfg, minimize=0)
        sid_names = get_sid_names_from_policy(results)
        self.assertEqual(len(sid_names), 1, "More than one statement returned, expected 1")

    def test_minimize_arn_case_5(self):
        """minimization test with ARN types from test_does_arn_match_case_5"""
        cfg = {
            "mode": "crud",
            "read": ["arn:aws:states:region:account-id:stateMachine:stateMachineName"],
            "write": ["arn:aws:states:region:account-id:stateMachine:stateMachineName"],
        }
        sid_group = SidGroup()
        results = sid_group.process_template(cfg, minimize=0)
        sid_names = get_sid_names_from_policy(results)
        self.assertEqual(len(sid_names), 2, "More than two statements returned, expected 2")

    def test_minimize_arn_case_6(self):
        """minimization test with ARN types from test_does_arn_match_case_6"""
        cfg = {
            "mode": "crud",
            "read": ["arn:aws:states:region:account-id:execution:stateMachineName:executionName"],
            "write": ["arn:aws:states:region:account-id:execution:stateMachineName:executionName"],
        }
        sid_group = SidGroup()
        results = sid_group.process_template(cfg, minimize=0)
        sid_names = get_sid_names_from_policy(results)
        self.assertEqual(len(sid_names), 1, "More than one statement returned, expected 1")

    # TODO: Greengrass now has two documentation pages. Need to fix that. Perhaps look to #226 for guidance? idk.
    # def test_minimize_arn_case_7(self):
    #     """minimization test with ARN types from test_does_arn_match_case_7"""
    #     cfg = {
    #         "mode": "crud",
    #         "read": ["arn:aws:greengrass:${Region}:${Account}:/greengrass/definition/devices/1234567/versions/1"],
    #         "write": ["arn:aws:greengrass:${Region}:${Account}:/greengrass/definition/devices/1234567/versions/1"]
    #     }
    #     sid_group = SidGroup()
    #     results = sid_group.process_template(cfg, minimize=0)
    #     sid_names = get_sid_names_from_policy(results)
    #     self.assertEqual(len(sid_names), 1, "More than one statement returned, expected 1")

    def test_GH_364_remove_duplicates_from_minimize(self):
        cfg = {
            "mode": "crud",
            "read": ["arn:aws:rds:*:*:*:test-*"],
            "write": ["arn:aws:rds:*:*:*:test-*"],
            "list": ["arn:aws:rds:*:*:*:test-*"],
            "tagging": ["arn:aws:rds:*:*:*:test-*"],
            "permissions-management": ["arn:aws:rds:*:*:*:test-*"],
        }
        # Bug introduced in https://github.com/salesforce/policy_sentry/pull/252
        sid_group = SidGroup()
        results = sid_group.process_template(cfg, minimize=0)
        print(json.dumps(results, indent=4))
        actions = results["Statement"][0]["Action"]
        actions_set = set(actions)
        self.assertEqual(
            len(actions_set),
            len(actions),
            "There should be no duplicate strings in the actions.",
        )

    def test_conservative_template_keeps_explicit_actions_and_reports(self):
        # A normal minimization compresses SSM parameter actions to prefix
        # wildcards. Conservative mode must keep them explicit because the
        # prefix is open, and expose the rejected prefixes on the SidGroup.
        cfg = {
            "mode": "crud",
            "read": ["arn:aws:ssm:us-east-1:123456789012:parameter/myparameter"],
        }
        normal_group = SidGroup()
        normal_policy = normal_group.process_template(cfg, minimize=0)
        normal_actions = normal_policy["Statement"][0]["Action"]
        self.assertTrue(any("*" in action for action in normal_actions))

        conservative_group = SidGroup()
        conservative_policy = conservative_group.process_template(cfg, minimize=0, conservative=True)
        conservative_actions = conservative_policy["Statement"][0]["Action"]
        # Every granted action is an explicit, full action name.
        self.assertTrue(all("*" not in action for action in conservative_actions))
        self.assertTrue(conservative_group.conservative_report)
        for entry in conservative_group.conservative_report.values():
            self.assertIn(entry["reason"], ("unapproved_actions_matched", "open_prefix_future_actions"))
            self.assertIsInstance(entry["blocked_by"], list)
