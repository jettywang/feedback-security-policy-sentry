import unittest

from policy_sentry.writing.sid_group import SidGroup

FUNCTION_ARN = "arn:aws:lambda:us-east-1:123456789012:function:my-function"
FUNCTION_ARN_CN = "arn:aws-cn:lambda:cn-north-1:123456789012:function:my-function"
CODE_SIGNING_ARN = "arn:aws:lambda:us-east-1:123456789012:code-signing-config:csg-12345678"
CODE_SIGNING_ARN_CN = "arn:aws-cn:lambda:cn-north-1:123456789012:code-signing-config:csg-12345678"
FUNCTION_RAW_ARN = "arn:${Partition}:lambda:${Region}:${Account}:function:${FunctionName}"
CODE_SIGNING_RAW_ARN = "arn:${Partition}:lambda:${Region}:${Account}:code-signing-config:${CodeSigningConfigId}"


def missing_types(diagnostic):
    return {
        entry["resource_type"]: entry["raw_arn"]
        for entry in diagnostic["required_resource_types"]
        if not entry["satisfied"]
    }


def statement_resources(policy):
    return {sid["Sid"]: sid["Resource"] for sid in policy["Statement"]}


class SidGroupMissingResourcesTestCase(unittest.TestCase):
    def test_diagnosis_points_at_the_statement_that_needs_an_arn(self):
        """The missing required type's raw ARN format is exactly the Resource of a generated statement."""
        sid_group = SidGroup()
        policy = sid_group.add_by_list_of_actions(["lambda:PutFunctionCodeSigningConfig"])
        resources = statement_resources(policy)

        # One statement per required resource type.
        self.assertEqual(resources["LambdaWriteFunction"], [FUNCTION_RAW_ARN])
        self.assertEqual(resources["LambdaWriteCodesigningconfig"], [CODE_SIGNING_RAW_ARN])

        # Requester only supplies the function ARN.
        diagnostic = sid_group.get_missing_required_resources(
            ["lambda:PutFunctionCodeSigningConfig"],
            [FUNCTION_ARN],
        )[0]
        self.assertEqual(missing_types(diagnostic), {"code signing config": CODE_SIGNING_RAW_ARN})
        self.assertEqual(
            missing_types(diagnostic)["code signing config"],
            resources["LambdaWriteCodesigningconfig"][0],
        )

        # Supplying the missing ARN closes the diagnostic, and the partition can differ.
        for code_signing_arn in (CODE_SIGNING_ARN, CODE_SIGNING_ARN_CN):
            satisfied = sid_group.get_missing_required_resources(
                ["lambda:PutFunctionCodeSigningConfig"],
                [FUNCTION_ARN, code_signing_arn],
            )[0]
            self.assertEqual(missing_types(satisfied), {})

        # An aws-cn function ARN also matches the aws-partition raw ARN format.
        china_diagnostic = sid_group.get_missing_required_resources(
            ["lambda:PutFunctionCodeSigningConfig"],
            [FUNCTION_ARN_CN, CODE_SIGNING_ARN_CN],
        )[0]
        self.assertEqual(missing_types(china_diagnostic), {})

    def test_wildcard_only_statement_has_no_missing_resource_types(self):
        """Wildcard-only actions produce a Resource: '*' statement and no missing-type diagnostics."""
        sid_group = SidGroup()
        policy = sid_group.add_by_list_of_actions(["s3:ListAllMyBuckets"])
        resources = statement_resources(policy)
        self.assertEqual(resources["MultMultNone"], ["*"])

        diagnostic = sid_group.get_missing_required_resources(["s3:ListAllMyBuckets"], [])[0]
        self.assertTrue(diagnostic["wildcard_only"])
        self.assertEqual(missing_types(diagnostic), {})
        self.assertEqual(diagnostic["required_resource_types"], [])

    def test_optional_types_absent_from_both_statements_and_diagnostics(self):
        """An optional resource type neither creates a missing item nor changes the required statements."""
        sid_group = SidGroup()
        sid_group.add_by_list_of_actions(["appstream:CreateFleet"])
        diagnostic = sid_group.get_missing_required_resources(
            ["appstream:CreateFleet"],
            ["arn:aws:appstream:us-east-1:123456789012:fleet/MyFleet"],
        )[0]
        self.assertEqual(missing_types(diagnostic), {})
        self.assertEqual(diagnostic["optional_resource_types"], ["image"])


if __name__ == "__main__":
    unittest.main()
