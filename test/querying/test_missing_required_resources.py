import unittest

from policy_sentry.querying.actions import (
    get_action_resource_requirements,
    get_missing_required_resource_types,
)

LAMBDA_FUNCTION_ARN = "arn:aws:lambda:us-east-1:123456789012:function:my-function"
LAMBDA_CODE_SIGNING_ARN = "arn:aws:lambda:us-east-1:123456789012:code-signing-config:csg-12345678"
EC2_INSTANCE_ARN = "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0"
EC2_IMAGE_ARN = "arn:aws:ec2:us-east-1::image/ami-0123456789abcdef0"
APPSTREAM_FLEET_ARN = "arn:aws:appstream:us-east-1:123456789012:fleet/MyFleet"
APPSTREAM_IMAGE_ARN = "arn:aws:appstream:us-east-1:123456789012:image/MyImage"


def index_by_resource_type(diagnostic):
    return {entry["resource_type"]: entry for entry in diagnostic["required_resource_types"]}


class MissingRequiredResourcesTestCase(unittest.TestCase):
    def test_action_resource_requirements_from_local_database(self):
        """Requirements are derived from the local iam-definition.json data."""
        requirements = get_action_resource_requirements("lambda", "PutFunctionCodeSigningConfig")
        required_types = [entry["resource_type"] for entry in requirements["required_resource_types"]]
        self.assertEqual(required_types, ["code signing config", "function"])
        self.assertEqual(requirements["optional_resource_types"], [])
        # The empty-string resource type entry only carries condition keys.
        self.assertEqual(requirements["condition_only_resource_types"], ["lambda:CodeSigningConfigArn"])
        self.assertFalse(requirements["wildcard_only"])

    def test_multiple_required_types_one_missing(self):
        """Supplying only one required ARN flags the other required type as missing."""
        diagnostics = get_missing_required_resource_types(
            ["lambda:PutFunctionCodeSigningConfig"],
            [LAMBDA_FUNCTION_ARN],
        )
        self.assertEqual(len(diagnostics), 1)
        diagnostic = diagnostics[0]
        self.assertEqual(diagnostic["action"], "lambda:PutFunctionCodeSigningConfig")
        by_type = index_by_resource_type(diagnostic)
        self.assertTrue(by_type["function"]["satisfied"])
        missing = by_type["code signing config"]
        self.assertFalse(missing["satisfied"])
        self.assertEqual(
            missing["raw_arn"],
            "arn:${Partition}:lambda:${Region}:${Account}:code-signing-config:${CodeSigningConfigId}",
        )

    def test_multiple_required_types_all_satisfied(self):
        """ARNs covering every required type leave no missing types."""
        diagnostics = get_missing_required_resource_types(
            ["lambda:PutFunctionCodeSigningConfig"],
            [LAMBDA_FUNCTION_ARN, LAMBDA_CODE_SIGNING_ARN],
        )
        diagnostic = diagnostics[0]
        self.assertTrue(all(entry["satisfied"] for entry in diagnostic["required_resource_types"]))
        missing = [entry["resource_type"] for entry in diagnostic["required_resource_types"] if not entry["satisfied"]]
        self.assertEqual(missing, [])

    def test_optional_types_are_never_reported_as_missing(self):
        """An optional resource type without an ARN does not show up among the missing required types."""
        diagnostics = get_missing_required_resource_types(
            ["appstream:CreateFleet"],
            [APPSTREAM_FLEET_ARN],
        )
        diagnostic = diagnostics[0]
        self.assertEqual(
            [entry["resource_type"] for entry in diagnostic["required_resource_types"]],
            ["fleet"],
        )
        self.assertTrue(index_by_resource_type(diagnostic)["fleet"]["satisfied"])
        self.assertEqual(diagnostic["optional_resource_types"], ["image"])
        self.assertNotIn("image", index_by_resource_type(diagnostic))

        # Supplying the optional ARN does not change the required-type diagnostics.
        with_optional = get_missing_required_resource_types(
            ["appstream:CreateFleet"],
            [APPSTREAM_FLEET_ARN, APPSTREAM_IMAGE_ARN],
        )[0]
        self.assertEqual(diagnostic["required_resource_types"], with_optional["required_resource_types"])

    def test_ec2_run_instances_flags_every_other_required_type(self):
        """Only supplying the instance ARN names all four other required EC2 types as missing."""
        diagnostics = get_missing_required_resource_types(
            ["ec2:RunInstances"],
            [EC2_INSTANCE_ARN],
        )
        diagnostic = diagnostics[0]
        by_type = index_by_resource_type(diagnostic)
        self.assertTrue(by_type["instance"]["satisfied"])
        for required_type in ("image", "network-interface", "security-group", "subnet"):
            self.assertIn(required_type, by_type)
            self.assertFalse(by_type[required_type]["satisfied"])
        # Optional types such as key-pair or volume are never flagged.
        self.assertNotIn("key-pair", by_type)
        self.assertNotIn("volume", by_type)
        self.assertIn("key-pair", diagnostic["optional_resource_types"])

        # Adding the image ARN removes exactly that missing item.
        with_image = get_missing_required_resource_types(
            ["ec2:RunInstances"],
            [EC2_INSTANCE_ARN, EC2_IMAGE_ARN],
        )[0]
        self.assertTrue(index_by_resource_type(with_image)["image"]["satisfied"])
        self.assertFalse(index_by_resource_type(with_image)["subnet"]["satisfied"])

    def test_wildcard_only_action_has_no_resource_requirements(self):
        """Actions that can only use Resource: '*' report wildcard_only instead of missing types."""
        diagnostics = get_missing_required_resource_types(["s3:ListAllMyBuckets"], [])
        diagnostic = diagnostics[0]
        self.assertTrue(diagnostic["wildcard_only"])
        self.assertEqual(diagnostic["required_resource_types"], [])
        self.assertEqual(diagnostic["optional_resource_types"], [])

    def test_wildcard_arn_satisfies_every_required_type(self):
        """A bare '*' or a wildcarded ARN covers all required resource types."""
        for wildcard_arn in ("*", "arn:aws:ec2:us-east-1:123456789012:*:*"):
            diagnostic = get_missing_required_resource_types(
                ["ec2:RunInstances"],
                [wildcard_arn],
            )[0]
            self.assertTrue(
                all(entry["satisfied"] for entry in diagnostic["required_resource_types"]),
                wildcard_arn,
            )

    def test_partition_differences_do_not_affect_matching(self):
        """aws, aws-cn and aws-us-gov ARNs match the same raw ARN format."""
        china_arn = "arn:aws-cn:lambda:cn-north-1:123456789012:code-signing-config:csg-12345678"
        gov_arn = "arn:aws-us-gov:lambda:us-gov-east-1:123456789012:code-signing-config:csg-12345678"
        for arn in (LAMBDA_CODE_SIGNING_ARN, china_arn, gov_arn):
            diagnostic = get_missing_required_resource_types(
                ["lambda:PutFunctionCodeSigningConfig"],
                [LAMBDA_FUNCTION_ARN, arn],
            )[0]
            self.assertTrue(
                all(entry["satisfied"] for entry in diagnostic["required_resource_types"]),
                arn,
            )

    def test_unknown_action_is_flagged(self):
        """Unknown actions are reported as unknown instead of silently ignored."""
        diagnostic = get_missing_required_resource_types(["lambda:DoesNotExist"], [])[0]
        self.assertTrue(diagnostic["unknown"])
        self.assertEqual(diagnostic["required_resource_types"], [])


if __name__ == "__main__":
    unittest.main()
