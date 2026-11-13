"""
Live demonstration of Policy Sentry's grouping/minimization behavior when two
requested statements share Action+Resource but differ only in Condition.

Run from repo root:
    PYTHONPATH="$TMPDIR/psstubs:." python3 condition_merge_analysis/demo_policy_sentry_behavior.py
"""
import json

from policy_sentry.writing.sid_group import SidGroup

ARN = "arn:aws:s3:::my-bucket"
COND_A = {
    "condition_key_string": "aws:RequestedRegion",
    "condition_type_string": "StringEquals",
    "condition_value": "eu-west-1",
}
COND_B = {
    "condition_key_string": "aws:RequestedRegion",
    "condition_type_string": "StringEqualsIfExists",
    "condition_value": "eu-west-1",
}

print("=" * 72)
print("DEMO 1: add_by_arn_and_access_level called twice, same ARN+level,")
print("        different condition blocks -> do they stay separate?")
print("=" * 72)
sg = SidGroup()
sg.add_by_arn_and_access_level([ARN], "Write", _conditions_block=COND_A)
sg.add_by_arn_and_access_level([ARN], "Write", _conditions_block=COND_B)
print("SID namespaces after grouping:", sg.list_sids())
print("conditions stored on the group:", [g.get("conditions") for g in sg.sids.values()])
policy = sg.get_rendered_policy()
print("rendered policy (no minimize):")
print(json.dumps(policy, indent=2))

print()
print("=" * 72)
print("DEMO 2: two SID groups, identical ARN list, different (hypothetical)")
print("        conditions attached -> get_rendered_policy(minimize=0)")
print("=" * 72)
sg2 = SidGroup()
sg2.sids = {
    "S3WriteBucketRegionEquals": {
        "arn": [ARN],
        "service": "s3",
        "access_level": "Write",
        "arn_format": "arn:${Partition}:s3:::${BucketName}",
        "actions": ["s3:PutObject", "s3:DeleteObject"],
        "conditions": ["StringEquals aws:RequestedRegion=eu-west-1"],
    },
    "S3WriteBucketTagOwner": {
        "arn": [ARN],
        "service": "s3",
        "access_level": "Write",
        "arn_format": "arn:${Partition}:s3:::${BucketName}",
        "actions": ["s3:PutObjectTagging"],
        "conditions": ["StringEquals aws:ResourceTag/Owner=alice"],
    },
}
policy_min = sg2.get_rendered_policy(minimize=0)
print("rendered policy (minimize=0):")
print(json.dumps(policy_min, indent=2))
print("number of statements:", len(policy_min["Statement"]))
