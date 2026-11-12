#!/usr/bin/env python

import json

from policy_sentry.querying.actions import get_missing_required_resource_types

if __name__ == "__main__":
    # The requester only supplied the instance ARN, but ec2:RunInstances also
    # requires an image, network interface, security group, and subnet.
    output = get_missing_required_resource_types(
        ["ec2:RunInstances"],
        ["arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0"],
    )
    print(json.dumps(output, indent=4))
