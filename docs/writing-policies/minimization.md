Character Minimization
======================

IAM Policies have character limits, which apply to individual policies, and there are also limits on the total aggregate policy sizes. As such, it is not possible to use exhaustive list of explicit IAM actions. To have granular control of specific IAM policies, we must use wildcards on IAM Actions, only in a programmatic manner.

This is typically performed by humans by reducing policies to `s3:Get*`, `ec2:Describe*`, and other approaches of the sort.

We borrow some strategies from Netflix's PolicyUniverse[1](https://github.com/Netflix-Skunkworks/policyuniverse/) for this. Let's see it in action, using the same template as the CRUD example.

## Input

* Use this as your `crud.yml` file:

```yaml
mode: crud
name: ''
read:
- 'arn:aws:ssm:us-east-1:123456789012:parameter/myparameter'
write:
- 'arn:aws:ssm:us-east-1:123456789012:parameter/myparameter'
list:
- 'arn:aws:ssm:us-east-1:123456789012:parameter/myparameter'
tagging:
- 'arn:aws:secretsmanager:us-east-1:123456789012:secret:mysecret'
permissions-management:
- 'arn:aws:secretsmanager:us-east-1:123456789012:secret:mysecret'
wildcard-only:
  single-actions: # standalone actions
  - ''
  # Service-wide - like 's3' or 'ec2'
  service-read:
  - ''
  service-write:
  - ''
  service-list:
  - ''
  service-tagging:
  - ''
  service-permissions-management:
  - ''
```


## Output - with character minimization

* To write the policy **with** Character minimization run this command:

```bash
policy_sentry write-policy --input-file crud.yml --minimize 0
```

The output has **500 characters** (not counting whitespaces) and will look like this:

```json
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
                "ssm:putp*",
                "ssm:listt*"
            ],
            "Resource": [
                "arn:aws:ssm:us-east-1:123456789012:parameter/myparameter"
            ]
        },
        {
            "Sid": "SecretsmanagerMultSecretmysecret",
            "Effect": "Allow",
            "Action": [
                "secretsmanager:t*",
                "secretsmanager:un*",
                "secretsmanager:deleter*",
                "secretsmanager:putr*",
                "secretsmanager:v*"
            ],
            "Resource": [
                "arn:aws:secretsmanager:us-east-1:123456789012:secret:mysecret"
            ]
        }
    ]
}
```

## Output - without character minimization


* To write the policy **without** Character minimization run this command:

```bash
policy_sentry write-policy --input-file crud.yml
```

* The output has **935 characters** and will look like this:

<details open>
<summary>policy_sentry query action-table --service all</summary>
<br>
<pre>
<code>
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "SsmReadParameter",
            "Effect": "Allow",
            "Action": [
                "ssm:GetParameter",
                "ssm:GetParameterHistory",
                "ssm:GetParameters",
                "ssm:GetParametersByPath",
                "ssm:ListTagsForResource"
            ],
            "Resource": [
                "arn:aws:ssm:us-east-1:123456789012:parameter/myparameter"
            ]
        },
        {
            "Sid": "SsmWriteParameter",
            "Effect": "Allow",
            "Action": [
                "ssm:DeleteParameter",
                "ssm:DeleteParameters",
                "ssm:LabelParameterVersion",
                "ssm:PutParameter"
            ],
            "Resource": [
                "arn:aws:ssm:us-east-1:123456789012:parameter/myparameter"
            ]
        },
        {
            "Sid": "SecretsmanagerPermissionsmanagementSecret",
            "Effect": "Allow",
            "Action": [
                "secretsmanager:DeleteResourcePolicy",
                "secretsmanager:PutResourcePolicy"
            ],
            "Resource": [
                "arn:aws:secretsmanager:us-east-1:123456789012:secret:mysecret"
            ]
        },
        {
            "Sid": "SecretsmanagerTaggingSecret",
            "Effect": "Allow",
            "Action": [
                "secretsmanager:TagResource",
                "secretsmanager:UntagResource"
            ],
            "Resource": [
                "arn:aws:secretsmanager:us-east-1:123456789012:secret:mysecret"
            ]
        }
    ]
}
</code>
</pre>
</details>


## Conclusion

As you can see, we used the minimization command to shave off 200 characters from the resulting IAM policy.

This becomes more and more useful as the amount of ARNs used in the policy add up.

## Conservative compression

A prefix wildcard such as `ssm:getpar*` is safe against the action catalog at
generation time, but it is an *open* prefix: if AWS later releases a new action
sharing that prefix (for example `ssm:GetParameterQuota`), an already deployed
policy grants it without anyone changing the policy. The granted action set
therefore has no fixed meaning over time.

Pass `--conservative` (or `conservative=True` when using Policy Sentry as a
library) to bind every wildcard to a fixed meaning against the current catalog:

```bash
policy_sentry write-policy --input-file crud.yml --minimize 0 --conservative
```

Under conservative compression:

* Narrow prefix wildcards such as `ssm:getpar*` are kept as explicit action
  names, because they are *open* prefixes and a future same-prefix AWS action
  would widen the grant. The only wildcard retained is the service-wide one
  (`ssm:*`), and only when **every** catalog action in that service is
  approved, which is already an explicit intent.
* Explicitly excluded actions are never hidden behind a wildcard, because the
  unfiltered catalog is used when deciding whether a prefix is safe.
* Every prefix that is kept explicit is recorded. Library callers can read it
  from `SidGroup.conservative_report`, and the lower-level
  `policy_sentry.writing.minimize.get_last_conservative_report()` exposes the
  same data. Each entry gives a `reason` and the concrete `blocked_by` actions:
  - `unapproved_actions_matched`: the wildcard would also grant known actions
    outside the approved set (including explicit exclusions).
  - `open_prefix_future_actions`: every current match is approved, but a future
    same-prefix AWS action could widen the grant.

A runnable, catalog-free walkthrough of both rejection reasons (including a
simulated AWS action addition, explicit exclusions, mixed-case input and mixed
services) lives at
`examples/library-usage/writing/conservative_minimization_demo.py`.
