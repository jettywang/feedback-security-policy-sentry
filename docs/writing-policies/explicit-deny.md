Explicit Deny
=============

- **TLDR**: Set the top-level `effect: Deny` key in a CRUD or Actions template to render every generated statement with `"Effect": "Deny"` instead of the default `"Allow"`.

There is one `effect` per template, applied to **all** statements generated from that file. Policy Sentry does not mix Allow and Deny inside a single render; to build a policy that contains both, render two templates (one Allow, one Deny) and combine their `Statement` arrays yourself.

Input template
--------------

```yaml
mode: crud
name: ParameterDeny
effect: Deny            # <-- one effect for the whole template
read:
- arn:aws:ssm:us-east-1:123456789012:parameter/myparameter
write:
- arn:aws:ssm:us-east-1:123456789012:parameter/myparameter
```

Output
------

Each generated statement keeps the same `Sid`, `Action`, and `Resource` it would have with the default effect; only `Effect` flips to `Deny`.

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "SsmReadParameter",
            "Effect": "Deny",
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
            "Effect": "Deny",
            "Action": [
                "ssm:DeleteParameter",
                "ssm:DeleteParameters",
                "ssm:LabelParameterVersion",
                "ssm:PutParameter"
            ],
            "Resource": [
                "arn:aws:ssm:us-east-1:123456789012:parameter/myparameter"
            ]
        }
    ]
}
```

Tracing each statement back to the template
--------------------------------------------

The `Sid` namespace encodes where a statement came from, so output is traceable to a single template field:

- `SsmReadParameter` <- the `read` list, resource type `parameter`, service `ssm`.
- `SsmWriteParameter` <- the `write` list against the same ARN.
- `MultMultNone` <- dependent actions and wildcard-only actions that only support `Resource: "*"`.

An identical template rendered without `effect` (or with `effect: Allow`) produces the same statements with `"Effect": "Allow"`. The action and resource lists are byte-for-byte equivalent; only the `Effect` value changes.

Action filtering is NOT an explicit Deny
----------------------------------------

These are two different mechanisms and must not be confused:

- **`exclude-actions` (filtering)** removes matching actions from the generated policy entirely. The action appears in **no** statement, neither Allow nor Deny. It shrinks what the policy talks about; it does not create a guardrail.
- **`effect: Deny` (explicit deny)** keeps the same actions and resources but marks the statement `Deny`. Because a Deny overrides any Allow in IAM evaluation, this actively blocks the action even if another policy grants it.

Use `exclude-actions` to trim an Allow policy to least privilege. Use `effect: Deny` to build an explicit guardrail (for example, blocking a sensitive action regardless of broader grants elsewhere).

Same action and resource on both Allow and Deny
-----------------------------------------------

Render the action twice - once with each effect - and concatenate the statement arrays. The two renders can produce statements that share a `Sid` (the Sid derives from service/access-level/resource, not from the effect). That is valid IAM: the statements remain distinct because their `Effect` differs, and the Deny statement is preserved in the final JSON. At evaluation time IAM resolves the overlap in favor of `Deny`, so the restriction is not lost.

```json
{
    "Sid": "S3WriteObject",
    "Effect": "Allow",
    "Action": ["s3:PutObject"],
    "Resource": ["arn:${Partition}:s3:::${BucketName}/${ObjectName}"]
}
```

paired with:

```json
{
    "Sid": "S3WriteObject",
    "Effect": "Deny",
    "Action": ["s3:PutObject"],
    "Resource": ["arn:${Partition}:s3:::${BucketName}/${ObjectName}"]
}
```

A replayable, annotated version of this comparison lives at
`examples/library-usage/writing/explicit_deny_replay.py`. Run it with:

```bash
python examples/library-usage/writing/explicit_deny_replay.py
```

Conditions
----------

Policy Sentry does not currently emit a `Condition` block (the IAM database stores condition keys, but the writer leaves conditions empty). It therefore cannot generate two same-`Sid` statements that differ only by condition. To scope a Deny by condition, add the `Condition` block to the rendered JSON outside Policy Sentry.

Analysis note
-------------

The policy analysis utilities only evaluate `Allow` statements; a pure Deny policy reports zero granted actions. This is intentional - a Deny is a restriction, never a grant.
