# Dependency Tree

Some AWS actions only work when the caller also holds one or more additional
actions. For example, `ec2:AssociateIamInstanceProfile` cannot pass an instance
profile without `iam:PassRole`. Policy Sentry walks the **full transitive
dependency graph** for the actions you request instead of only looking at the
single level of dependencies stored next to each action.

## Reviewing dependencies from the CLI

```bash
policy_sentry query dependency-tree \
  --action ec2:AssociateIamInstanceProfile
```

Each dependency is reported with:

- `paths`: every route from one of your requested actions to the dependency,
  so multi-level chains and shared dependencies stay auditable;
- `status`: one of
  - `scoped` — the dependency accepts the same resource ARN type as your
    request and can be rendered against that ARN;
  - `wildcard_only` — AWS defines no resource-level scope for the action, so
    `Resource: "*"` is the only valid form;
  - `needs_resource_scope` — the dependency requires a different ARN type and
    you must supply the resource scope;
  - `missing_metadata` — the action is referenced but absent from the local
    action directory, so no scope can be derived automatically;
- `resource_arn_formats`: the ARN formats the dependency can be restricted to;
- `cycles`: dependency paths that revisit an action; traversal terminates and
  the loop is reported rather than followed forever.

## Why some dependencies are not rendered automatically

When writing a policy, Policy Sentry will **never** emit an `Allow` on
`Resource: "*"` for a dependency that actually supports resource-level
scoping. Those dependencies are held on a pending list until you call
`add_dependency_resource_scope()` with a concrete ARN. Only genuinely
wildcard-only actions (status `wildcard_only`) are rendered under `*`.

```python
from policy_sentry.writing.sid_group import SidGroup

sid_group = SidGroup()
sid_group.add_by_list_of_actions(["ec2:AssociateIamInstanceProfile"])

# iam:PassRole is pending — it targets an IAM role ARN, not the EC2 instance
print(sid_group.get_dependency_review()["pending_resource_scopes"])

sid_group.add_dependency_resource_scope(
    "iam:PassRole",
    "arn:aws:iam::123456789012:role/EC2WebServerRole",
)
policy = sid_group.get_rendered_policy()
```

Supplying an ARN that does not match any of the action's supported ARN formats
raises an error, so a typo cannot silently widen the policy.
