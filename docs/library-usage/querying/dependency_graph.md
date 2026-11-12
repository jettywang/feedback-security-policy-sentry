# querying.dependency_graph

Transitive dependency analysis for IAM actions. Unlike
`querying.actions.get_dependent_actions`, which returns only the direct
dependencies, `build_dependency_graph` resolves the whole graph while handling
multi-level chains, shared dependencies, cycles and missing metadata.

## build_dependency_graph(requested_actions)

Returns a review report containing the requested actions, every transitive
dependency, the paths reaching each dependency, detected cycles, and references
that could not be resolved against the local action directory.

```python
from policy_sentry.querying.dependency_graph import build_dependency_graph

report = build_dependency_graph(["ec2:AssociateIamInstanceProfile"])
```

Dependency `status` values:

- `scoped`: shares a resource ARN format with the request;
- `wildcard_only`: only valid on `Resource: "*"`;
- `needs_resource_scope`: requires a different ARN type;
- `missing_metadata`: unknown to the local action directory.

## Helper functions

- `get_transitive_dependent_actions(actions)` — sorted list of every distinct
  transitive dependency action.
- `get_dependencies_requiring_resource_scope(actions)` — only the entries whose
  status is `needs_resource_scope` or `missing_metadata`.

The module is read-only: it never generates policy statements. Pair it with
`SidGroup.review_dependent_actions()` and
`SidGroup.add_dependency_resource_scope()` to turn the report into a
least-privilege policy.
