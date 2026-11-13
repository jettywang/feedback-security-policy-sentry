#!/usr/bin/env python
"""
Replayable sample: action filtering vs. an explicit Deny.

Run it with no arguments and no network access:

    python examples/library-usage/writing/explicit_deny_replay.py

The same template is rendered twice - once with the default ``Allow`` effect
and once with ``effect: Deny``. Every generated statement is annotated below
with the template field that produced it, so a maintainer can trace each
``Sid``/``Action``/``Resource`` triple back to its source.
"""

from __future__ import annotations

import copy
import json

from policy_sentry.command.write_policy import write_policy_with_template
from policy_sentry.util.policy_files import get_actions_from_policy

# One CRUD template. Notice there is no per-statement effect: the single
# top-level ``effect`` key applies to every statement generated from this file.
#   read  -> SsmReadParameter      (all Read actions valid for the parameter ARN)
#   write -> SsmWriteParameter     (all Write actions valid for the parameter ARN)
# exclude-actions -> action FILTERING; the action is removed from the output,
#                    it is never turned into a Deny.
TEMPLATE = {
    "mode": "crud",
    "name": "ParameterAccess",
    # "effect": "Deny",   # uncomment to render the explicit-Deny version
    "read": ["arn:aws:ssm:us-east-1:123456789012:parameter/myparameter"],
    "write": ["arn:aws:ssm:us-east-1:123456789012:parameter/myparameter"],
    "exclude-actions": ["ssm:GetParameters"],
}


def render(effect: str) -> dict:
    cfg = copy.deepcopy(TEMPLATE)
    if effect == "Deny":
        cfg["effect"] = "Deny"
    return write_policy_with_template(cfg)


def explain(policy: dict, source_field: dict[str, str]) -> None:
    for statement in policy["Statement"]:
        sid = statement["Sid"]
        origin = source_field.get(sid, "derived (dependent/wildcard action)")
        print(
            f"  Sid={sid:<20} Effect={statement['Effect']:<5} "
            f"Resource={statement['Resource'][0]} <- template: {origin}"
        )


def main() -> None:
    allow_policy = render("Allow")
    deny_policy = render("Deny")

    print("== Allow render (effect omitted, defaults to Allow) ==")
    explain(allow_policy, SOURCE_FIELD)
    print("\n== Deny render (effect: Deny) ==")
    explain(deny_policy, SOURCE_FIELD)

    # The two renders share identical Sid/Action/Resource structure; only Effect differs.
    allow_keys = [(s["Sid"], tuple(s["Action"]), tuple(s["Resource"])) for s in allow_policy["Statement"]]
    deny_keys = [(s["Sid"], tuple(s["Action"]), tuple(s["Resource"])) for s in deny_policy["Statement"]]
    print("\nStructure identical, only Effect flips:", allow_keys == deny_keys)
    print("Deny render is fully Deny:", all(s["Effect"] == "Deny" for s in deny_policy["Statement"]))

    # Action FILTERING vs. explicit DENY:
    #  - exclude-actions simply deletes ssm:GetParameters from the generated statements.
    #  - effect: Deny keeps the actions but marks them Deny; AWS then overrides any Allow.
    all_actions = {a for s in allow_policy["Statement"] for a in s["Action"]}
    print("exclude-actions removed ssm:GetParameters:", "ssm:GetParameters" not in all_actions)

    # The analyzer only evaluates Allow statements, so a pure Deny policy grants nothing.
    print("Actions an analyzer sees in the Deny policy:", get_actions_from_policy(deny_policy))

    # Same action + resource on an Allow and a Deny at once: render both and combine the
    # statement arrays. The Deny statement is preserved (AWS resolves the overlap as Deny).
    allow_obj = write_policy_with_template(
        {"mode": "actions", "name": "A", "actions": ["s3:PutObject"]}
    )
    deny_obj = write_policy_with_template(
        {"mode": "actions", "name": "D", "effect": "Deny", "actions": ["s3:PutObject"]}
    )
    combined = allow_obj["Statement"] + deny_obj["Statement"]
    print("\n== Combined Allow + explicit Deny for s3:PutObject ==")
    print(json.dumps({"Version": "2012-10-17", "Statement": combined}, indent=2))
    print(
        "Both effects retained:",
        {s["Effect"] for s in combined} == {"Allow", "Deny"},
    )


# Maps each generated Sid back to the template field that requested it.
SOURCE_FIELD = {
    "SsmReadParameter": "read",
    "SsmWriteParameter": "write",
    "MultMultNone": "dependent action added automatically (Resource='*')",
}


if __name__ == "__main__":
    main()
