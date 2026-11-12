#!/usr/bin/env python
"""
Conservative wildcard compression demo.

Policy Sentry normally compresses approved actions into prefix wildcards
(such as ``foo:getu*``). If AWS later ships a new action sharing that prefix,
the already-generated policy silently grants it. The ``conservative`` option
only emits a wildcard when its meaning is fixed against the current catalog;
every other prefix stays an explicit action, and the rejected prefixes are
reported with the reason.

This demo uses two tiny synthetic action catalogs so it needs no AWS database:

* ``CATALOG_V1``: the actions the generator knows today.
* ``CATALOG_V2``: the same catalog after AWS adds same-prefix actions.
"""

from __future__ import annotations

from policy_sentry.writing.minimize import (
    get_last_conservative_report,
    minimize_statement_actions,
)

CATALOG_V1 = {
    "foo:getuser",
    "foo:getrole",
    "foo:putrecord",
    "bar:listthings",
    "bar:listwidgets",
    "bar:deletewidget",
}
# AWS ships two new actions, one per service, sharing existing prefixes.
CATALOG_V2 = CATALOG_V1 | {"foo:getaccount", "bar:listaccounts"}


def _granted_set(output: list[str], catalog: set[str]) -> set[str]:
    """The concrete catalog actions an Allow statement actually grants."""
    granted: set[str] = set()
    for token in output:
        if token.endswith("*"):
            prefix = token[:-1]
            granted.update(action for action in catalog if action.startswith(prefix))
        else:
            granted.add(token)
    return granted


def _show(title: str, desired: list[str], catalog: set[str]) -> None:
    normal = minimize_statement_actions(desired, catalog)
    conservative = minimize_statement_actions(desired, catalog, conservative=True)
    print(f"\n=== {title} ===")
    print(f"approved input : {desired}")
    print(f"normal tokens  : {normal}")
    print(f"normal grants  : {sorted(_granted_set(normal, catalog))}")
    print(f"conservative   : {conservative}")
    print(f"conservative grants: {sorted(_granted_set(conservative, catalog))}")
    report = get_last_conservative_report()
    if report:
        print("prefixes kept explicit (would widen permissions):")
        for wildcard, detail in sorted(report.items()):
            blocked = ", ".join(detail["blocked_by"]) if detail["blocked_by"] else "future same-prefix AWS actions"
            print(f"  - {wildcard:<14} reason={detail['reason']:<28} blocked_by=[{blocked}]")
    else:
        print("prefixes kept explicit: none (service-wide wildcard covers a fixed set)")


if __name__ == "__main__":
    # 1. Two services, mixed case input, on the catalog as it exists today.
    _show("catalog v1: open prefix compressed today", ["Foo:GetUser", "Foo:GetRole"], CATALOG_V1)

    # 2. Same approval after AWS adds foo:GetAccount under the same get* prefix.
    _show("catalog v2: AWS adds same-prefix foo:GetAccount", ["Foo:GetUser", "Foo:GetRole"], CATALOG_V2)

    # 3. Explicit exclusion: only GetUser is approved; GetRole/GetAccount are not.
    _show("explicit exclusion (only GetUser approved)", ["foo:GetUser"], CATALOG_V2)

    # 4. Mixed services in a single statement.
    _show("mixed services, catalog v2", ["Foo:GetUser", "bar:ListThings"], CATALOG_V2)

    # 5. Approving the whole service keeps the one fixed-meaning wildcard: foo:*.
    whole_foo = sorted(action for action in CATALOG_V2 if action.startswith("foo:"))
    _show("whole foo service approved", whole_foo, CATALOG_V2)
