"""End-to-end dependency review tests using the local action directory sample."""

from __future__ import annotations

import json
from typing import Any

from policy_sentry.writing.sid_group import SidGroup

WORKLOAD_ARN = "arn:aws:depsvc:us-east-1:123456789012:workload/w-1"
CONNECTOR_ARN = "arn:aws:othersvc:us-east-1:123456789012:connector/c-1"


def _statements(sid_group: SidGroup) -> list[dict[str, Any]]:
    return sid_group.get_rendered_policy()["Statement"]


def test_review_report_carries_full_paths(sample_action_directory: dict[str, Any]) -> None:
    sid_group = SidGroup()
    sid_group.add_by_list_of_actions(["depsvc:RootAction"])
    review = sid_group.get_dependency_review()

    by_action = {entry["action"]: entry for entry in review["dependencies"]}
    assert by_action["depsvc:LevelTwo"]["paths"] == [
        ["depsvc:RootAction", "depsvc:LevelOne", "depsvc:LevelTwo"]
    ]
    assert by_action["othersvc:DifferentArnAction"]["status"] == "needs_resource_scope"
    assert review["pending_resource_scopes"] == ["othersvc:differentarnaction"]


def test_unscoped_dependency_is_never_rendered_on_wildcard(
    sample_action_directory: dict[str, Any],
) -> None:
    sid_group = SidGroup()
    sid_group.add_by_list_of_actions(["depsvc:RootAction"])
    rendered = json.dumps(_statements(sid_group))

    assert "othersvc:DifferentArnAction" not in rendered
    # No statement may carry Resource "*" while the dependency is pending.
    for statement in _statements(sid_group):
        if "othersvc" in json.dumps(statement["Action"]):
            assert statement["Resource"] != ["*"]


def test_wildcard_only_dependency_still_renders(sample_action_directory: dict[str, Any]) -> None:
    sid_group = SidGroup()
    sid_group.add_by_list_of_actions(["depsvc:NeedsWildcard"])
    statements = _statements(sid_group)

    wildcard = next(stmt for stmt in statements if "depsvc:WildcardOnlyAction" in stmt["Action"])
    assert wildcard["Resource"] == ["*"]
    assert sid_group.get_dependency_review()["pending_resource_scopes"] == []


def test_supplying_scope_renders_pending_dependency(sample_action_directory: dict[str, Any]) -> None:
    sid_group = SidGroup()
    sid_group.add_by_list_of_actions(["depsvc:RootAction"])
    assert "othersvc:differentarnaction" in sid_group.get_dependency_review()["pending_resource_scopes"]

    sid_group.add_dependency_resource_scope("othersvc:DifferentArnAction", CONNECTOR_ARN)
    statements = _statements(sid_group)
    rendered = next(stmt for stmt in statements if "othersvc:DifferentArnAction" in stmt["Action"])
    assert rendered["Resource"] == [CONNECTOR_ARN]
    assert sid_group.get_dependency_review()["pending_resource_scopes"] == []


def test_same_resource_dependency_uses_requested_arn(sample_action_directory: dict[str, Any]) -> None:
    sid_group = SidGroup()
    sid_group.add_by_arn_and_access_level([WORKLOAD_ARN], "Write")
    statements = _statements(sid_group)

    workload_statement = next(stmt for stmt in statements if "depsvc:SharedAction" in stmt["Action"])
    assert workload_statement["Resource"] == [WORKLOAD_ARN]
    # The different-ARN dependency stays pending instead of joining the workload statement.
    assert "othersvc:DifferentArnAction" not in workload_statement["Action"]
    assert "othersvc:differentarnaction" in sid_group.get_dependency_review()["pending_resource_scopes"]


def test_missing_metadata_dependency_is_held(sample_action_directory: dict[str, Any]) -> None:
    sid_group = SidGroup()
    sid_group.add_by_list_of_actions(["depsvc:BrokenMetadata"])
    rendered = json.dumps(_statements(sid_group))

    assert "ghostsvc:NotInDirectory" not in rendered
    review = sid_group.get_dependency_review()
    assert review["pending_resource_scopes"] == ["ghostsvc:notindirectory"]
    unknown = next(entry for entry in review["dependencies"] if entry["action"] == "ghostsvc:NotInDirectory")
    assert unknown["status"] == "missing_metadata"
    assert unknown["paths"] == [["depsvc:BrokenMetadata", "ghostsvc:NotInDirectory"]]


def test_cycle_does_not_break_policy_generation(sample_action_directory: dict[str, Any]) -> None:
    sid_group = SidGroup()
    sid_group.add_by_list_of_actions(["depsvc:CycleA"])
    review = sid_group.get_dependency_review()

    assert review["cycles"] == [["depsvc:CycleA", "depsvc:CycleB", "depsvc:CycleA"]]
    rendered = json.dumps(_statements(sid_group))
    assert "depsvc:CycleB" in rendered
    assert "depsvc:CycleA" in rendered


def test_scope_validation_rejects_wrong_resource_type(sample_action_directory: dict[str, Any]) -> None:
    sid_group = SidGroup()
    sid_group.add_by_list_of_actions(["depsvc:RootAction"])
    try:
        sid_group.add_dependency_resource_scope("othersvc:DifferentArnAction", WORKLOAD_ARN)
    except Exception as exc:  # noqa: BLE001
        assert "does not match" in str(exc)
    else:
        raise AssertionError("Expected a resource type mismatch error")


def test_multi_level_same_arn_chain_renders_against_requested_arn(
    sample_action_directory: dict[str, Any],
) -> None:
    sid_group = SidGroup()
    sid_group.add_by_arn_and_access_level([WORKLOAD_ARN], "Write")
    statements = _statements(sid_group)
    workload = next(stmt for stmt in statements if stmt["Sid"] == "DepsvcWriteWorkload")

    # The full chain shares the workload ARN type and stays on the requested ARN.
    for action in ("depsvc:LevelOne", "depsvc:LevelTwo", "depsvc:SharedAction"):
        assert action in workload["Action"]
    assert workload["Resource"] == [WORKLOAD_ARN]
    # Cross-service and missing-metadata dependencies cannot share the workload
    # ARN, so they stay pending rather than being widened to "*".
    pending = sid_group.get_dependency_review()["pending_resource_scopes"]
    assert "othersvc:differentarnaction" in pending
    assert "ghostsvc:notindirectory" in pending


def test_shared_dependency_is_rendered_once(sample_action_directory: dict[str, Any]) -> None:
    sid_group = SidGroup()
    sid_group.add_by_list_of_actions(["depsvc:RootAction", "depsvc:SecondRoot"])
    rendered = json.dumps(_statements(sid_group))
    assert rendered.count("depsvc:SharedAction") == 1
