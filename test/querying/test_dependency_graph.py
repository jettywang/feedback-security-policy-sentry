"""Tests for transitive dependency graph analysis using the local action directory sample."""

from __future__ import annotations

from typing import Any

import pytest

from policy_sentry.querying import dependency_graph as dg


def _by_action(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {entry["action"]: entry for entry in report["dependencies"]}


def test_multi_level_dependency_chain_is_resolved(sample_action_directory: dict[str, Any]) -> None:
    report = dg.build_dependency_graph(["depsvc:RootAction"])
    entries = _by_action(report)

    assert list(entries) == [
        "depsvc:LevelOne",
        "depsvc:LevelTwo",
        "depsvc:SharedAction",
        "othersvc:DifferentArnAction",
    ]
    assert entries["depsvc:LevelOne"]["paths"] == [
        ["depsvc:RootAction", "depsvc:LevelOne"]
    ]
    assert entries["depsvc:LevelTwo"]["paths"] == [
        ["depsvc:RootAction", "depsvc:LevelOne", "depsvc:LevelTwo"]
    ]
    assert entries["depsvc:LevelTwo"]["direct_parents"] == ["depsvc:levelone"]


def test_shared_dependency_reports_every_path(sample_action_directory: dict[str, Any]) -> None:
    report = dg.build_dependency_graph(["depsvc:RootAction", "depsvc:SecondRoot"])
    shared = _by_action(report)["depsvc:SharedAction"]

    # SharedAction is reachable through two branches of the chain plus a second root.
    assert shared["paths"] == [
        ["depsvc:RootAction", "depsvc:LevelOne", "depsvc:LevelTwo", "depsvc:SharedAction"],
        ["depsvc:RootAction", "depsvc:LevelOne", "depsvc:SharedAction"],
        ["depsvc:SecondRoot", "depsvc:SharedAction"],
    ]
    assert shared["direct_parents"] == ["depsvc:levelone", "depsvc:leveltwo", "depsvc:secondroot"]
    # One entry only: shared dependencies are de-duplicated.
    assert sum(1 for entry in report["dependencies"] if entry["action"] == "depsvc:SharedAction") == 1


def test_dependency_cycle_terminates_and_is_reported(sample_action_directory: dict[str, Any]) -> None:
    report = dg.build_dependency_graph(["depsvc:CycleA"])
    entries = _by_action(report)

    assert set(entries) == {"depsvc:CycleB"}
    assert report["cycles"] == [["depsvc:CycleA", "depsvc:CycleB", "depsvc:CycleA"]]
    # The back edge stays visible on CycleB's paths without exploding traversal.
    assert entries["depsvc:CycleB"]["paths"] == [["depsvc:CycleA", "depsvc:CycleB"]]


def test_self_loop_is_reported_as_a_cycle(sample_action_directory: dict[str, Any]) -> None:
    report = dg.build_dependency_graph(["depsvc:SelfLoop"])

    assert report["dependencies"] == []
    assert report["cycles"] == [["depsvc:SelfLoop", "depsvc:SelfLoop"]]


def test_missing_metadata_is_surfaced_not_dropped(sample_action_directory: dict[str, Any]) -> None:
    report = dg.build_dependency_graph(["depsvc:BrokenMetadata"])
    entries = _by_action(report)

    assert "ghostsvc:NotInDirectory" in entries
    unknown = entries["ghostsvc:NotInDirectory"]
    assert unknown["status"] == dg.STATUS_MISSING_METADATA
    assert unknown["resource_arn_formats"] == []
    assert unknown["paths"] == [["depsvc:BrokenMetadata", "ghostsvc:NotInDirectory"]]
    assert report["missing_metadata"] == ["ghostsvc:NotInDirectory"]
    assert dg.get_dependencies_requiring_resource_scope(["depsvc:BrokenMetadata"])[0]["action"] == (
        "ghostsvc:NotInDirectory"
    )


def test_dependency_requiring_different_arn_needs_scope(sample_action_directory: dict[str, Any]) -> None:
    report = dg.build_dependency_graph(["depsvc:RootAction"])
    different_arn = _by_action(report)["othersvc:DifferentArnAction"]

    assert different_arn["status"] == dg.STATUS_NEEDS_RESOURCE_SCOPE
    assert different_arn["resource_arn_formats"] == [
        "arn:${Partition}:othersvc:${Region}:${Account}:connector/${ConnectorId}"
    ]
    assert different_arn["paths"] == [
        [
            "depsvc:RootAction",
            "depsvc:LevelOne",
            "depsvc:LevelTwo",
            "othersvc:DifferentArnAction",
        ]
    ]


def test_same_arn_dependency_is_scoped_and_wildcard_only_is_distinct(
    sample_action_directory: dict[str, Any],
) -> None:
    chain_report = dg.build_dependency_graph(["depsvc:RootAction"])
    chain_entries = _by_action(chain_report)
    assert chain_entries["depsvc:SharedAction"]["status"] == dg.STATUS_SCOPED

    wildcard_report = dg.build_dependency_graph(["depsvc:NeedsWildcard"])
    wildcard_entry = _by_action(wildcard_report)["depsvc:WildcardOnlyAction"]
    assert wildcard_entry["status"] == dg.STATUS_WILDCARD_ONLY
    assert wildcard_entry["resource_arn_formats"] == ["*"]


def test_transitive_helper_includes_grandchildren(sample_action_directory: dict[str, Any]) -> None:
    assert dg.get_transitive_dependent_actions(["depsvc:RootAction"]) == [
        "depsvc:LevelOne",
        "depsvc:LevelTwo",
        "depsvc:SharedAction",
        "othersvc:DifferentArnAction",
    ]


def test_unknown_requested_action_is_flagged(sample_action_directory: dict[str, Any]) -> None:
    report = dg.build_dependency_graph(["depsvc:DoesNotExist"])

    assert report["requested_actions"][0]["status"] == dg.STATUS_MISSING_METADATA
    assert report["dependencies"] == []


def test_inputs_are_case_insensitive(sample_action_directory: dict[str, Any]) -> None:
    report = dg.build_dependency_graph(["DEPSVC:rootaction"])
    assert _by_action(report)["depsvc:LevelOne"]["paths"][0][0] == "depsvc:RootAction"


def test_malformed_action_references_are_skipped(sample_action_directory: dict[str, Any]) -> None:
    report = dg.build_dependency_graph(["not-an-action-reference"])
    assert report["requested_actions"] == []
    assert report["dependencies"] == []


@pytest.mark.parametrize(
    ("action", "expected_status"),
    [
        ("depsvc:RootAction", dg.STATUS_REQUESTED),
        ("depsvc:BrokenMetadata", dg.STATUS_REQUESTED),
    ],
)
def test_requested_action_metadata(
    sample_action_directory: dict[str, Any], action: str, expected_status: str
) -> None:
    report = dg.build_dependency_graph([action])
    assert report["requested_actions"][0]["action"] == action
    assert report["requested_actions"][0]["status"] == expected_status
