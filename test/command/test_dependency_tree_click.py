"""Click tests for the dependency-tree query subcommand."""

from __future__ import annotations

import json
from typing import Any

from click.testing import CliRunner

from policy_sentry.command.query import query


def test_dependency_tree_click_real_datastore() -> None:
    runner = CliRunner()
    result = runner.invoke(
        query,
        ["dependency-tree", "--action", "ec2:AssociateIamInstanceProfile"],
    )
    assert result.exit_code == 0
    output = json.loads(result.output)
    dependency = next(item for item in output["dependencies"] if item["action"] == "iam:PassRole")
    assert dependency["status"] == "needs_resource_scope"
    assert dependency["paths"] == [["ec2:AssociateIamInstanceProfile", "iam:PassRole"]]


def test_dependency_tree_click_sample_directory(sample_action_directory: dict[str, Any]) -> None:
    runner = CliRunner()
    result = runner.invoke(
        query,
        [
            "dependency-tree",
            "--action",
            "depsvc:RootAction",
            "--action",
            "depsvc:SecondRoot",
        ],
    )
    assert result.exit_code == 0
    output = json.loads(result.output)
    by_action = {item["action"]: item for item in output["dependencies"]}

    assert by_action["depsvc:LevelTwo"]["paths"] == [
        ["depsvc:RootAction", "depsvc:LevelOne", "depsvc:LevelTwo"]
    ]
    assert by_action["othersvc:DifferentArnAction"]["status"] == "needs_resource_scope"
    assert len(by_action["depsvc:SharedAction"]["paths"]) == 3


def test_dependency_tree_click_yaml(sample_action_directory: dict[str, Any]) -> None:
    runner = CliRunner()
    result = runner.invoke(
        query,
        ["dependency-tree", "--action", "depsvc:CycleA", "--fmt", "yaml"],
    )
    assert result.exit_code == 0
    assert "dependencies:" in result.output
    assert "CycleB" in result.output
