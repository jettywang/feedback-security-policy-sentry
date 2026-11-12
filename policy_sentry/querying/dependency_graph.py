"""
Transitive dependency analysis for IAM actions.

AWS actions sometimes require additional actions to work at runtime (for example,
``ec2:AssociateIamInstanceProfile`` requires ``iam:PassRole``). The upstream
``get_dependent_actions`` helper only returns the direct, single-level
dependencies. This module walks the full dependency graph instead so that:

* multi-level dependency chains are resolved recursively;
* actions shared by several parents are only reported once, with every path
  that reaches them;
* dependency cycles terminate instead of looping forever;
* actions missing from the local action directory are surfaced rather than
  silently dropped;
* dependencies that require a different resource ARN than the original request
  are flagged so a user can supply a resource scope.

The module never generates policy statements itself. It returns a reviewable
report. Callers decide which entries are safe to render automatically.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from policy_sentry.shared.iam_data import get_service_prefix_data

if TYPE_CHECKING:
    from collections.abc import Iterable

logger = logging.getLogger(__name__)

# Status values used in the review report.
STATUS_SCOPED = "scoped"
STATUS_WILDCARD_ONLY = "wildcard_only"
STATUS_NEEDS_RESOURCE_SCOPE = "needs_resource_scope"
STATUS_MISSING_METADATA = "missing_metadata"
STATUS_REQUESTED = "requested"


def _service_data(service_prefix: str) -> dict[str, Any] | None:
    """Look up service metadata case-insensitively, mirroring action-name handling."""
    service_data = get_service_prefix_data(service_prefix)
    if service_data:
        return service_data
    return get_service_prefix_data(service_prefix.lower())


def _normalize_action(action: str) -> str:
    """Return the canonical ``Service:Action`` spelling stored in the directory."""
    service_prefix, action_name = action.split(":", 1)
    service_data = _service_data(service_prefix)
    canonical_name = service_data["privileges_lower_name"].get(action_name.lower()) if service_data else None
    if canonical_name is None:
        return action
    return f"{service_data['prefix']}:{canonical_name}"


def _action_entry(action: str) -> dict[str, Any] | None:
    """Return the raw directory entry for an action, or ``None`` if metadata is missing."""
    try:
        service_prefix, action_name = action.split(":", 1)
    except ValueError:
        logger.debug("Skipping malformed action reference: %r", action)
        return None
    service_data = _service_data(service_prefix)
    if not service_data:
        return None
    canonical_name = service_data["privileges_lower_name"].get(action_name.lower())
    if canonical_name is None:
        return None
    return service_data["privileges"][canonical_name]


def _direct_dependencies(action: str) -> list[str]:
    """Return the distinct direct dependency actions declared on every resource type."""
    entry = _action_entry(action)
    if entry is None:
        return []
    dependencies: list[str] = []
    seen: set[str] = set()
    for resource_entry in entry.get("resource_types", {}).values():
        for dependency in resource_entry.get("dependent_actions", []):
            dependency_key = dependency.lower()
            if dependency_key not in seen:
                seen.add(dependency_key)
                dependencies.append(dependency)
    return dependencies


def _arn_formats_for_action(action: str) -> list[str]:
    """Return the raw ARN formats an action can be scoped to.

    A single ``"*"`` entry means the action is wildcard-only. An empty list is
    returned when the action is missing from the local directory.
    """
    entry = _action_entry(action)
    if entry is None:
        return []
    formats: list[str] = []
    seen: set[str] = set()
    for resource_type, resource_entry in entry.get("resource_types", {}).items():
        if resource_type:
            service_prefix, _ = action.split(":", 1)
            service_data = _service_data(service_prefix)
            resource_metadata = service_data["resources"].get(resource_type) if service_data else None
            arn_format = resource_metadata.get("arn", "*") if resource_metadata else "*"
        else:
            arn_format = "*"
        if arn_format not in seen:
            seen.add(arn_format)
            formats.append(arn_format)
    return formats


def build_dependency_graph(requested_actions: Iterable[str]) -> dict[str, Any]:
    """Walk the full dependency graph for the requested actions.

    Arguments:
        requested_actions: IAM actions requested by the user, e.g.
            ``["ec2:AssociateIamInstanceProfile"]``.

    Returns:
        A review report containing the requested actions, every transitive
        dependency, the paths reaching each dependency, detected cycles, and
        references that could not be resolved against the local directory.
    """
    requested: list[str] = []
    requested_seen: set[str] = set()
    for action in requested_actions:
        if ":" not in action:
            logger.debug("Skipping malformed requested action: %r", action)
            continue
        normalized = _normalize_action(action)
        if normalized.lower() not in requested_seen:
            requested_seen.add(normalized.lower())
            requested.append(normalized)

    # parent -> ordered, de-duplicated list of direct children (as written in the directory)
    graph: dict[str, list[str]] = {}
    # canonical child key -> set of canonical parent keys actually present in the graph
    parents: dict[str, set[str]] = {}
    missing: set[str] = set()

    queue = list(requested)
    queued: set[str] = set(action.lower() for action in requested)
    visited: set[str] = set()

    while queue:
        current = queue.pop(0)
        current_key = current.lower()
        if current_key in visited:
            continue
        visited.add(current_key)

        children: list[str] = []
        child_seen: set[str] = set()
        for raw_child in _direct_dependencies(current):
            if ":" not in raw_child:
                logger.debug("Skipping malformed dependency %r of %s", raw_child, current)
                continue
            child = _normalize_action(raw_child)
            child_key = child.lower()
            # Self loops and back edges stay in the graph for path/cycle
            # reporting; the visited/queued guards keep traversal finite.
            if child_key not in child_seen:
                child_seen.add(child_key)
                children.append(child)
            parents.setdefault(child_key, set()).add(current_key)

            if _action_entry(child) is None:
                missing.add(child)
            if child_key not in queued:
                queued.add(child_key)
                queue.append(child)
        graph[current_key] = children

    # Reconstruct every root-to-dependency path with a BFS per root.
    paths: dict[str, list[list[str]]] = {}
    for root in requested:
        _collect_paths(root, graph, requested, paths)

    requested_keys = {action.lower() for action in requested}
    dependencies: list[dict[str, Any]] = []
    for action_key in sorted(paths):
        if action_key in requested_keys:
            continue
        canonical = paths[action_key][0][-1]
        action_paths = [path for path in paths[action_key] if path]
        entry = _action_entry(canonical)
        if entry is None:
            status = STATUS_MISSING_METADATA
            arn_formats: list[str] = []
        else:
            arn_formats = _arn_formats_for_action(canonical)
            status = _classify_dependency(arn_formats, requested)

        dependencies.append(
            {
                "action": canonical,
                "status": status,
                "paths": action_paths,
                "resource_arn_formats": arn_formats,
                "direct_parents": sorted(parents.get(action_key, set())),
            }
        )

    # Anything referenced but unresolved gets an explicit entry even if BFS
    # could not attach a path (defensive; normally paths already cover it).
    known_keys = {item["action"].lower() for item in dependencies}
    for unknown in sorted(missing):
        if unknown.lower() in known_keys:
            continue
        dependencies.append(
            {
                "action": unknown,
                "status": STATUS_MISSING_METADATA,
                "paths": [],
                "resource_arn_formats": [],
                "direct_parents": sorted(parents.get(unknown.lower(), set())),
            }
        )

    requested_metadata = []
    for action in requested:
        entry = _action_entry(action)
        requested_metadata.append(
            {
                "action": action,
                "status": STATUS_REQUESTED if entry is not None else STATUS_MISSING_METADATA,
                "resource_arn_formats": _arn_formats_for_action(action) if entry is not None else [],
            }
        )

    cycles = _extract_cycles(paths, requested_keys)

    return {
        "requested_actions": requested_metadata,
        "dependencies": dependencies,
        "cycles": cycles,
        "missing_metadata": sorted(missing),
    }


def _extract_cycles(paths: dict[str, list[list[str]]], requested_keys: set[str]) -> list[list[str]]:
    """Return de-duplicated paths that revisit an action already on the path."""
    cycles: list[list[str]] = []
    cycle_keys: set[tuple[str, ...]] = set()
    for action_key, action_paths in paths.items():
        if action_key not in requested_keys:
            continue
        for path in action_paths:
            if len(path) <= 1:
                continue
            visited_on_path: set[str] = set()
            is_cycle = False
            for node in path:
                node_key = node.lower()
                if node_key in visited_on_path:
                    is_cycle = True
                    break
                visited_on_path.add(node_key)
            if not is_cycle:
                continue
            normalized = tuple(node.lower() for node in path)
            if normalized not in cycle_keys:
                cycle_keys.add(normalized)
                cycles.append(path)
    return cycles


def _collect_paths(
    root: str,
    graph: dict[str, list[str]],
    requested: list[str],
    paths: dict[str, list[list[str]]],
) -> None:
    """BFS from one requested action, recording the shortest path to each node.

    An edge leading back to an already-visited node (a cycle or a shared
    dependency) records the loop path without re-enqueuing the node, so every
    way of reaching a dependency stays visible while traversal stays finite.
    """
    root_key = root.lower()
    requested_keys = {action.lower() for action in requested}
    queue: list[list[str]] = [[root]]
    seen = {root_key}

    while queue:
        path = queue.pop(0)
        node = path[-1]
        node_key = node.lower()

        if node_key not in requested_keys or len(path) > 1:
            existing = paths.setdefault(node_key, [])
            if path not in existing:
                existing.append(path)

        for child in graph.get(node_key, []):
            child_key = child.lower()
            child_path = [*path, child]
            if child_key in seen:
                existing = paths.setdefault(child_key, [])
                if child_path not in existing:
                    existing.append(child_path)
                continue
            seen.add(child_key)
            queue.append(child_path)


def _classify_dependency(arn_formats: list[str], requested: list[str]) -> str:
    """Decide whether a dependency can be rendered without more user input."""
    if arn_formats == ["*"]:
        return STATUS_WILDCARD_ONLY
    requested_formats: set[str] = set()
    for requested_action in requested:
        requested_formats.update(_arn_formats_for_action(requested_action))
    if any(arn_format != "*" and arn_format in requested_formats for arn_format in arn_formats):
        return STATUS_SCOPED
    return STATUS_NEEDS_RESOURCE_SCOPE


def get_transitive_dependent_actions(requested_actions: Iterable[str]) -> list[str]:
    """Convenience helper returning every distinct transitive dependency action.

    Arguments:
        requested_actions: IAM actions requested by the user.
    Returns:
        A sorted list of canonical dependency actions, excluding the requested
        actions themselves.
    """
    report = build_dependency_graph(requested_actions)
    return sorted(item["action"] for item in report["dependencies"])


def get_dependencies_requiring_resource_scope(requested_actions: Iterable[str]) -> list[dict[str, Any]]:
    """Return only the dependency entries that need a user-supplied resource scope."""
    report = build_dependency_graph(requested_actions)
    return [
        item
        for item in report["dependencies"]
        if item["status"] in (STATUS_NEEDS_RESOURCE_SCOPE, STATUS_MISSING_METADATA)
    ]
