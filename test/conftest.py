"""Shared pytest fixtures for the Policy Sentry test suite."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from policy_sentry.querying import actions as actions_module
from policy_sentry.querying import all as all_module
from policy_sentry.querying import arns as arns_module
from policy_sentry.querying import conditions as conditions_module
from policy_sentry.querying import services as services_module
from policy_sentry.shared import iam_data

FIXTURE_DIRECTORY = Path(__file__).parent / "files"
# Modules that bind the datastore at import time and/or memoize queries.
_QUERY_MODULES = (actions_module, all_module, arns_module, conditions_module, services_module)


def _clear_query_caches() -> None:
    iam_data.get_service_prefix_data.cache_clear()
    for module in _QUERY_MODULES:
        for attribute in vars(module).values():
            clear_cache = getattr(attribute, "cache_clear", None)
            if callable(clear_cache):
                clear_cache()


@pytest.fixture
def sample_action_directory(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Load the curated local action directory sample and make it the active datastore.

    The sample deliberately covers multi-level chains, shared dependencies,
    cycles, missing metadata and dependencies requiring different ARNs. Every
    module-level datastore binding and LRU cache is reset so querying code only
    sees the sample data for the duration of the test.
    """
    sample_path = FIXTURE_DIRECTORY / "action-directory-sample.json"
    sample_data = json.loads(sample_path.read_text())

    monkeypatch.setattr(iam_data, "iam_definition", sample_data)
    for module in _QUERY_MODULES:
        if hasattr(module, "iam_definition"):
            monkeypatch.setattr(module, "iam_definition", sample_data)
    monkeypatch.setattr(actions_module, "all_service_prefixes", list(sample_data))
    _clear_query_caches()

    yield sample_data

    _clear_query_caches()
