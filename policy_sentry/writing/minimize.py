# pylint: disable=W1202,E1305
"""
Functions for Minimizing statements, heavily borrowed from policyuniverse.
https://github.com/Netflix-Skunkworks/policyuniverse/

IAM Policies have character limits, which apply to individual policies, and there are also limits on the total
aggregate policy sizes. As such, it is not possible to use exhaustive list of explicit IAM actions.
To have granular control of specific IAM policies, we must use wildcards on IAM Actions, only in a programmatic manner.

This is typically performed by humans by reducing policies to s3:Get*, ec2:Describe*, and other approaches of the sort.

Netflix's PolicyUniverse has addressed this in their minimization code. We borrowed this logic from their code and modified it a bit to fit our needs.

https://aws.amazon.com/iam/faqs/
Q: How many policies can I attach to an IAM role?
* For inline policies: You can add as many inline policies as you want to a user, role, or group, but
  the total aggregate policy size (the sum size of all inline policies) per entity cannot exceed the following limits:
  - User policy size cannot exceed 2,048 characters.
  - Role policy size cannot exceed 10,240 characters.
  - Group policy size cannot exceed 5,120 characters.
* For managed policies: You can add up to 10 managed policies to a user, role, or group.
* The size of each managed policy cannot exceed 6,144 characters.
"""

from __future__ import annotations

import functools
import logging
from typing import TypedDict

logger = logging.getLogger(__name__)


class ConservativeRejection(TypedDict):
    """Why a prefix wildcard was kept as explicit actions."""

    reason: str
    blocked_by: list[str]


# Borrowed from policyuniverse to reduce size
# https://github.com/Netflix-Skunkworks/policyuniverse/blob/master/policyuniverse/expander_minimizer.py#L45
@functools.lru_cache(maxsize=1024)
def _get_prefixes_for_action(action: str) -> list[str]:
    """
    :param action: iam:cat
    :return: [ "iam:", "iam:c", "iam:ca", "iam:cat" ]
    """
    technology, permission = action.split(":")
    return [f"{technology}:{permission[:i]}" for i in range(len(permission) + 1)]


# Adapted version of policyuniverse's _get_denied_prefixes_from_desired, here:
# https://github.com/Netflix-Skunkworks/policyuniverse/blob/master/policyuniverse/expander_minimizer.py#L101
def get_denied_prefixes_from_desired(desired_actions: list[str], all_actions: set[str]) -> set[str]:  # pylint: disable=missing-function-docstring
    """
    Adapted version of policyuniverse's _get_denied_prefixes_from_desired, here: https://github.com/Netflix-Skunkworks/policyuniverse/blob/master/policyuniverse/expander_minimizer.py#L101
    """
    denied_actions = all_actions.difference(desired_actions)
    return {
        denied_prefix for denied_action in denied_actions for denied_prefix in _get_prefixes_for_action(denied_action)
    }


# Adapted version of policyuniverse's _check_permission_length. We are commenting out the skipping prefix message
# https://github.com/Netflix-Skunkworks/policyuniverse/blob/master/policyuniverse/expander_minimizer.py#L111
def check_min_permission_length(permission: str, minchars: int | None = None) -> bool:  # pylint: disable=missing-function-docstring
    """
    Adapted version of policyuniverse's _check_permission_length. We are commenting out the skipping prefix message
    https://github.com/Netflix-Skunkworks/policyuniverse/blob/master/policyuniverse/expander_minimizer.py#L111
    """
    return bool(minchars and permission and len(permission) < int(minchars))


def _actions_matching_prefix(prefix: str, all_actions: set[str]) -> set[str]:
    """
    Every catalog action that an IAM prefix wildcard such as ``foo:getu*``
    would actually match.
    """
    return {action for action in all_actions if action.startswith(prefix)}


def _service_actions(service_prefix: str, all_actions: set[str]) -> set[str]:
    """Every catalog action under a service prefix such as ``foo:``."""
    return {action for action in all_actions if action.startswith(service_prefix)}


# This is a condensed version of policyuniverse's minimize_statement_actions, changed for our purposes.
# https://github.com/Netflix-Skunkworks/policyuniverse/blob/master/policyuniverse/expander_minimizer.py#L123
def minimize_statement_actions(
    desired_actions: list[str],
    all_actions: set[str],
    minchars: int | None = None,
    conservative: bool = False,
) -> list[str]:  # pylint: disable=missing-function-docstring
    """
    This is a condensed version of policyuniverse's minimize_statement_actions, changed for our purposes.
    https://github.com/Netflix-Skunkworks/policyuniverse/blob/master/policyuniverse/expander_minimizer.py#L123

    Arguments:
        desired_actions: The actions the statement is meant to grant.
        all_actions: The full catalog of actions known to the generator. When
            ``conservative`` is enabled it must be the unfiltered catalog, so
            explicit exclusions and every other service action stay visible.
        minchars: Skip any wildcard prefix shorter than this many characters.
        conservative: Bind wildcards to a fixed meaning. Narrow prefix
            wildcards (such as ``foo:getu*``) are never emitted: they are kept
            as explicit action names because a future same-prefix AWS action
            could widen them. The only wildcard retained is the service-wide
            one (``foo:*``), and only when every catalog action in that service
            is approved. Rejected prefixes are recorded in
            :func:`get_last_conservative_report` with the reason they could not
            be used.
    """
    minimized_actions = set()

    desired_actions = [x.lower() for x in desired_actions]
    desired_services = {f"{action.split(':')[0]}:" for action in desired_actions}

    if conservative:
        # Never hide an excluded or not-yet-approved action behind a service
        # filter: a prefix is only safe if the whole catalog agrees on it.
        filtered_actions = set(all_actions)
        # A service-wide wildcard input such as "foo:*" means "every foo action
        # in the catalog". Expand it up front so it is never re-suffixed into a
        # malformed token like "foo:**".
        expanded_desired: list[str] = []
        for action in desired_actions:
            if action.endswith(":*"):
                service_prefix = action[:-1]
                expanded_desired.extend(
                    sorted(
                        catalog_action
                        for catalog_action in filtered_actions
                        if catalog_action.startswith(service_prefix)
                    )
                )
            else:
                expanded_desired.append(action)
        desired_actions = expanded_desired
    else:
        filtered_actions = {
            action for action in all_actions if any(action.startswith(service) for service in desired_services)
        }

    desired_actions_set = set(desired_actions)

    denied_prefixes = get_denied_prefixes_from_desired(desired_actions, filtered_actions)
    conservative_report: dict[str, ConservativeRejection] = {}

    def record_rejection(wildcard: str, reason: str, blocked_by: set[str] | None = None) -> None:
        entry = conservative_report.setdefault(wildcard, {"reason": reason, "blocked_by": []})
        if blocked_by:
            entry["blocked_by"].extend(sorted(blocked_by))
            # A concrete over-grant always outranks the generic open-prefix reason.
            entry["reason"] = "unapproved_actions_matched"

    for action in desired_actions:
        if action in denied_prefixes:
            # print("Action is a denied prefix. Action: {}".format(action))
            minimized_actions.add(action)
            continue

        found_prefix = False
        prefixes = _get_prefixes_for_action(action)
        # Shortest non-denied prefix (first match when walking from the bare
        # service prefix toward the full action name) that the default
        # minimizer would have emitted, honoring minchars. The conservative
        # report names this single prefix per action instead of every
        # character length it rejected.
        default_prefix: str | None = None
        for candidate in prefixes:
            candidate_permission = candidate.split(":")[1]
            if (
                candidate_permission
                and candidate not in denied_prefixes
                and not check_min_permission_length(candidate_permission, minchars=minchars)
            ):
                default_prefix = candidate
                break

        if conservative and default_prefix is not None:
            # Classify, once, why the default wildcard cannot be trusted to
            # have a fixed meaning. Inspect the default prefix and every
            # shorter one: an unapproved action hidden behind a shorter prefix
            # (for example an explicit exclusion sharing the "get" stem) is
            # what forces the default minimizer to lengthen the wildcard, and
            # must be reported as a concrete over-grant.
            default_wildcard = f"{default_prefix}*"
            default_service = f"{default_prefix.split(':')[0]}:"
            over_grants: set[str] = set()
            for candidate in prefixes:
                candidate_permission = candidate.split(":")[1]
                if not candidate_permission or check_min_permission_length(
                    candidate_permission, minchars=minchars
                ):
                    continue
                over_grants.update(_actions_matching_prefix(candidate, filtered_actions) - desired_actions_set)
                if candidate == default_prefix:
                    break
            if over_grants:
                # The prefix the normal minimizer would print (or a shorter one
                # it had to avoid) would also grant known unapproved actions.
                record_rejection(default_wildcard, "unapproved_actions_matched", over_grants)
            elif _actions_matching_prefix(default_prefix, filtered_actions) != _service_actions(
                default_service, filtered_actions
            ):
                # Every current match is approved, but a future same-prefix AWS
                # action would silently widen the grant.
                record_rejection(default_wildcard, "open_prefix_future_actions")

        for prefix in prefixes:
            permission = prefix.split(":")[1]
            wildcard = f"{prefix}*"
            if check_min_permission_length(permission, minchars=minchars):
                continue

            if not conservative:
                # If the action name is not empty
                if prefix not in denied_prefixes and permission:
                    minimized_actions.add(prefix if prefix in desired_actions else f"{prefix}*")
                    found_prefix = True
                    break
                continue

            # Conservative path.
            service_prefix = f"{prefix.split(':')[0]}:"
            if not permission:
                # The bare "foo:" prefix can only become the service-wide
                # wildcard "foo:*", and only when every action in the service
                # is approved. Any unapproved action keeps it denied.
                if prefix in denied_prefixes:
                    continue
                if _service_actions(service_prefix, filtered_actions) - desired_actions_set:
                    continue
                minimized_actions.add(wildcard)
                found_prefix = True
                # The service-wide wildcard supersedes every narrower report
                # entry recorded for actions in this service.
                for reported in list(conservative_report):
                    if reported.startswith(service_prefix):
                        del conservative_report[reported]
                break

            # Every non-empty prefix needs a non-denied, fully-approved meaning.
            if prefix in denied_prefixes:
                continue
            matched = _actions_matching_prefix(prefix, filtered_actions)
            if matched - desired_actions_set:
                # Would grant known unapproved actions; stay explicit.
                continue
            # A non-empty prefix (e.g. "bar:listt") never spans the whole
            # service namespace the way the bare "bar:" prefix does, so it
            # stays explicit to keep a fixed meaning against future actions.
            continue

        if not found_prefix:
            logger.debug(f"Could not find suitable prefix. Defaulting to {prefixes[-1]}")
            minimized_actions.add(prefixes[-1])
    # sort the actions
    _LAST_CONSERVATIVE_REPORT.clear()
    for rejected_prefix, entry in conservative_report.items():
        _LAST_CONSERVATIVE_REPORT[rejected_prefix] = {
            "reason": entry["reason"],
            "blocked_by": sorted(set(entry["blocked_by"])),
        }
    return sorted(minimized_actions)


# Rejected-prefix report from the most recent conservative minimization run.
_LAST_CONSERVATIVE_REPORT: dict[str, ConservativeRejection] = {}


def get_last_conservative_report() -> dict[str, ConservativeRejection]:
    """
    Prefixes that the most recent conservative run refused to emit.

    Each entry maps the rejected wildcard to a dict with:

    * ``reason``: ``unapproved_actions_matched`` when the wildcard would grant
      known actions outside the approved set (for example explicit
      exclusions), or ``open_prefix_future_actions`` when every current match
      is approved but a future same-prefix AWS action could still widen it.
    * ``blocked_by``: the concrete catalog actions the wildcard would have
      added unintentionally (empty for the open-prefix reason).

    Example: ``{"foo:get*": {"reason": "unapproved_actions_matched",
    "blocked_by": ["foo:getaccount"]}}`` means ``foo:get*`` was kept as
    explicit actions because it would also grant ``foo:getaccount``.
    """
    return {
        key: ConservativeRejection(reason=value["reason"], blocked_by=list(value["blocked_by"]))
        for key, value in _LAST_CONSERVATIVE_REPORT.items()
    }
