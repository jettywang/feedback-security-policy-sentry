"""
A small, restricted IAM condition evaluator.

Scope (deliberately narrow, semantics follow the AWS IAM docs):
- Effect: Allow only (no Deny, no NotAction/NotResource).
- Condition operators:
    StringEquals, StringNotEquals,
    StringEqualsIfExists, StringNotEqualsIfExists,
    ForAllValues:StringEquals, ForAnyValue:StringEquals,
    Null
- Request context: dict mapping condition key -> list of string values.
  A key that is absent from the dict models "the context key is not present
  in the request" (the missing-key case).

AWS evaluation rules implemented here:
- Within one operator block: multiple keys are ANDed; multiple values for one
  key are ORed.
- Multiple operators in one Condition block are ANDed.
- Multiple Allow statements are ORed.
- Missing-key behavior:
    StringEquals            -> False (no match)
    StringNotEquals         -> True  (negated operators match on missing key)
    *IfExists               -> True  (missing key is ignored)
    ForAllValues:*          -> True  (vacuously true: every one of zero values matches)
    ForAnyValue:*           -> False (no value exists that could match)
    Null "true"             -> True iff key is missing
"""
from __future__ import annotations

Context = dict[str, list[str]]


def _string_equals(request_value: str, condition_value: str) -> bool:
    return request_value == condition_value


def _string_not_equals(request_value: str, condition_value: str) -> bool:
    return request_value != condition_value


_BASE_OPS = {
    "StringEquals": _string_equals,
    "StringNotEquals": _string_not_equals,
}
_NEGATED = {"StringNotEquals"}


def eval_operator_on_key(operator: str, key: str, condition_values: list[str], context: Context) -> bool:
    """Evaluate one `Operator: {key: [values...]}` pair against the request context."""
    if operator == "Null":
        # Null expects exactly one condition value: "true" or "false"
        wants_missing = condition_values[0].lower() == "true"
        return (key not in context) == wants_missing

    if_exists = operator.endswith("IfExists")
    base_name = operator[: -len("IfExists")] if if_exists else operator

    set_quantifier = None
    if base_name.startswith("ForAllValues:"):
        set_quantifier = "all"
        base_name = base_name[len("ForAllValues:"):]
    elif base_name.startswith("ForAnyValue:"):
        set_quantifier = "any"
        base_name = base_name[len("ForAnyValue:"):]

    base_fn = _BASE_OPS[base_name]
    key_present = key in context
    request_values = context.get(key, [])

    if not key_present:
        if if_exists:
            return True
        if set_quantifier == "all":
            return True  # vacuous truth
        if set_quantifier == "any":
            return False
        # plain (non-set) operator
        return base_name in _NEGATED

    if set_quantifier == "all":
        # every request value must match at least one condition value
        return all(any(base_fn(rv, cv) for cv in condition_values) for rv in request_values)
    if set_quantifier == "any":
        # at least one request value must match at least one condition value
        return any(any(base_fn(rv, cv) for cv in condition_values) for rv in request_values)

    # plain operator: key matches if ANY request value matches ANY condition value
    return any(base_fn(rv, cv) for rv in request_values for cv in condition_values)


def eval_condition(condition: dict | None, context: Context) -> bool:
    """Evaluate a whole Condition block. Absent Condition -> always True."""
    if not condition:
        return True
    for operator, key_map in condition.items():
        for key, values in key_map.items():
            if isinstance(values, str):
                values = [values]
            if not eval_operator_on_key(operator, key, values, context):
                return False
    return True


def eval_statement(statement: dict, action: str, resource: str, context: Context) -> bool:
    """True iff this Allow statement grants the request."""
    if statement.get("Effect", "Allow") != "Allow":
        return False
    if action not in statement["Action"]:
        return False
    if resource not in statement["Resource"]:
        return False
    return eval_condition(statement.get("Condition"), context)


def eval_policy(policy: dict, action: str, resource: str, context: Context) -> bool:
    """Allow-only policy: OR over statements."""
    return any(
        eval_statement(stmt, action, resource, context) for stmt in policy["Statement"]
    )
