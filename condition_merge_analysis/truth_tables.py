"""
Truth-table comparison of "two statements with same Action/Resource but
different Condition" vs. various merged forms, using the restricted evaluator
in iam_eval.py.

For each sample we compare:
  BEFORE     : the two original statements (OR semantics, as AWS evaluates them)
  PS_ACTUAL  : what Policy Sentry emits today -> one statement, Condition dropped
  MERGE_AND  : hypothetical single statement ANDing both condition blocks
  KEEP_A     : single statement keeping only statement 1's condition
  KEEP_B     : single statement keeping only statement 2's condition

Run: python3 condition_merge_analysis/truth_tables.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from iam_eval import eval_policy

ACTION = "s3:PutObject"
RESOURCE = "arn:aws:s3:::my-bucket/*"

REGION = "aws:RequestedRegion"
OWNER = "aws:ResourceTag/Owner"
TAGKEYS = "aws:TagKeys"

CONTEXTS = [
    ("C01 no keys", {}),
    ("C02 region=eu-west-1", {REGION: ["eu-west-1"]}),
    ("C03 region=us-east-1", {REGION: ["us-east-1"]}),
    ("C04 owner=alice", {OWNER: ["alice"]}),
    ("C05 owner=bob", {OWNER: ["bob"]}),
    ("C06 region=eu + owner=alice", {REGION: ["eu-west-1"], OWNER: ["alice"]}),
    ("C07 region=us + owner=alice", {REGION: ["us-east-1"], OWNER: ["alice"]}),
    ("C08 tagkeys=[CostCenter]", {TAGKEYS: ["CostCenter"]}),
    ("C09 tagkeys=[CostCenter,Owner]", {TAGKEYS: ["CostCenter", "Owner"]}),
    ("C10 tagkeys=[Owner]", {TAGKEYS: ["Owner"]}),
    ("C11 tagkeys=[CostCenter,Evil]", {TAGKEYS: ["CostCenter", "Evil"]}),
    ("C12 tagkeys=[Evil]", {TAGKEYS: ["Evil"]}),
]


def stmt(condition):
    s = {"Effect": "Allow", "Action": [ACTION], "Resource": [RESOURCE]}
    if condition is not None:
        s["Condition"] = condition
    return s


def two(cond_a, cond_b):
    return {"Statement": [stmt(cond_a), stmt(cond_b)]}


def one(condition):
    return {"Statement": [stmt(condition)]}


def merged_and(cond_a, cond_b):
    """Hypothetical: one statement, both condition blocks ANDed."""
    merged = {}
    for cond in (cond_a, cond_b):
        if cond:
            for op, km in cond.items():
                merged.setdefault(op, {}).update(km)
    return one(merged or None)


SAMPLES = [
    (
        "S1 identical conditions (candidate SAFE merge)",
        {"StringEquals": {REGION: ["eu-west-1"]}},
        {"StringEquals": {REGION: ["eu-west-1"]}},
    ),
    (
        "S2 StringEquals vs StringEqualsIfExists (same key/value)",
        {"StringEquals": {REGION: ["eu-west-1"]}},
        {"StringEqualsIfExists": {REGION: ["eu-west-1"]}},
    ),
    (
        "S3 plain StringEquals vs ForAllValues:StringEquals (multivalued key)",
        {"StringEquals": {TAGKEYS: ["CostCenter"]}},
        {"ForAllValues:StringEquals": {TAGKEYS: ["CostCenter", "Owner"]}},
    ),
    (
        "S4 two different keys (region vs resource tag)",
        {"StringEquals": {REGION: ["eu-west-1"]}},
        {"StringEquals": {OWNER: ["alice"]}},
    ),
    (
        "S5 Null(key absent) vs StringEquals on the same key",
        {"Null": {REGION: ["true"]}},
        {"StringEquals": {REGION: ["eu-west-1"]}},
    ),
]


def render_context(ctx):
    if not ctx:
        return "(none)"
    return ",".join(f"{k.split(':')[-1]}={v}" for k, v in ctx.items())


def run_sample(name, cond_a, cond_b):
    before = two(cond_a, cond_b)
    variants = {
        "PS_ACTUAL": one(None),  # Policy Sentry today: condition dropped entirely
        "MERGE_AND": merged_and(cond_a, cond_b),
        "KEEP_A": one(cond_a),
        "KEEP_B": one(cond_b),
    }
    print(f"\n### {name}")
    header = f"{'context':<34} | BEFORE | " + " | ".join(f"{v:<9}" for v in variants)
    print(header)
    print("-" * len(header))
    diffs = {v: 0 for v in variants}
    for label, ctx in CONTEXTS:
        b = eval_policy(before, ACTION, RESOURCE, ctx)
        row = [b]
        marks = []
        for vname, pol in variants.items():
            r = eval_policy(pol, ACTION, RESOURCE, ctx)
            row.append(r)
            if r != b:
                diffs[vname] += 1
                marks.append(vname)
        flag = f"  <-- DIFF: {','.join(marks)}" if marks else ""
        cells = " | ".join(f"{'T' if x else 'F':^9}" for x in row[1:])
        print(f"{label:<34} |   {'T' if b else 'F'}    | {cells}{flag}")
    print("verdict:", {k: ("EQUIVALENT" if n == 0 else f"differs in {n} context(s)") for k, n in diffs.items()})


if __name__ == "__main__":
    for name, cond_a, cond_b in SAMPLES:
        run_sample(name, cond_a, cond_b)
