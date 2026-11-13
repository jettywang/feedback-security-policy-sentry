# Policy Sentry 分组/压缩对 Condition 的处理：判定报告

问题：两条 IAM 语句 Action 和 Resource 相同、Condition 不同，Policy Sentry
的分组（SidGroup）与压缩（minimize）会不会把它们错误合成一条？

## 结论

会，而且是两个层面都会：

1. **分组阶段直接丢弃 Condition。** 模板 schema 根本没有 condition 字段
   （`policy_sentry/writing/validate.py:40` 的 `CRUD_SCHEMA` 和 `:64` 的
   `ACTIONS_SCHEMA` 均无 condition 键）；`validate_condition_block()`
   （`validate.py:104`）是全仓库无调用方的死代码。`SidGroup.add_by_arn_and_access_level()`
   的 `_conditions_block` 参数被显式忽略（`sid_group.py:282-287`，
   `pylint: disable=unused-argument`），SID 命名空间只含
   `{Service}{AccessLevel}{ResourceType}`，不含 condition（`sid_group.py:313`
   调用 `create_policy_sid_namespace` 时不传 `condition_block`）。两条只差
   Condition 的请求落进同一个 SID，且 `"conditions": []  # TODO`
   （`sid_group.py:346`），渲染时 Condition 彻底消失——比"错误合并"更糟：
   输出的是**无条件**语句，权限被放大到两条语句条件的并集之上。

2. **压缩阶段按 Resource 相等盲目合并。** `get_rendered_policy(minimize=...)`
   里 `if stmt["Resource"] == group["arn"]` 就把 Action 并进已有语句
   （`sid_group.py:247-252`），完全不比较 Condition。即使未来把 Condition
   渲染进语句，这条路径仍会把不同 Condition 的语句合成一条并丢掉后者的条件。

实测证据（`demo_policy_sentry_behavior.py`，离线 stub 掉 orjson/schema 后运行）：

- Demo 1：同一 ARN+access level 调两次、分别传 `StringEquals` 和
  `StringEqualsIfExists` 条件 → 只生成一个 SID `S3WriteBucket`，
  `conditions` 为 `[]`，输出语句无 `Condition` 键。
- Demo 2：两个 SID 组、ARN 列表相同、各挂不同条件 →
  `get_rendered_policy(minimize=0)` 输出 **1 条**语句（`S3MultMybucket`），
  Action 被合并，条件信息丢失。

## 判定方法（不触碰真实 AWS）

- `iam_eval.py`：受限判定器。仅 Allow；算子覆盖 StringEquals /
  StringNotEquals / 两者 IfExists 变体 / ForAllValues:StringEquals /
  ForAnyValue:StringEquals / Null。语义按 AWS 文档：同一算子内多键 AND、
  单键多值 OR、多算子 AND、多语句 OR；缺失上下文键时——普通正向算子
  False、取反算子 True、`*IfExists` True、`ForAllValues:*` 空真（True）、
  `ForAnyValue:*` False、`Null:"true"` 当且仅当键缺失。
- `truth_tables.py`：12 个请求上下文（键缺失、单值、多值、全被拒值）×
  5 组样本，比较 BEFORE（两条独立语句）与四种"生成后"形态：
  `PS_ACTUAL`（条件被丢弃，即 Policy Sentry 当前行为）、`MERGE_AND`
  （两条件 AND 成一条）、`KEEP_A`/`KEEP_B`（只保留其一）。

## 真假表要点（T=允许；完整表见 `python3 condition_merge_analysis/truth_tables.py`）

| 样本 | 关键分歧行 | 结论 |
|---|---|---|
| S1 两条 Condition 完全相同 | PS_ACTUAL 在 9/12 上下文不同；MERGE_AND/KEEP_A/KEEP_B 全等价 | **唯一可安全合并的情形，但前提是保留条件**；Policy Sentry 当前连这种也会丢条件 |
| S2 `StringEquals` vs `StringEqualsIfExists`（同键同值） | C01（键缺失）：BEFORE=T，MERGE_AND/KEEP_A=F | 必须分开；或保留更宽者（KEEP_B 恰好等价，因为 IfExists 版允许集严格包含普通版） |
| S3 普通 `StringEquals` vs `ForAllValues:StringEquals`（多值键） | C01 键缺失、C10 单值 Owner、C11 含 Evil、C12 全 Evil | 必须分开；集合算子与普通算子语义不可互替 |
| S4 两个不同键（region vs 资源标签） | C02/C04/C07：分开是 OR，任何单语句形态都是 AND | 必须分开；OR 语义无法用一条语句表达 |
| S5 `Null:true`（键须缺失） vs 同键 `StringEquals` | C01 与 C02 互补为 T，MERGE_AND 恒 F | 必须分开；AND 合并会把语句变成死语句 |

注意 S2/S3 中 KEEP_B 等价是**逻辑包含**的巧合（一个条件的允许集是另一个的
超集），不是语法现象；判定它需要逐上下文求值，不能靠字符串比较。

## 安全合并规则（建议）

- **可合并**：两条语句的 Condition 块规范化后逐字相等（同算子、同键、同值
  集合），且合并时原样保留该 Condition。S1 即此类样本。
- **必须分开输出**（合并即改变语义）：
  - 一方带 `*IfExists` 另一方不带（缺失键行为不同，真假表 C01 行分叉）；
  - 一方是 `ForAllValues:`/`ForAnyValue:` 集合算子另一方不是（多值请求与
    缺失键下均分叉）；
  - 条件键不同或值不同（分开=OR，单语句只能表达 AND）；
  - 涉及 `Null` 条件键测试（键缺失本身就是条件）；
  - 一方有条件一方无（无条件的允许集是全集）。
- 保守默认：**Condition 不同就分语句输出**，只有逐字相同才合并；不要用
  "AND 进一条"或"丢掉一个"近似。

## 复现

```bash
# 离线桩（沙箱无法访问 PyPI，orjson/schema 用最小桩替代）
PYTHONPATH="$TMPDIR/psstubs:." python3 condition_merge_analysis/demo_policy_sentry_behavior.py
python3 condition_merge_analysis/truth_tables.py   # 纯标准库，无需桩
```
