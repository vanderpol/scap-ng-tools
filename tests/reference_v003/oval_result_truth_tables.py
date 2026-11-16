#!/usr/bin/env python3
"""Reference OVAL 5.12.3 result combiners used by SCAP-NG conformance tests.

This module intentionally implements only generic result aggregation and
existence truth tables documented in the pinned OVAL 5.12.3 schemas. It is not
an evaluator and does not collect target data.
"""
from collections import Counter

TRUE = "true"
FALSE = "false"
ERROR = "error"
UNKNOWN = "unknown"
NOT_EVALUATED = "not evaluated"
NOT_APPLICABLE = "not applicable"
NO_VALUES = "no values"

RESULTS = {TRUE, FALSE, ERROR, UNKNOWN, NOT_EVALUATED, NOT_APPLICABLE}


SET_FLAGS = (
    "error",
    "complete",
    "incomplete",
    "does_not_exist",
    "not_collected",
    "not_applicable",
)

# OVAL 5.12.3 set collected-object flag tables. Rows are the second operand;
# columns are the first operand in SET_FLAGS order.
SET_FLAG_TABLES = {
    "UNION": {
        "error":          ["error","error","error","error","error","error"],
        "complete":       ["error","complete","incomplete","complete","incomplete","complete"],
        "incomplete":     ["error","incomplete","incomplete","incomplete","incomplete","incomplete"],
        "does_not_exist": ["error","complete","incomplete","does_not_exist","incomplete","does_not_exist"],
        "not_collected":  ["error","incomplete","incomplete","incomplete","not_collected","not_collected"],
        "not_applicable": ["error","complete","incomplete","does_not_exist","not_collected","not_applicable"],
    },
    "INTERSECTION": {
        "error":          ["error","error","error","does_not_exist","error","error"],
        "complete":       ["error","complete","incomplete","does_not_exist","not_collected","complete"],
        "incomplete":     ["error","incomplete","incomplete","does_not_exist","not_collected","incomplete"],
        "does_not_exist": ["does_not_exist","does_not_exist","does_not_exist","does_not_exist","does_not_exist","does_not_exist"],
        "not_collected":  ["error","not_collected","not_collected","does_not_exist","not_collected","not_collected"],
        "not_applicable": ["error","complete","incomplete","does_not_exist","not_collected","not_applicable"],
    },
    "COMPLEMENT": {
        "error":          ["error","error","error","does_not_exist","error","error"],
        "complete":       ["error","complete","incomplete","does_not_exist","not_collected","error"],
        "incomplete":     ["error","error","error","does_not_exist","not_collected","error"],
        "does_not_exist": ["error","complete","incomplete","does_not_exist","not_collected","error"],
        "not_collected":  ["error","not_collected","not_collected","does_not_exist","not_collected","error"],
        "not_applicable": ["error","error","error","error","error","error"],
    },
}


def _counts(values):
    values = list(values)
    if not values:
        raise ValueError("OVAL result aggregation requires at least one input")
    unknown = [v for v in values if v not in RESULTS]
    if unknown:
        raise ValueError(f"unsupported result values: {unknown}")
    return Counter(values)


def aggregate_check(check, values):
    """Apply OVAL CheckEnumeration to individual result values."""
    c = _counts(values)
    t, f = c[TRUE], c[FALSE]
    e, u, ne, na = c[ERROR], c[UNKNOWN], c[NOT_EVALUATED], c[NOT_APPLICABLE]

    if check == "all":
        if f: return FALSE
        if e: return ERROR
        if u: return UNKNOWN
        if ne: return NOT_EVALUATED
        if t: return TRUE
        if na: return NOT_APPLICABLE
    elif check == "at least one":
        if t: return TRUE
        if e: return ERROR
        if u: return UNKNOWN
        if ne: return NOT_EVALUATED
        if f: return FALSE
        if na: return NOT_APPLICABLE
    elif check == "only one":
        if t >= 2: return FALSE
        if e: return ERROR
        if u: return UNKNOWN
        if ne: return NOT_EVALUATED
        if t == 1: return TRUE
        if f: return FALSE
        if na: return NOT_APPLICABLE
    elif check == "none satisfy":
        if t: return FALSE
        if e: return ERROR
        if u: return UNKNOWN
        if ne: return NOT_EVALUATED
        if f: return TRUE
        if na: return NOT_APPLICABLE
    else:
        raise ValueError(f"unsupported CheckEnumeration: {check}")
    raise AssertionError("unreachable result combination")


def decisive_partial_check(check, observed_results):
    """Return a conclusive result from a partial item stream, or None.

    This models only outcomes that cannot be changed by any additional
    matching items. It is intentionally conservative: lack of a decisive
    result means evaluation must continue or end as incomplete/unknown.
    """
    values = list(observed_results)
    if not values:
        return None
    c = _counts(values)
    t, f = c[TRUE], c[FALSE]

    if check == "all":
        return FALSE if f else None
    if check == "at least one":
        return TRUE if t else None
    if check == "only one":
        return FALSE if t >= 2 else None
    if check == "none satisfy":
        return FALSE if t else None
    raise ValueError(f"unsupported CheckEnumeration: {check}")


def decisive_partial_existence(mode, *, exists=0):
    """Return a conclusive existence result from partial collection, or None."""
    if not isinstance(exists, int) or exists < 0:
        raise ValueError("exists must be a non-negative integer")
    if mode == "at_least_one_exists":
        return TRUE if exists >= 1 else None
    if mode == "none_exist":
        return FALSE if exists >= 1 else None
    if mode == "only_one_exists":
        return FALSE if exists >= 2 else None
    if mode == "any_exist":
        # Once one existing item has been observed, future error/not-collected
        # observations cannot overturn OVAL's any_exist=true outcome.
        return TRUE if exists >= 1 else None
    if mode == "all_exist":
        return None
    raise ValueError(f"unsupported ExistenceEnumeration: {mode}")



def aggregate_operator(operator, values):
    """Apply OVAL OperatorEnumeration to individual result values."""
    c = _counts(values)
    t, f = c[TRUE], c[FALSE]
    e, u, ne, na = c[ERROR], c[UNKNOWN], c[NOT_EVALUATED], c[NOT_APPLICABLE]

    if operator == "AND":
        return aggregate_check("all", values)
    if operator == "OR":
        return aggregate_check("at least one", values)
    if operator == "ONE":
        return aggregate_check("only one", values)
    if operator == "XOR":
        if e: return ERROR
        if u: return UNKNOWN
        if ne: return NOT_EVALUATED
        if t or f:
            return TRUE if t % 2 else FALSE
        if na:
            return NOT_APPLICABLE
        raise AssertionError("unreachable XOR combination")
    raise ValueError(f"unsupported OperatorEnumeration: {operator}")


def apply_filter_state_result(action, state_result):
    """Apply native filter selection and explicit non-Boolean failure semantics.

    OVAL 5.12.3 defines include/exclude behavior for Boolean State matches but
    is not explicit about every non-Boolean propagation path. SCAP-NG resolves
    that ambiguity by treating any non-Boolean filter-State result as a
    collection/evaluation error rather than guessing include/exclude behavior.
    This matches the historical MITRE ovaldi reference-interpreter behavior for
    core OVAL filters: Filter::DoFilter rejects non-Boolean State results and
    the Object collector surfaces the exception as a collected-object error.
    """
    action = (action or "exclude").lower()
    if action not in {"include", "exclude"}:
        raise ValueError(f"unsupported filter action: {action}")
    if state_result == TRUE:
        return action == "include"
    if state_result == FALSE:
        return action == "exclude"
    if state_result in {ERROR, UNKNOWN, NOT_EVALUATED, NOT_APPLICABLE}:
        return ERROR
    raise ValueError(f"unsupported filter State result: {state_result}")



def combine_set_flags(operator, first_flag, second_flag):
    """Combine two collected-object flags per OVAL 5.12.3 set tables."""
    operator = operator.upper()
    if operator not in SET_FLAG_TABLES:
        raise ValueError(f"unsupported set operator: {operator}")
    if first_flag not in SET_FLAGS or second_flag not in SET_FLAGS:
        raise ValueError(
            f"unsupported collected-object flags: {first_flag}, {second_flag}"
        )
    return SET_FLAG_TABLES[operator][second_flag][SET_FLAGS.index(first_flag)]



def aggregate_existence(mode, *, exists=0, does_not_exist=0, error=0, not_collected=0):
    """Apply OVAL ExistenceEnumeration to item-status counts."""
    for name, value in {
        "exists": exists,
        "does_not_exist": does_not_exist,
        "error": error,
        "not_collected": not_collected,
    }.items():
        if not isinstance(value, int) or value < 0:
            raise ValueError(f"{name} must be a non-negative integer")

    if mode == "all_exist":
        if does_not_exist: return FALSE
        if error: return ERROR
        if not_collected: return UNKNOWN
        return TRUE if exists else FALSE

    if mode == "any_exist":
        # OVAL's table makes this true whenever there is no error, including
        # zero matching items; an existing item also makes an error non-fatal.
        if exists: return TRUE
        if error: return ERROR
        return TRUE

    if mode == "at_least_one_exists":
        if exists: return TRUE
        if error: return ERROR
        if not_collected: return UNKNOWN
        return FALSE

    if mode == "none_exist":
        if exists: return FALSE
        if error: return ERROR
        if not_collected: return UNKNOWN
        return TRUE

    if mode == "only_one_exists":
        if exists >= 2: return FALSE
        if error: return ERROR
        if not_collected: return UNKNOWN
        return TRUE if exists == 1 else FALSE

    raise ValueError(f"unsupported ExistenceEnumeration: {mode}")


def evaluate_collected_object_test(
    flag,
    *,
    existence,
    check="all",
    item_results=None,
    has_state=True,
    exists=0,
    does_not_exist=0,
    error=0,
    not_collected=0,
):
    """Evaluate OVAL Test control flow for a present collected_object record.

    This implements the generic rules stated in the pinned OVAL 5.12.3
    oval-results-schema.xsd TestType documentation. Per-item State evaluation
    is supplied as item_results; this helper does not evaluate entity values.
    """
    if flag == "error":
        return ERROR
    if flag == "not collected":
        return UNKNOWN
    if flag == "not applicable":
        return NOT_APPLICABLE
    if flag == "does not exist":
        return TRUE if existence in {"none_exist", "any_exist"} else FALSE

    if flag not in {"complete", "incomplete"}:
        raise ValueError(f"unsupported collected_object flag: {flag}")

    existence_result = aggregate_existence(
        existence,
        exists=exists,
        does_not_exist=does_not_exist,
        error=error,
        not_collected=not_collected,
    )

    if flag == "complete":
        if existence_result != TRUE:
            return existence_result
        if not has_state:
            return TRUE
        if item_results is None:
            raise ValueError("complete Test with State requires item_results")
        return aggregate_check(check, item_results)

    # OVAL 5.12.3 incomplete collections require a result that cannot
    # change under *any* valid future Item/status outcome. Existence and
    # matching are independent scopes but the final verdict depends on both.
    if existence == "none_exist" and exists >= 1:
        return FALSE
    if existence == "only_one_exists" and exists > 1:
        return FALSE

    if has_state:
        if item_results is None:
            raise ValueError("incomplete Test with State requires item_results")
        # For exactly one observed Item, a currently failed comparison and
        # only_one_exists is conclusively false: if no further Items appear,
        # the comparison fails; if another appears, existence fails instead.
        # Conversely, a current success is NOT final, because a second Item
        # would invalidate only_one_exists.
        if existence == "only_one_exists":
            if exists == 1 and len(item_results) == 1:
                if aggregate_check(check, item_results) == FALSE:
                    return FALSE
            return UNKNOWN

        # Under all_exist, the unseen part of an incomplete population could
        # still contain an absent/error Item, so even an observed passing
        # comparison cannot settle the combined verdict.
        if existence == "all_exist":
            return UNKNOWN

        # These existence checks are monotone once one observed Item exists.
        # No later Item can invalidate their truth, although later State
        # comparisons can still change a nondecisive check result.
        if existence in {"at_least_one_exists", "any_exist"} and exists >= 1:
            decisive = decisive_partial_check(check, item_results)
            if decisive is not None:
                return decisive

    return UNKNOWN


def select_collected_object_instance(records, *, object_id, version, variable_instance=1):
    """Select one OVAL collected_object by its schema identity tuple.

    OVAL System Characteristics keys collected objects by id, version, and
    variable_instance. Missing is represented as None; duplicates are invalid
    input and must not be resolved by arbitrary first/last wins behavior.
    """
    matches = [
        record for record in records
        if record.get("id") == object_id
        and record.get("version") == version
        and record.get("variable_instance", 1) == variable_instance
    ]
    if len(matches) > 1:
        raise ValueError(
            "duplicate collected_object identity: "
            f"{object_id}@{version}#{variable_instance}"
        )
    return matches[0] if matches else None



def evaluate_missing_collected_object_record():
    """OVAL Test result when collected_objects exists but matching object does not."""
    return UNKNOWN


def resolve_variable_reference(values):
    """Normalize variable cardinality without prematurely applying reference context.

    OVAL 5.12.3 generic variable prose and entity var_ref prose are not identical:
    a zero-value variable must remain distinguishable until the Object or State
    reference site applies its more specific semantics.
    """
    values = list(values)
    if not values:
        return {"status": NO_VALUES, "values": []}
    return {"status": TRUE, "values": values}


def apply_variable_reference_context(variable_result, context):
    """Apply OVAL entity var_ref semantics for a resolved variable result."""
    status = variable_result["status"]
    if status == NO_VALUES:
        if context == "object":
            return "does_not_exist"
        if context in {"state", "direct_test"}:
            return ERROR
        raise ValueError(f"unsupported variable reference context: {context}")
    if status != TRUE:
        return status
    return TRUE


def evaluate_variable_entity_reference(
    *,
    variable_status,
    var_check,
    entity_check,
    comparison_rows=None,
):
    """Propagate variable resolution status into State/Object entity evaluation.

    Zero-value cardinality must be resolved through apply_variable_reference_context()
    before this helper is called because Object and State references intentionally
    diverge. Non-success variable status is propagated before any
    var_check/entity_check aggregation; quantifiers cannot turn an unresolved or
    error-like variable into a successful predicate.
    """
    if variable_status != TRUE:
        if variable_status not in RESULTS:
            raise ValueError(f"unsupported variable status: {variable_status}")
        return variable_status
    if comparison_rows is None:
        raise ValueError("resolved variable requires comparison_rows")
    return aggregate_many_to_many(
        var_check=var_check,
        entity_check=entity_check,
        comparison_rows=comparison_rows,
    )


def aggregate_many_to_many(*, var_check, entity_check, comparison_rows):
    """Aggregate one State entity's many-to-many value comparisons.

    Each row represents one corresponding system/item entity compared against
    all values of the referenced variable. OVAL first combines each row using
    var_check, then combines row results using entity_check.
    """
    rows = [list(row) for row in comparison_rows]
    if not rows or any(not row for row in rows):
        raise ValueError("many-to-many aggregation requires non-empty rows")
    per_entity = [aggregate_check(var_check, row) for row in rows]
    return aggregate_check(entity_check, per_entity)


def aggregate_state(operator, predicate_results):
    """Combine entity/predicate results inside one OVAL State."""
    return aggregate_operator(operator, predicate_results)


def aggregate_item_states(state_operator, state_results):
    """Combine multiple referenced State results for one collected item."""
    return aggregate_operator(state_operator, state_results)


def evaluate_record_field(field_name, comparison_results, entity_check="all"):
    """Evaluate one expected record field against same-name Item fields.

    OVAL 5.12.3 EntityStateFieldType requires a missing expected field to
    produce error. When multiple same-name Item fields are present,
    entity_check combines their comparison results.
    """
    values = list(comparison_results)
    if not values:
        return ERROR
    return aggregate_check(entity_check, values)


def evaluate_record_entity(field_results):
    """Combine expected record-field results for one record Item entity.

    OVAL 5.12.3 EntityStateRecordType defines the parent record comparison as
    logical AND across its expected fields. Parent record entity_check, when
    multiple record entities with the same name exist, is applied outside this
    helper by the ordinary entity aggregation layer.
    """
    values = list(field_results)
    if not values:
        # A record State with no field requirements imposes no failing field
        # predicate on the record value.
        return TRUE
    return aggregate_operator("AND", values)


def validate_record_state_constraints(*, datatype, operation, var_ref=None, var_check=None):
    """Validate OVAL-derived record State constraints stated by 5.12.3 schema."""
    errors = []
    if datatype != "record":
        errors.append("record entity datatype must be record")
    if operation != "equals":
        errors.append("record entity operation must be equals")
    if var_ref is not None:
        errors.append("record entity var_ref is not permitted")
    if var_check is not None:
        errors.append("record entity var_check does not apply")
    return errors


def evaluate_state_entity_existence(
    mode, *, exists=0, does_not_exist=0, error=0, not_collected=0
):
    """Evaluate the State-entity existence piece before value comparison.

    OVAL 5.12.3 ExistenceEnumeration explicitly states that its tables apply
    secondarily to State entities in corresponding Items. This helper therefore
    reuses the authoritative existence table without guessing the subsequent
    zero-entity value-comparison behavior.
    """
    return aggregate_existence(
        mode,
        exists=exists,
        does_not_exist=does_not_exist,
        error=error,
        not_collected=not_collected,
    )
