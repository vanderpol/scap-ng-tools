"""Native 0.4.1 semantic extension for typed Input expressions.

The copied OVAL visitor and pinned 0.4 semantic port remain byte-identical.
The old checker retains responsibility for all other operations. This overlay
creates typed *validation-only* placeholders; these must never be serialized,
used for execution, or treated as source/value equivalence evidence.
"""
from __future__ import annotations

from copy import deepcopy
from functools import wraps


class InputExpressionContractError(ValueError):
    pass


def project_assessment(assessment):
    """Return (validation-only assessment, integer-cast operand probes).

    Each probe is evaluated by the original source-typed semantic checker
    against the same projected Variable graph and must have result string.
    """
    if not isinstance(assessment, dict):
        raise InputExpressionContractError("Assessment must be a map")
    inputs = assessment.get("inputs") or {}
    variables = assessment.get("variables") or {}
    if not isinstance(inputs, dict) or not isinstance(variables, dict):
        raise InputExpressionContractError("Inputs/Variables must be maps")
    probes = []
    seen = set()

    def visit(node, level=0):
        if level > 32 or not isinstance(node, dict) or len(node) != 1:
            raise InputExpressionContractError("Variable expression shape/depth invalid")
        operator, value = next(iter(node.items()))
        if operator == "input":
            if not isinstance(value, str) or value not in inputs:
                raise InputExpressionContractError("Input expression references undeclared Input")
            contract = inputs[value]
            if not isinstance(contract, dict) or contract.get("required") is not True or (
                    contract.get("cardinality") != "exactly_one"):
                raise InputExpressionContractError(
                    "Only required, exactly_one Input function operands currently qualify")
            datatype = contract.get("datatype")
            literal = {"string": "0", "integer": 0, "float": 0.0, "boolean": False}.get(datatype)
            if literal is None:
                raise InputExpressionContractError(
                    "Input datatype lacks an approved scalar expression projection")
            seen.add("input")
            return {"literal": {"datatype": datatype, "value": literal}}
        if operator == "to_integer":
            if not isinstance(value, dict):
                raise InputExpressionContractError("to_integer requires one expression")
            # The actual source text graph is verified independently below.
            probes.append(visit(value, level + 1))
            seen.add("to_integer")
            return {"literal": {"datatype": "integer", "value": 0}}
        if operator in ("literal", "variable", "values"):
            return deepcopy(node)
        if operator in ("count",):
            return {operator: visit(value, level + 1)}
        if operator in ("concat", "unique"):
            if isinstance(value, list):
                return {operator: [visit(v, level + 1) for v in value]}
            return {operator: visit(value, level + 1)}
        if operator in ("arithmetic", "merge", "time_difference"):
            if not isinstance(value, dict) or "values" not in value:
                raise InputExpressionContractError(operator + " lacks values")
            payload = deepcopy(value)
            if isinstance(value["values"], list):
                payload["values"] = [visit(v, level + 1) for v in value["values"]]
            else:
                payload["values"] = visit(value["values"], level + 1)
            return {operator: payload}
        if operator in ("split", "substring", "begin", "end", "regex_capture"):
            if not isinstance(value, dict) or "value" not in value:
                raise InputExpressionContractError(operator + " lacks value")
            payload = deepcopy(value)
            payload["value"] = visit(value["value"], level + 1)
            return {operator: payload}
        # The original semantic validator remains the authority for
        # unsupported operators; never reinterpret unknown expression syntax.
        return deepcopy(node)

    projected = deepcopy(assessment)
    for ident, declaration in variables.items():
        if not isinstance(declaration, dict) or "expression" not in declaration:
            raise InputExpressionContractError("Invalid Variable declaration")
        projected["variables"][ident]["expression"] = visit(declaration["expression"])
    return projected, probes, seen


def validate_assessment(assessment):
    from ._v04_semantic.v04_variable_expressions import assessment_variable_expressions
    projected, probes, seen = project_assessment(assessment)
    if not seen:
        return assessment_variable_expressions(assessment)
    # Every numeric result cast must originate in a lexical *string* operand;
    # a consumer cannot demand integer and thereby authorize an implicit cast.
    for operand in probes:
        probe = deepcopy(projected)
        ident = "native-input-operand-probe-variable"
        while ident in probe["variables"]:
            ident = "native-input-" + ident
        probe["variables"][ident] = {"kind": "local", "expression": operand}
        types = assessment_variable_expressions(probe)
        if types[ident] != "string":
            raise InputExpressionContractError("to_integer requires a typed string operand")
    return assessment_variable_expressions(projected)


def install():
    from ._v04_semantic import validation
    if getattr(validation, "_native041_input_semantics_adapter", False):
        return
    original = validation.variable_expression_errors

    @wraps(original)
    def variable_expression_errors(document):
        assessment = document.get("assessment")
        if not isinstance(assessment, dict):
            yield from original(document)
            return
        try:
            # New forms get strict checked through an independently typed,
            # never-executed projection. Existing documents use the original
            # semantic validator with unchanged diagnostics.
            projected, _, seen = project_assessment(assessment)
            if not seen:
                yield from original(document)
                return
            validate_assessment(assessment)
        except (ValueError, KeyError, TypeError) as error:
            from jsonschema import ValidationError
            yield ValidationError("Native Input Variable expression: " + str(error),
                                  validator="native_input_expression")
    validation.variable_expression_errors = variable_expression_errors
    validation._native041_input_semantics_adapter = True
