"""Adapt original converter function envelopes to the sole active 0.4.1 grammar.

This layer runs *after* the provenance-pinned OVAL visitor and *before* native
semantic validation. No source XML or visitor is changed. It never evaluates
values, discards components, or claims scanner equivalence.
"""
from copy import deepcopy


LEAVES = {"literal", "variable", "values"}
UNARY = {"split", "substring", "begin", "end"}
FUNCTION_NAMES = {"count", "arithmetic", *UNARY, "unique", "concat", "merge", "regex_capture"}


def _required(condition, diagnostic):
    if not condition:
        raise ValueError(diagnostic)


def _source_text_projection(operand):
    """Make an inherited source lexical conversion visible in native authoring.

    The one-element empty prefix maps each collected scalar to a string without
    dropping duplicates, reordering values, or changing population cardinality.
    Only collected-field projections receive this adapter; a typed literal,
    Variable reference, or already explicit expression is never rewritten.
    Native evaluation must still reject non-scalar evidence and propagate
    missing/error/incomplete collection statuses.
    """
    if isinstance(operand, dict) and "values" in operand:
        return {"concat": [{"literal": ""}, operand]}
    return operand


def lower_expression(node):
    """Return a new 0.4.1 expression, or reject an unrepresentable source."""
    _required(isinstance(node, dict) and len(node) == 1,
              "Variable expression must have exactly one operator")
    operation, value = next(iter(node.items()))
    if operation in LEAVES:
        return deepcopy(node)
    if operation == "function":
        _required(isinstance(value, dict) and set(value) == {"name", "arguments", "options"},
                  "legacy function envelope has unexpected members")
        name, args, options = value["name"], value["arguments"], value["options"]
        _required(name in FUNCTION_NAMES and isinstance(args, list) and
                  isinstance(options, dict), "unsupported native function envelope")
        children = [lower_expression(child) for child in args]
        if name == "count":
            _required(not options, "count has unsupported source options")
            _required(len(children) == 1,
                      "multi-component OVAL count has no lossless native 0.4.1 mapping")
            return {"count": children[0]}
        if name == "arithmetic":
            _required(len(children) >= 2 and set(options) == {"arithmetic_operation"} and
                      options["arithmetic_operation"] in {"add", "multiply"},
                      "unsupported arithmetic arity or operation")
            return {"arithmetic": {
                "arithmetic_operation": options["arithmetic_operation"], "values": children}}
        if name in UNARY:
            required = ({"delimiter"} if name == "split" else
                        {"substring_start", "substring_length"} if name == "substring" else
                        {"character"})
            _required(len(children) == 1 and set(options) == required,
                      name + " requires exactly one operand and explicit options")
            operand = children[0]
            if name in {"split", "substring"}:
                operand = _source_text_projection(operand)
            return {name: {**deepcopy(options), "value": operand}}
        if name == "unique":
            _required(len(children) >= 1 and not options, "unique source arity/options invalid")
            # The source OVAL unique function returns lexical strings, while
            # native unique intentionally preserves the datatype of its input.
            # Expose the source conversion for direct collected-field operands
            # rather than silently guessing a type for a 12-domain Item field.
            # Non-text literals and referenced Variables remain fail-closed.
            source_children = [_source_text_projection(child) for child in children]
            return {"unique": source_children if len(source_children) > 1 else source_children[0]}
        if name == "concat":
            _required(len(children) >= 2 and not options, "concat source arity/options invalid")
            return {"concat": children}
        if name == "merge":
            _required(len(children) >= 1 and set(options) == {"delimiter", "sort", "order"},
                      "merge source arity/options invalid")
            return {"merge": {**deepcopy(options),
                              "values": children if len(children) > 1 else children[0]}}
        if name == "regex_capture":
            _required(len(children) == 1 and set(options) == {"pattern"},
                      "regex_capture source arity/options invalid")
            return {"regex_capture": {"pattern": options["pattern"], "value": children[0]}}
        raise ValueError("unhandled source function: " + name)

    if operation == "count":
        return {"count": lower_expression(value)}
    if operation == "unique":
        return {"unique": ([lower_expression(v) for v in value] if isinstance(value, list)
                           else lower_expression(value))}
    if operation == "concat":
        _required(isinstance(value, list) and len(value) >= 2, "concat requires ordered operands")
        return {"concat": [lower_expression(v) for v in value]}
    if operation in UNARY | {"regex_capture"}:
        _required(isinstance(value, dict) and "value" in value, operation + " needs value")
        operand = lower_expression(value["value"])
        if operation in {"split", "substring"}:
            operand = _source_text_projection(operand)
        return {operation: {**deepcopy(value), "value": operand}}
    if operation in {"merge", "arithmetic"}:
        _required(isinstance(value, dict) and "values" in value, operation + " needs values")
        operands = value["values"]
        if operation == "arithmetic":
            _required(isinstance(operands, list) and len(operands) >= 2,
                      "arithmetic requires multiple operands")
        return {operation: {**deepcopy(value), "values": (
            [lower_expression(v) for v in operands] if isinstance(operands, list)
            else lower_expression(operands))}}
    raise ValueError("unsupported native Variable expression: " + str(operation))


def lower_assessment_inplace(document):
    """Atomically migrate Variable expression ASTs in one generated Assessment.

    The original OVAL identity/provenance is retained by the caller. A failed
    expression leaves this Assessment unmodified, so it may be reported blocked.
    """
    assessment = document.get("assessment") if isinstance(document, dict) else None
    if not isinstance(assessment, dict):
        return False
    variables = assessment.get("variables", {})
    if not isinstance(variables, dict):
        return False  # The canonical schema reports this structural error.
    replacements = {}
    for name, declaration in variables.items():
        if isinstance(declaration, dict) and isinstance(declaration.get("expression"), dict):
            replacements[name] = lower_expression(declaration["expression"])
    changed = False
    for name, expression in replacements.items():
        old = variables[name]["expression"]
        if old != expression:
            variables[name]["expression"] = expression
            changed = True
    return changed
