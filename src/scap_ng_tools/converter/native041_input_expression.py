"""Native-only OVAL Input/function adapter; immutable visitor remains untouched.

The signed OL7 Rule has a policy-bound external string Input; local Variables
use substring with int result declarations before numeric arithmetic.
"""
from __future__ import annotations
from copy import deepcopy
from functools import wraps
from importlib import import_module


_STRING_OPERATIONS = frozenset({
    "concat", "merge", "split", "substring", "begin", "end",
    "regex_capture", "escape_regex", "glob_to_regex",
})


def _mapping_field_types(visitor, expression):
    """Return the admitted native Item datatype set for a values expression."""
    if not isinstance(expression, dict) or set(expression) != {"values"}:
        return None
    values = expression["values"]
    if not isinstance(values, dict) or set(values) != {"object", "field"}:
        return None
    obj, field = values["object"], values["field"]
    if not isinstance(obj, dict) or not isinstance(field, str):
        return None
    capability = obj.get("capability")
    if not isinstance(capability, str):
        # A shared Object reference has no local mapping here. Do not infer a
        # cast from the consumer's predicate; leave the conversion held.
        return None
    for mapping in getattr(visitor, "mappings", ()):
        if mapping.get("capability") != capability:
            continue
        return mapping.get("native", {}).get("field_datatypes", {}).get(field)
    return None


def _needs_explicit_integer_conversion(visitor, expression, active=None):
    """Prove that an OVAL int Variable expression is lexical/string-valued.

    OVAL local_variable/@datatype is source truth for the result boundary, but
    SCAP-NG 0.4.1 requires an explicit operation when a string population is
    converted to integer. This helper only casts admitted string-producing
    expressions; an unknown or already-integer graph remains untouched and is
    therefore held rather than guessed.
    """
    if not isinstance(expression, dict) or len(expression) != 1:
        return False
    active = set() if active is None else set(active)
    operation, value = next(iter(expression.items()))
    if operation == "to_integer":
        return False
    if operation == "literal":
        return isinstance(value, dict) and value.get("datatype") == "string"
    if operation == "values":
        types = _mapping_field_types(visitor, expression)
        return types is not None and types != ["integer"]
    if operation == "input":
        return isinstance(value, str) and bool(value)
    if operation in _STRING_OPERATIONS:
        return True
    if operation == "function":
        return (isinstance(value, dict) and
                value.get("name") in _STRING_OPERATIONS)
    if operation == "unique":
        children = value if isinstance(value, list) else [value]
        return any(_needs_explicit_integer_conversion(visitor, child, active)
                   for child in children)
    if operation == "variable":
        identifier = value
        if not isinstance(identifier, str) or identifier in active:
            return False
        declaration = getattr(visitor, "variables", {}).get(identifier)
        if not isinstance(declaration, dict):
            return False
        active.add(identifier)
        return _needs_explicit_integer_conversion(
            visitor, declaration.get("expression"), active)
    # count, time_difference, arithmetic and all unknown expressions are not
    # lexical string witnesses. Their own typed operation/result boundary must
    # be validated, not silently converted by the source declaration.
    return False


def install(engine):
    converter = engine.AssessmentConverter
    if getattr(converter, "_native041_input_expression_adapter", False):
        return

    migration = import_module("v04_variable_function_migration")
    original_canonical = migration.canonical_expression

    @wraps(original_canonical)
    def canonical_expression(node, *, allow_existing=False):
        if isinstance(node, dict) and len(node) == 1:
            if "input" in node:
                name = node["input"]
                if isinstance(name, str) and name.endswith("-input") and name:
                    return deepcopy(node)
                raise migration.UnsupportedExpression("invalid Assessment Input reference")
            if "to_integer" in node:
                return {"to_integer": canonical_expression(
                    node["to_integer"], allow_existing=allow_existing)}
        return original_canonical(node, allow_existing=allow_existing)

    migration.canonical_expression = canonical_expression
    original_function = converter.function
    original_convert_variable = converter.convert_variable

    @wraps(original_function)
    def function(visitor, element):
        if (not getattr(visitor, "native_recovery", False) or
                element.tag != "{%s}variable_component" % engine.OVAL):
            return original_function(visitor, element)
        from v04_direct_scap_source import attributes, ensure, local_name
        ident = element.get("var_ref")
        if not ident:
            return original_function(visitor, element)
        source = visitor.source.node(visitor.component_id, ident, "variable")
        if local_name(source) != "external_variable":
            return original_function(visitor, element)
        attributes(element, {"var_ref"})
        ensure(not len(element), "variable_component has children")
        value = visitor.reference(ident, "variable")
        ensure(isinstance(value, dict) and set(value) == {"input"} and
               isinstance(value["input"], str) and value["input"].endswith("-input"),
               "unbound or malformed native Assessment Input function operand")
        # Policy-bound Input remains dynamic: never copy XCCDF publisher default.
        return {"input": value["input"]}

    @wraps(original_convert_variable)
    def convert_variable(visitor, element):
        result = original_convert_variable(visitor, element)
        from v04_direct_scap_source import local_name
        if (not getattr(visitor, "native_recovery", False) or
                local_name(element) != "local_variable" or
                element.get("datatype") != "int" or len(element) != 1):
            return result
        # The source local_variable datatype=int is an explicit lexical result
        # boundary. Emit canonical to_integer only when the generated expression
        # proves a string population; never cast an unknown or integer graph.
        if not isinstance(result, dict) or set(result) != {"variable"}:
            raise ValueError("unexpected int Variable result")
        declaration = visitor.variables.get(result["variable"])
        if not isinstance(declaration, dict) or declaration.get("kind") != "local":
            raise ValueError("missing converted int Variable")
        expression = declaration.get("expression")
        if not _needs_explicit_integer_conversion(visitor, expression):
            return result
        if isinstance(expression, dict) and "to_integer" in expression:
            return result
        declaration["expression"] = {"to_integer": expression}
        operation = next(iter(expression), "unknown") if isinstance(expression, dict) else "unknown"
        visitor.conversion_warnings.append({
            "code": ("oval_local_int_substring_explicit_conversion"
                     if operation == "substring" else
                     "oval_local_int_explicit_conversion"),
            "source_variable": element.get("id"),
            "source_datatype": "int",
            "source_operation": operation,
            "semantic_basis": "OVAL local_variable int result explicitly converts an admitted string lexical population",
            "independent_static_proof": "SOURCE_DECLARED_RESULT_BOUNDARY_AND_NATIVE_STRING_DOMAIN",
            "scanner_evaluated": False,
        })
        return result

    converter.function = function
    converter.convert_variable = convert_variable
    converter._native041_input_expression_adapter = True
