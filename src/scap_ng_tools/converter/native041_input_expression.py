"""Native-only OVAL Input/function adapter; immutable visitor remains untouched.

The signed OL7 Rule has a policy-bound external string Input; local Variables
use substring with int result declarations before numeric arithmetic.
"""
from __future__ import annotations
from copy import deepcopy
from functools import wraps
from importlib import import_module


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
                element.get("datatype") != "int" or len(element) != 1 or
                local_name(element[0]) != "substring"):
            return result
        # The source local_variable datatype=int denotes an explicit lexical
        # result type boundary; substring itself returns a string.
        if not isinstance(result, dict) or set(result) != {"variable"}:
            raise ValueError("unexpected int substring Variable result")
        declaration = visitor.variables.get(result["variable"])
        if not isinstance(declaration, dict) or declaration.get("kind") != "local":
            raise ValueError("missing converted int substring Variable")
        expression = declaration["expression"]
        is_legacy = (isinstance(expression, dict) and "function" in expression and
                     isinstance(expression["function"], dict) and
                     expression["function"].get("name") == "substring")
        is_native = isinstance(expression, dict) and "substring" in expression
        if not (is_legacy or is_native):
            raise ValueError("OVAL integer substring lost source expression")
        declaration["expression"] = {"to_integer": expression}
        visitor.conversion_warnings.append({
            "code": "oval_local_int_substring_explicit_conversion",
            "source_variable": element.get("id"),
            "source_datatype": "int",
            "source_function": "substring",
            "semantic_basis": "OVAL local_variable int result explicitly converts substring's decimal lexical value",
            "independent_static_proof": "UNPROVED",
            "scanner_evaluated": False,
        })
        return result

    converter.function = function
    converter.convert_variable = convert_variable
    converter._native041_input_expression_adapter = True
