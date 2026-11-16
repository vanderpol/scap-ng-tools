"""Source-independent Variable result typing adapter for native 0.4.1.

The provenance-pinned OVAL visitor remains byte-identical. This adapter is
installed in memory at the production converter boundary and only corrects the
expected-value lexical boundary for a Variable Test whose OVAL declaration
contradicts its function's result type. It never changes source XML, collected
Item types, or evaluator semantics.
"""
from __future__ import annotations

from copy import deepcopy
from functools import wraps

STRING_FUNCTIONS = frozenset({
    "concat", "merge", "split", "substring", "begin", "end",
    "regex_capture", "escape_regex", "glob_to_regex", "unique",
})
INTEGER_FUNCTIONS = frozenset({"time_difference", "count", "arithmetic"})


def result_type(variable):
    """Return the native result type of a one-expression OVAL Variable."""
    declared = variable.get("datatype", "")
    children = list(variable)
    if len(children) != 1:
        return declared
    operation = children[0].tag.rsplit("}", 1)[-1]
    if operation in INTEGER_FUNCTIONS:
        return "int"
    if operation in STRING_FUNCTIONS:
        return "string"
    if operation == "literal_component":
        # OVAL leaves literal_component/@datatype optional. In that form the
        # enclosing local_variable declaration supplies the source datatype;
        # defaulting to string would turn an authored integer into an invalid
        # native comparison during Test conversion.
        return children[0].get("datatype") or declared
    # Variable/Object components retain their declaration type until an
    # approved source-bound projection proves otherwise.
    return declared


def _variable_ref_for_test(visitor, element):
    """Find one variable Object reference without interpreting source state."""
    try:
        mapping = visitor.capability(element, "test")
        objects = [child for child in element
                   if child.tag == "{%s}%s" % (mapping["source"]["namespace"], "object")]
        if len(objects) != 1:
            return None
        object_source = visitor.source.node(visitor.component_id, objects[0].get("object_ref"), "object")
        if object_source.tag.rsplit("}", 1)[-1] != "variable_object":
            return None
        refs = [child.text.strip() for child in object_source
                if child.tag.rsplit("}", 1)[-1] == "var_ref" and (child.text or "").strip()]
        return refs[0] if len(refs) == 1 else None
    except (AttributeError, KeyError, TypeError, ValueError):
        return None


def install(engine):
    """Install the bounded adapter once on the loaded visitor class."""
    converter = engine.AssessmentConverter
    if getattr(converter, "_native041_result_type_adapter", False):
        return
    original = converter.convert_test

    @wraps(original)
    def convert_test(visitor, element):
        if not getattr(visitor, "native_recovery", False):
            return original(visitor, element)
        variable_ref = _variable_ref_for_test(visitor, element)
        if not variable_ref:
            return original(visitor, element)
        source = visitor.source
        original_node = source.node
        variable = original_node(visitor.component_id, variable_ref, "variable")
        native_type = result_type(variable)
        if native_type == variable.get("datatype", ""):
            return original(visitor, element)
        # The copied visitor consults only this declaration's datatype while
        # parsing the Test State value. Give that lookup an in-memory clone with
        # the expression result type, then restore the source boundary exactly.
        replacement = deepcopy(variable)
        replacement.set("datatype", native_type)

        def node(component, identifier, kind):
            if component == visitor.component_id and identifier == variable_ref and kind == "variable":
                return replacement
            return original_node(component, identifier, kind)

        source.node = node
        try:
            result = original(visitor, element)
            visitor.conversion_warnings.append({
                "code": "oval_variable_declared_datatype_differs_from_expression_result",
                "source_variable": variable_ref,
                "declared_datatype": variable.get("datatype"),
                "expression_result_datatype": native_type,
                "semantic_basis": "native expression result type governs SCAP-NG 0.4.1; OVAL declaration retained as provenance",
                "independent_static_proof": "SOURCE_EXPRESSION_RESULT_TYPE",
            })
            return result
        finally:
            source.node = original_node

    converter.convert_test = convert_test
    converter._native041_result_type_adapter = True
