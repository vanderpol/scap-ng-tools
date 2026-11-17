"""Version-local structural + semantic checks matching original 0.4 admission.

No previous-version generators, implicit datatype inference, or independent
scanner/proof claims are involved. The original 0.4 semantic passes are kept
in separate auditable modules with a pinned compiled capability-contract pack.
"""

from collections import deque
from functools import lru_cache

from jsonschema import Draft202012Validator, ValidationError
from referencing import Registry

from . import schema_resources, selected_schema
from .v04_object_contract import object_errors
from .v04_comparison_types import comparison_errors
from .v04_variable_expressions import variable_expression_errors


@lru_cache(maxsize=36)
def validator(schema_root, kind):
    root = schema_root
    from json import loads
    from pathlib import Path
    schema = loads((Path(root) / (kind + '.schema.json')).read_bytes())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema,
        registry=Registry().with_resources(schema_resources(root).items()))


def document_errors(snapshot, kind, document):
    """Return the original order and wording of 0.4.1 validation diagnostics."""
    with selected_schema(snapshot):
        yield from validator(str(snapshot.schema_root), kind).iter_errors(document)
        if kind != 'assessment':
            return
        yield from object_errors(document)
        yield from comparison_errors(document)
        yield from variable_expression_errors(document)
        assessment = document.get('assessment')
        if not isinstance(assessment, dict) or assessment.get('mode') != 'manual':
            return
        response = assessment.get('response')
        if not isinstance(response, dict) or not isinstance(response.get('choices'), list):
            return
        seen = {}
        for index, choice in enumerate(response['choices']):
            if not isinstance(choice, dict) or not isinstance(choice.get('value'), str):
                continue
            value = choice['value']
            if value in seen:
                yield ValidationError(
                    f'Duplicate manual response value {value!r}; first declared at choices/{seen[value]}',
                    validator='unique_response_value',
                    path=deque(['assessment', 'response', 'choices', index, 'value']))
            else:
                seen[value] = index
