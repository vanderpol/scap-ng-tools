"""Lossless manual projection for Rules whose source check is OCIL-only.

The projection intentionally does not pretend to execute OCIL.  The original
check XML identity, selection, and component/name reference are retained in the
binding trace; the generated Assessment is a human procedure with explicit
outcomes.  OCIL alternatives on an OVAL Rule are emitted as a non-default
choice and therefore can never make automation mandatory.
"""
from __future__ import annotations

from copy import deepcopy


def _choice_assessment(source, rule, check, *, assessment_id, title):
    from v04_direct_scap_source import XCCDF, OCIL, attributes, digest, ensure, xml_identity

    attributes(check, {'system', 'selector'})
    ensure(check.get('system') == OCIL and check.get('selector', '') in ('', 'manual'),
           'OCIL check must be manual')
    refs = check.findall('{' + XCCDF + '}check-content-ref')
    inline = check.findall('{' + XCCDF + '}check-content')
    # Do not parse or invent a questionnaire graph.  OCIL workflows are
    # preserved in provenance and represented by a bounded human procedure.
    ensure(len(refs) <= 1 and len(inline) <= 1 and len(check) == len(refs) + len(inline),
           'OCIL imports/exports or compound check are not a bounded manual projection')
    reference = None
    if refs:
        reference = refs[0]
        attributes(reference, {'href', 'name'})
        ensure(reference.get('href') in source.catalog, 'unresolved OCIL catalog reference')
        component = source.catalog[reference.get('href')]
        ensure(component in source.components, 'unresolved OCIL component')
    else:
        component = None
    body = ''
    if inline and inline[0].text:
        body = inline[0].text.strip()
    if not body and reference:
        body = f'Complete the source OCIL procedure {reference.get("name")}.'
    if not body:
        body = 'Complete the source OCIL procedure and record the result.'
    procedure = (
        'Manual alternative preserved from the original OCIL check. '
        'Follow the source procedure; this Assessment does not execute OCIL.\n\n' + body
    )
    assessment = {'assessment': {
        'id': assessment_id, 'version': 1, 'assessment_title': title,
        'mode': 'manual', 'class': 'compliance', 'procedure': procedure,
        'response': {'type': 'ocil-manual', 'choices': [
            {'value': 'true', 'label': 'Pass', 'outcome': 'true'},
            {'value': 'false', 'label': 'Fail', 'outcome': 'false'},
            {'value': 'not_applicable', 'label': 'Not applicable', 'outcome': 'not_applicable'},
            {'value': 'unknown', 'label': 'Unable to determine', 'outcome': 'unknown'},
        ], 'allow_comment': True, 'allow_evidence': True},
        'references': ([{'source_component': component,
                         'source_check_ref': reference.get('name'),
                         'source_catalog_ref': reference.get('href')}] if reference else []),
        'evidence_guidance': 'Retain the completed source OCIL evidence and reviewer notes.'
    }}
    provenance = {
        'selection': {'system': OCIL, 'selector': check.get('selector', '')},
        'source_check_sha256': digest(xml_identity(check)),
        'source_check_identity': xml_identity(check),
        'source_catalog_ref': reference.get('href') if reference else None,
        'source_content_ref': reference.get('name') if reference else None,
        'source_component': component,
        'projection': 'manual_assessment',
        'automated_equivalent': False,
    }
    return assessment, provenance


def manual_rule(source, rule, *, title, rule_id, assessment_id):
    """Return one native Rule and one manual Assessment for an OCIL Rule."""
    from v04_direct_scap_source import XCCDF, OCIL, digest, ensure, xml_identity

    checks = [check for check in rule.findall('{' + XCCDF + '}check')
              if check.get('system') == OCIL]
    ensure(checks, 'manual projection requires an OCIL check')
    # A manual Rule may carry multiple OCIL checks.  Keep one native manual
    # Assessment (the Rule still has one manual choice) while concatenating
    # each source procedure and retaining every source check identity.  No
    # Boolean OCIL workflow is inferred.
    projections = [_choice_assessment(source, rule, check,
                                      assessment_id=assessment_id, title=title)
                   for check in checks]
    assessment, provenance = projections[0]
    for extra, extra_provenance in projections[1:]:
        assessment['assessment']['procedure'] += '\n\n' + extra['assessment']['procedure']
        assessment['assessment']['references'].extend(extra['assessment'].get('references', []))
        provenance.setdefault('additional_source_checks', []).append(extra_provenance)
    native_rule = {'id': rule_id, 'version': rule.findtext('{' + XCCDF + '}version', ''),
        'title': title, 'severity': rule.get('severity', 'unknown'), 'role': 'full',
        'weight': float(rule.get('weight', '1')), 'discussion': rule.findtext('{' + XCCDF + '}description', ''),
        'requires': [], 'conflicts': [], 'applicability': [], 'parameters': {},
        'remediation': {}, 'organizational_input_requirements': {},
        'assessment_choices': {'manual': {'assessment': assessment_id}},
        'default_assessment_choice': 'manual'}
    if not native_rule['discussion']:
        native_rule.pop('discussion')
    binding = {'source_rule': rule.get('id'),
        'source_rule_sha256': digest(xml_identity(rule)), 'native_rule': rule_id,
        'assessment': assessment_id, 'conversion_status': 'MANUAL_ONLY_PRESERVED',
        'manual_provenance': provenance, 'source_checks': [xml_identity(check) for check in checks]}
    return ({f'authoring/direct-slice/assessments/{assessment_id}.json': assessment,
             f'authoring/direct-slice/rules/{rule_id}.json': {'rule': native_rule}}, binding)
