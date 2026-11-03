"""Bounded OCIL single-choice questionnaire -> existing native manual contract.

No questionnaire evaluator or inferred answers. Only source-explicit, complete
choice/result mappings are admitted. Unsupported workflows remain traceable.
"""
import xml.etree.ElementTree as ET

OCIL_NS = 'http://scap.nist.gov/schema/ocil/2.0'
O = '{' + OCIL_NS + '}'
OUTCOMES = {'PASS': 'true', 'FAIL': 'false', 'ERROR': 'error',
            'UNKNOWN': 'unknown', 'NOT_TESTED': 'not_evaluated',
            'NOT_APPLICABLE': 'not_applicable'}


def manual_assessment(source, check, *, assessment_id, title):
    from v04_direct_scap_source import XCCDF, OCIL, attributes, ensure, digest, xml_identity
    attributes(check, {'system', 'selector'})
    ensure(check.get('system') == OCIL, 'not an OCIL check')
    refs = check.findall('{' + XCCDF + '}check-content-ref')
    inline=check.findall('{'+XCCDF+'}check-content')
    ensure(len(refs)==1 and len(inline)<=1 and len(check)==len(refs)+len(inline),
           'OCIL imports/exports or multiple references unsupported')
    ref = refs[0]; attributes(ref, {'href', 'name'})
    ensure(ref.get('href') in source.catalog, 'unresolved OCIL catalog reference')
    component = source.catalog[ref.get('href')]
    root = source.components[component]
    ensure(root.tag == O + 'ocil', 'OCIL catalog target has wrong kind')
    index = source.nodes[component]

    def target(ident, kind):
        ensure(ident in index and index[ident].tag == O + kind, 'unresolved/wrong-kind OCIL ' + kind)
        return index[ident]

    questionnaire = target(ref.get('name'), 'questionnaire')
    attributes(questionnaire, {'id'})
    ensure(all(n.tag in {O+'title', O+'description', O+'actions'} for n in questionnaire),
           'unsupported OCIL questionnaire metadata/workflow')
    actions = questionnaire.findall(O + 'actions')
    ensure(len(actions) == 1, 'OCIL questionnaire requires one actions group')
    actions = actions[0]; attributes(actions, {'operation'})
    ensure(actions.get('operation') in ('AND', 'OR') and len(actions) == 1
           and actions[0].tag == O + 'test_action_ref', 'compound OCIL workflow requires separate adapter')
    action = target(actions[0].text, 'choice_question_test_action')
    attributes(action, {'id', 'question_ref'})
    question = target(action.get('question_ref'), 'choice_question')
    attributes(question, {'id', 'default_answer_ref'})
    ensure(all(n.tag in {O+'question_text', O+'choice_group_ref'} for n in question),
           'unsupported OCIL question children')
    text = question.findall(O + 'question_text'); group_refs = question.findall(O + 'choice_group_ref')
    ensure(len(text) == len(group_refs) == 1 and not len(text[0]) and bool(text[0].text),
           'OCIL question requires one plain source procedure')
    if inline:
        ensure(not len(inline[0]) and text[0].text.strip().startswith((inline[0].text or '').strip()),
               'OCIL inline procedure differs from referenced question')
    group = target(group_refs[0].text, 'choice_group')
    attributes(group, {'id'})
    choices = {}; mappings = {}
    for choice in group:
        ensure(choice.tag == O+'choice', 'unsupported OCIL choice group member')
        attributes(choice, {'id'})
        ident = choice.get('id')
        ensure(ident and ident not in choices and len(choice) == 0 and bool(choice.text),
               'duplicate/complex/empty OCIL choice')
        choices[ident] = choice.text
    for when in action:
        if when.tag == O+'title': continue
        ensure(when.tag == O+'when_choice' and len(when) == 2
               and {n.tag for n in when} == {O+'result', O+'choice_ref'},
               'unsupported OCIL result branch')
        ident = when.findtext(O+'choice_ref'); result = when.findtext(O+'result')
        ensure(ident in choices and ident not in mappings and result in OUTCOMES,
               'unknown/duplicate OCIL choice or unsupported result')
        mappings[ident] = OUTCOMES[result]
    ensure(choices and set(choices) == set(mappings), 'incomplete OCIL answer mapping')
    default = question.get('default_answer_ref')
    ensure(default is None or default in choices, 'unresolved OCIL default answer')
    provenance = {'source_check_xml':ET.tostring(check,encoding='unicode'), 'component': component, 'questionnaire': questionnaire.get('id'),
                  'test_action': action.get('id'), 'question': question.get('id'),
                  'choice_group': group.get('id'), 'default_answer_ref': default,
                  'default_answer_applied': False,
                  'nodes': [{'id': n.get('id'), 'sha256': digest(xml_identity(n)),
                             'xml': ET.tostring(n, encoding='unicode')}
                            for n in (questionnaire, action, question, group)]}
    result = {'assessment': {'id': assessment_id, 'version': 1,
        'assessment_title': title, 'mode': 'manual', 'class': 'compliance',
        'procedure': text[0].text,
        'response': {'type': 'ocil-choice',
                     'choices': [{'value': key, 'label': label, 'outcome': mappings[key]}
                                 for key, label in choices.items()],
                     'allow_comment': True, 'allow_evidence': True},
        'references': [{'source_component': component,
                        'source_questionnaire': questionnaire.get('id')}],
        'evidence_guidance': None}}
    return result, provenance
