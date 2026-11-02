"""Original shell collection error controls, not Test matching requirements."""
from v04_direct_scap_source import attributes, ensure

ERROR_FLAGS = ('error_if_exit_status_not_0', 'error_if_stderr_exists')


def command_behaviors(element):
    """Optional original attributes -> explicit approved Boolean parameters.

    Both original defaults are false. True requests collection error evidence;
    it must never be lowered into an ordinary failed comparison or ignored.
    This function represents the contract; it does not execute commands.
    """
    values = {} if element is None else element.attrib
    if element is not None:
        attributes(element, set(ERROR_FLAGS))
        ensure(not len(element) and not (element.text or '').strip(), 'behaviors must have no content')
    result = {}
    for name in ERROR_FLAGS:
        value = values.get(name, 'false')
        ensure(value in ('true', 'false', '1', '0'), 'invalid command error-flag boolean: ' + name)
        result[name] = value in ('true', '1')
    return result
