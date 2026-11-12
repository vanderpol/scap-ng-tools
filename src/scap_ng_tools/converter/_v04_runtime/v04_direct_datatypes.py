"""Approved OVAL/native datatype identities; no comparison evaluation.

String-based special types keep their exact lexical values and select the
already-approved typed comparison operator. Float expected values use the
owner-coordinated finite IEEE-754 binary32 contract only in native recovery
mode: decimal text is rounded directly from an exact rational, never through a
binary64 intermediate. Runtime comparison and status propagation remain
outside this converter.
"""
from decimal import Decimal, InvalidOperation
import re
import struct

from v04_direct_scap_source import UnsupportedSource, ensure

SOURCE_TYPES = {
    'string': 'string', 'int': 'integer', 'boolean': 'boolean', 'float': 'float',
    'binary': 'binary', 'version': 'version',
    'evr_string': 'rpm_evr', 'debian_evr_string': 'debian_evr',
    'fileset_revision': 'fileset_revision', 'ios_version': 'ios_version',
    'ipv4_address': 'ipv4', 'ipv6_address': 'ipv6',
}
SPECIAL_TYPES = {key: value for key, value in SOURCE_TYPES.items()
                 if key not in ('string', 'int', 'boolean')}
ORDERED = frozenset({'equals', 'not equal', 'greater than', 'greater than or equal',
                     'less than', 'less than or equal'})
SPECIAL_OPERATIONS = {name: ORDERED for name in SPECIAL_TYPES}
SPECIAL_OPERATIONS.update(binary=frozenset({'equals', 'not equal'}),
    ipv4_address=ORDERED | {'subset of', 'superset of'},
    ipv6_address=ORDERED | {'subset of', 'superset of'})
FLOAT_LEXICAL = re.compile(
    r'[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?\Z')


def _round_division(numerator, denominator):
    """Round a nonnegative rational to nearest integer, ties to even."""
    quotient, remainder = divmod(numerator, denominator)
    twice = remainder * 2
    if twice > denominator or (twice == denominator and quotient & 1):
        quotient += 1
    return quotient


def _binary32_bits(decimal_value):
    """Return exact IEEE-754 binary32 bits for a finite Decimal."""
    sign = 0x80000000 if decimal_value.is_signed() else 0
    value = decimal_value.copy_abs()
    if value.is_zero():
        return sign
    # Avoid constructing a million-digit rational for values that are
    # unambiguously outside the binary32 range. Values near subnormal limits
    # still go through the exact-rational path.
    adjusted = value.adjusted()
    if adjusted > 38:
        raise UnsupportedSource('float literal overflows finite binary32 expected domain')
    if adjusted < -47:
        return sign
    numerator, denominator = value.as_integer_ratio()
    # floor(log2(numerator / denominator)), computed without host floats.
    exponent = numerator.bit_length() - denominator.bit_length()
    if exponent >= 0 and numerator < denominator << exponent:
        exponent -= 1
    elif exponent < 0 and (numerator << -exponent) < denominator:
        exponent -= 1
    if exponent >= -126:
        shift = 23 - exponent
        # Keep the rational exact when the significand scale is negative;
        # shifting the numerator right would discard rounding bits.
        scaled = numerator << shift if shift >= 0 else numerator
        divisor = denominator if shift >= 0 else denominator << -shift
        significand = _round_division(scaled, divisor)
        if significand >= 1 << 24:
            significand >>= 1
            exponent += 1
        if exponent > 127:
            raise UnsupportedSource('float literal overflows finite binary32 expected domain')
        bits = ((exponent + 127) << 23) | (significand - (1 << 23))
    else:
        # Subnormal value = significand * 2^-149. Rounding here also handles
        # a result that becomes the minimum normal or signed zero.
        significand = _round_division(numerator << 149, denominator)
        if significand >= 1 << 23:
            bits = 1 << 23
        else:
            bits = significand
    return sign | bits


def binary32_bits(text):
    """Parse finite OVAL float text and return its exact binary32 bit pattern."""
    lexical = (text or '').strip(' \t\r\n')
    ensure(FLOAT_LEXICAL.fullmatch(lexical) is not None,
           f'invalid float lexical form: {text!r}')
    try:
        value = Decimal(lexical)
    except InvalidOperation as error:
        raise UnsupportedSource(f'invalid float literal: {text!r}') from error
    return _binary32_bits(value)


def binary32_literal(text):
    """Return a JSON-safe Python number representing exact binary32 bits."""
    bits = binary32_bits(text)
    # Every finite binary32 value is exactly representable in binary64. This is
    # only serialization of the already-rounded bits, not the conversion path.
    value = struct.unpack('>f', struct.pack('>I', bits))[0]
    if bits & 0x7f800000 == 0x7f800000:
        raise UnsupportedSource('nonfinite float expected value is unsupported')
    return value


def native_datatype(source_type):
    ensure(source_type in SOURCE_TYPES, f'unsupported Variable datatype: {source_type}')
    return SOURCE_TYPES[source_type]


def literal(source_type, text, *, binary32=False):
    """Convert source lexical forms with an approved native representation."""
    ensure(source_type in SOURCE_TYPES, f'unsupported scalar datatype: {source_type}')
    if source_type == 'boolean':
        ensure(text in ('true', 'false', '1', '0'), 'invalid boolean literal')
        return text in ('true', '1')
    if source_type == 'float':
        ensure(binary32, 'float literal requires the native binary32 recovery contract')
        return binary32_literal(text)
    try:
        return int(text) if source_type == 'int' else text
    except ValueError as error:
        raise UnsupportedSource(f'invalid {source_type} literal: {text!r}') from error


def comparison(source_type, operation, generic):
    """Keep the source algorithm as a self-describing native typed operator."""
    if source_type not in SPECIAL_TYPES:
        ensure(operation not in ('subset of', 'superset of'), 'address operation requires address datatype')
        ensure(operation not in ('bitwise and', 'bitwise or') or source_type == 'int',
               'bitwise operation requires integer datatype')
        return generic
    ensure(operation in SPECIAL_OPERATIONS[source_type],
           f'unsupported typed comparison: {source_type} {operation}')
    return SPECIAL_TYPES[source_type] + '_' + generic
