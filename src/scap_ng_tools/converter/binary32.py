"""Finite-expected binary32 comparison contract; not a scanner/evaluator.

Decimal lexical conversion uses exact integer ratios and round-to-nearest,
ties-to-even. A binary64 intermediate would double-round valid source values.
Nonfinite observed encodings are internal bits, never native JSON operands.
"""
from decimal import Decimal
import math
from pathlib import Path
import re
import struct
from hashlib import sha256

CONTRACT_ID = 'scap-ng-0.4.0-binary32-comparisons/1'
CONTRACT_SHA256 = '676dfd1bbe1e83e781e68c9c66fd4e53ed6f9da4278affbd0a877edf49ab03dd'
OPERATIONS = frozenset(('equals', 'not_equal', 'greater_than', 'greater_than_or_equal',
                        'less_than', 'less_than_or_equal'))
LEXICAL = re.compile(r'[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?\Z')


def require_contract(schema_root):
    path = Path(schema_root).parent / 'docs/metadata/binary32-comparison-contract.json'
    if path.is_symlink() or not path.is_file() or sha256(path.read_bytes()).hexdigest() != CONTRACT_SHA256:
        raise ValueError('exact owner-authorized binary32 comparison contract required')
    return {'id': CONTRACT_ID, 'sha256': CONTRACT_SHA256}


def lexical_bits(text):
    """OVAL/W3C lexical float → binary32 bits; malformed values raise errors."""
    if not isinstance(text, str):
        raise ValueError('binary32 lexical value must be text')
    text = text.strip(' \t\r\n')
    if text in ('INF', '-INF', 'NaN'):
        return {'INF': 0x7f800000, '-INF': 0xff800000, 'NaN': 0x7fc00000}[text]
    if not LEXICAL.fullmatch(text):
        raise ValueError('invalid OVAL binary32 lexical value')
    # Bound enormous lexical exponents before Decimal's implementation limit.
    # The exponent dominates any possible mantissa length in this input.
    mantissa, _, exponent_text = text.lower().partition('e')
    if exponent_text:
        digits = exponent_text.lstrip('+-').lstrip('0') or '0'
        limit = str(len(mantissa) + 100)
        if len(digits) > len(limit) or (len(digits) == len(limit) and digits > limit):
            sign = int(text.startswith('-')) << 31
            nonzero = any(c in '123456789' for c in mantissa)
            return sign | (0x7f800000 if nonzero and not exponent_text.startswith('-') else 0)
    value = Decimal(text)
    sign = int(value.is_signed()) << 31
    value = value.copy_abs()
    if value.is_zero() or value.adjusted() < -46:
        return sign
    if value.adjusted() >= 39:
        return sign | 0x7f800000
    numerator, denominator = value.as_integer_ratio()
    exponent = numerator.bit_length() - denominator.bit_length()
    if (numerator < denominator << exponent if exponent >= 0
            else numerator << -exponent < denominator):
        exponent -= 1
    quantum = max(exponent - 23, -149)
    if quantum < 0:
        numerator <<= -quantum
    else:
        denominator <<= quantum
    significand, remainder = divmod(numerator, denominator)
    if 2 * remainder > denominator or (2 * remainder == denominator and significand & 1):
        significand += 1
    if significand < 1 << 23:  # zero/subnormal, quantum == -149
        return sign | significand
    exponent = significand.bit_length() - 1 + quantum
    if exponent >= 128:
        return sign | 0x7f800000
    significand >>= max(significand.bit_length() - 24, 0)
    return sign | ((exponent + 127) << 23) | (significand - (1 << 23))


def finite_literal(text):
    """Source lexical → exact finite binary32 value in the JSON number domain."""
    bits = lexical_bits(text)
    if bits & 0x7f800000 == 0x7f800000:
        raise ValueError('nonfinite expected binary32 operand remains blocked')
    return struct.unpack('!f', bits.to_bytes(4, 'big'))[0]


def expected_bits(value):
    """Validate canonical finite native numeric operands; never coerce strings."""
    if type(value) not in (int, float) or (isinstance(value, float) and not math.isfinite(value)):
        raise ValueError('finite canonical binary32 expected number required')
    # Decimal.from_float preserves the host value exactly. Canonical expected
    # operands must already be binary32 values; no second lexical interpretation.
    text = str(value) if isinstance(value, int) else str(Decimal.from_float(value))
    bits = lexical_bits(text)
    if bits & 0x7f800000 == 0x7f800000:
        raise ValueError('nonfinite expected binary32 operand remains blocked')
    represented = struct.unpack('!f', bits.to_bytes(4, 'big'))[0]
    if represented != value:
        raise ValueError('expected number is not canonical binary32; convert exact source lexical value first')
    return bits


def compare_observed(text, operation, expected):
    """Small comparison reference oracle only; no collection/Result evaluation."""
    if operation not in OPERATIONS:
        raise ValueError('unsupported binary32 operation')
    left, right = lexical_bits(text), expected_bits(expected)
    if left & 0x7fffffff > 0x7f800000:  # NaN against finite expected operand.
        return operation == 'not_equal'
    if left & 0x7fffffff == 0 and right & 0x7fffffff == 0:
        order = 0
    else:
        def key(bits):
            return ~bits & 0xffffffff if bits >> 31 else bits | 0x80000000
        order = (key(left) > key(right)) - (key(left) < key(right))
    return {'equals': order == 0, 'not_equal': order != 0, 'greater_than': order > 0,
            'greater_than_or_equal': order >= 0, 'less_than': order < 0,
            'less_than_or_equal': order <= 0}[operation]
