#!/usr/bin/env python3
"""Offline structural audit only; does not invoke the TA or prove vendor compatibility."""
import argparse
import hashlib
import json
from pathlib import Path


def decode(data, pos=0, depth=0):
    if depth > 32 or pos >= len(data):
        raise ValueError('CBOR truncated or nesting limit exceeded')
    head = data[pos]
    pos += 1
    major, ai = head >> 5, head & 31
    if ai < 24:
        n = ai
    elif ai in (24, 25, 26, 27):
        width = 1 << (ai - 24)
        if pos + width > len(data):
            raise ValueError('CBOR truncated argument')
        n = int.from_bytes(data[pos:pos + width], 'big')
        pos += width
    else:
        raise ValueError('Indefinite/reserved CBOR encoding not supported by auditor')
    if major in (0, 1):
        return (n if major == 0 else -1 - n), pos
    if major in (2, 3):
        if pos + n > len(data):
            raise ValueError('CBOR truncated string')
        value = data[pos:pos + n]
        return (value if major == 2 else value.decode('utf-8')), pos + n
    if major in (4, 5):
        if n > len(data):
            raise ValueError('CBOR excessive container size')
        values = []
        for _ in range(n * (2 if major == 5 else 1)):
            value, pos = decode(data, pos, depth + 1)
            values.append(value)
        if major == 4:
            return values, pos
        pairs = list(zip(values[::2], values[1::2]))
        if any(not isinstance(k, int) or isinstance(k, bool) for k, _ in pairs):
            raise ValueError('Auditor requires integer map labels')
        if len({k for k, _ in pairs}) != len(pairs):
            raise ValueError('Duplicate CBOR map label')
        return dict(pairs), pos
    if major == 7 and ai in (20, 21, 22):
        return {20: False, 21: True, 22: None}[ai], pos
    raise ValueError('Unsupported CBOR type in auditor')


def exact(data):
    value, end = decode(data)
    if end != len(data):
        raise ValueError('CBOR trailing bytes')
    return value


def describe(value):
    result = {'type': type(value).__name__}
    if isinstance(value, (bytes, str, list, dict)):
        result['length'] = len(value)
    if isinstance(value, int):
        result['value'] = value
    return result


def audit(directory):
    report = {'directory': directory.name, 'scope': 'Structural checks only; no MAC, signature or vendor ABI validation'}
    request_path = directory / 'request.bin'
    response_path = directory / 'response.bin'
    if request_path.stat().st_size > 1048576 or response_path.stat().st_size > 1048576:
        raise ValueError('Exchange exceeds auditor size limit')
    request = request_path.read_bytes()
    response = response_path.read_bytes()
    report['request_length'] = len(request)
    report['request_sha256'] = hashlib.sha256(request).hexdigest()
    if len(request) < 4:
        raise ValueError('Missing request command')
    command = int.from_bytes(request[:4], 'little')
    report['command'] = hex(command)
    try:
        fields = exact(request[4:])
        if not isinstance(fields, dict):
            raise ValueError('Request is not a CBOR map')
        report['fields'] = {str(k): describe(v) for k, v in fields.items()}
        expected = {4, 57} if command == 0x3122 else ({4, 55, 56, 57, 58} if command == 0x311e else None)
        report['matches_current_builder_labels'] = expected is not None and set(fields) == expected
        label = 57 if command == 0x3122 else (58 if command == 0x311e else None)
        if label is not None and isinstance(fields.get(label), bytes):
            inner = exact(fields[label])
            report['embedded_cbor'] = describe(inner)
            if isinstance(inner, list):
                report['embedded_items'] = [describe(v) for v in inner]
        report['request_cbor_exact'] = True
    except (ValueError, UnicodeError) as error:
        report['request_parse_error'] = str(error)
    report['response_length'] = len(response)
    report['response_sha256'] = hashlib.sha256(response).hexdigest()
    if len(response) < 8:
        report['response_error'] = 'Truncated response header'
    else:
        status = int.from_bytes(response[:4], 'little', signed=True)
        length = int.from_bytes(response[4:8], 'little')
        report['status'] = status
        report['header_length_word'] = length
        report['nonzero_bytes_after_header'] = sum(v != 0 for v in response[8:])
        if status == 0:
            report['success_length_in_bounds'] = 0 < length <= len(response) - 8 and length <= 0xa000 - 8
        else:
            report['note'] = 'Rejected: length word is not evidence of a returned CSR; status meaning requires vendor verification'
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directories', nargs='+', type=Path, help='Exchange directories containing request.bin and response.bin')
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    reports = []
    for directory in args.directories:
        try:
            reports.append(audit(directory))
        except (OSError, ValueError) as error:
            reports.append({'directory': directory.name, 'error': str(error)})
    args.output.write_text(json.dumps(reports, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
