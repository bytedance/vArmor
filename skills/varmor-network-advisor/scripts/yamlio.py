# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0
"""Dependency-free block YAML for JSON-compatible data, not a general YAML parser.

Read our emitted subset and legacy JSON. No tags, aliases, implicit dates,
multiline scalars are interpreted; mapping/sequence forms follow our output.
"""
import json
import math
import re


RESERVED = {'y', 'n', 'yes', 'no', 'true', 'false', 'on', 'off', 'null'}


def plain(value):
    return bool(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_./-]*', value)) and value.lower() not in RESERVED


def scalar(value):
    if isinstance(value, str):
        if plain(value):
            return value
        # YAML 1.1 treats these literal code points as physical line breaks.
        return json.dumps(value, ensure_ascii=False).replace('\u0085', '\\u0085').replace('\u2028', '\\u2028').replace('\u2029', '\\u2029')
    if type(value) is float and math.isfinite(value):
        token = json.dumps(value, allow_nan=False)
        if 'e' in token and '.' not in token.split('e')[0]:
            token = token.replace('e', '.0e')
        return token
    if value is None or type(value) in (bool, int):
        return json.dumps(value, allow_nan=False)
    if value == {} or value == []:
        return json.dumps(value)
    raise ValueError('Policy YAML requires JSON-compatible finite values')


def dumps(value):
    lines = []

    def emit(obj, indent):
        pad = ' ' * indent
        if isinstance(obj, dict) and obj:
            for key, child in obj.items():
                if not isinstance(key, str):
                    raise ValueError('Policy YAML requires string mapping keys')
                prefix = pad + scalar(key) + ':'
                if isinstance(child, (dict, list)) and child:
                    lines.append(prefix)
                    emit(child, indent + 2)
                else:
                    lines.append(prefix + ' ' + scalar(child))
        elif isinstance(obj, list) and obj:
            for child in obj:
                if isinstance(child, (dict, list)) and child:
                    if isinstance(child, dict):
                        start = len(lines)
                        emit(child, indent + 2)
                        lines[start] = pad + '- ' + lines[start].lstrip(' ')
                    else:
                        lines.append(pad + '-')
                        emit(child, indent + 2)
                else:
                    lines.append(pad + '- ' + scalar(child))
        else:
            lines.append(pad + scalar(obj))

    emit(value, 0)
    return '\n'.join(lines) + '\n'


def loads(text):
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    lines = []
    for raw in text.split('\n'):
        if not raw.strip() or raw.lstrip().startswith('#'):
            continue
        if raw == '---' and not lines:
            continue
        if '\t' in raw or raw.rstrip() != raw:
            raise ValueError('Unsupported YAML whitespace; use the generated format or JSON')
        indent = len(raw) - len(raw.lstrip(' '))
        if indent % 2:
            raise ValueError('Generated policy YAML uses two-space indentation')
        lines.append((indent, raw[indent:]))
    if not lines or lines[0][0] != 0:
        raise ValueError('Empty or indented YAML document')

    def value(token):
        try:
            result = json.loads(token)
        except json.JSONDecodeError:
            if not plain(token):
                raise ValueError('Unsupported YAML scalar; use the generated format or JSON')
            return token
        if type(result) is float and not math.isfinite(result):
            raise ValueError('Non-finite YAML number')
        return result

    def pair(token):
        if token.startswith('"'):
            key, end = json.JSONDecoder().raw_decode(token)
            suffix = token[end:]
            if not isinstance(key, str) or not suffix.startswith(':'):
                raise ValueError('Invalid YAML mapping key')
            return key, suffix[1:].lstrip(' ')
        key, separator, child = token.partition(':')
        if not separator or not plain(key):
            raise ValueError('Unsupported YAML mapping; use the generated format or JSON')
        return key, child.lstrip(' ')

    expanded = []
    for indent, token in lines:
        compact = False
        if token.startswith('- '):
            try:
                pair(token[2:])
                compact = True
            except (ValueError, json.JSONDecodeError):
                pass
        if compact:
            expanded.extend([(indent, '-'), (indent + 2, token[2:])])
        else:
            expanded.append((indent, token))
    lines = expanded

    def node(index, indent):
        if lines[index][0] != indent:
            raise ValueError('Invalid YAML nesting')
        token = lines[index][1]
        sequence = token == '-' or token.startswith('- ')
        if not sequence and ':' not in token:
            return value(token), index + 1
        # A quoted scalar may itself contain a colon.
        if token.startswith('"'):
            parsed, end = json.JSONDecoder().raw_decode(token)
            if end == len(token):
                return parsed, index + 1
        output = [] if sequence else {}
        while index < len(lines) and lines[index][0] == indent:
            token = lines[index][1]
            if sequence:
                if token != '-' and not token.startswith('- '):
                    raise ValueError('Mixed YAML sequence and mapping')
                child = token[1:].lstrip(' ')
            else:
                key, child = pair(token)
                if key in output:
                    raise ValueError('Duplicate YAML mapping key')
            index += 1
            if child:
                parsed = value(child)
            else:
                if index == len(lines) or lines[index][0] != indent + 2:
                    raise ValueError('Missing YAML child')
                parsed, index = node(index, indent + 2)
            if sequence:
                output.append(parsed)
            else:
                output[key] = parsed
        return output, index

    result, end = node(0, 0)
    if end != len(lines):
        raise ValueError('Unsupported YAML structure; use the generated format or JSON')
    return result
