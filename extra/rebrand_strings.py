#!/usr/bin/env python3
"""Rebrands user-visible strings to Chromium-Gost: "Chromium" in the Chromium
string resources and the product name "Chrome" in the shared ones. Translations
are keyed by a fingerprint of the source message, so every translation id is
rewritten from the old fingerprint to the new one. Run from the Chromium src
directory on pristine files."""

import pathlib
import re
import sys
import tempfile

sys.path.insert(0, 'tools/grit')
from grit import grd_reader  # noqa: E402

PRODUCT = 'Chromium-Gost'
# (product mention to rename, every occurrence of the word)
CHROMIUM = (re.compile(r'Chromium(?! Authors)'), re.compile(r'Chromium'))
CHROME = (re.compile(r'(?<!Google )\bChrome\b(?! Web Store| OS| for Testing| Remote Desktop'
                     r'| Enterprise| Root)'), re.compile(r'\bChrome\b'))
RESOURCES = [
    ('chrome/app/chromium_strings.grd', CHROMIUM),
    ('components/components_chromium_strings.grd', CHROMIUM),
    ('chrome/app/generated_resources.grd', CHROME),
    ('components/components_strings.grd', CHROME),
    ('components/privacy_sandbox_strings.grd', CHROME),
]
GRIT_BUILTINS = {'and', 'or', 'not', 'in', 'lang', 'pp_ifdef', 'is_linux', 'is_win',
                 'is_macosx', 'is_android', 'is_ios', 'is_chromeos', 'is_posix',
                 'is_fuchsia'}
MESSAGE = re.compile(r'(<message\b[^>]*>)(.*?)(</message>)', re.S)


def sources(grd):
    files = [grd]
    for path in files:
        files += [path.parent / part for part in
                  re.findall(r'<part file="([^"]+)"', path.read_text(encoding='utf-8'))]
    return files


def message_ids(grd, texts):
    expressions = ' '.join(e for text in texts.values()
                           for e in re.findall(r'expr="([^"]*)"', text))
    defines = {name: False for name in re.findall(r'[A-Za-z_]\w*', expressions)
               if name not in GRIT_BUILTINS}
    defines['_chromium'] = True
    with tempfile.TemporaryDirectory() as scratch:
        for path, text in texts.items():
            copy = pathlib.Path(scratch) / path.relative_to(grd.parent)
            copy.parent.mkdir(parents=True, exist_ok=True)
            copy.write_text(text, encoding='utf-8')
        root = grd_reader.Parse(str(pathlib.Path(scratch) / grd.name), defines=defines,
                                first_ids_file=None, debug=False,
                                target_platform='linux')
        return [(node.GetCliques()[0].GetId(), node.GetCliques()[0].GetMessage().GetRealContent())
                for node in root.Preorder() if node.name == 'message']


def rebrand(grd, rule):
    pattern, word = rule
    files = sources(grd)
    original = {path: path.read_bytes().decode('utf-8') for path in files}
    renamed = {path: MESSAGE.sub(lambda m: m[1] + pattern.sub(PRODUCT, m[2]) + m[3], text)
               for path, text in original.items()}
    remap = {}
    for (old_id, old_text), (new_id, _) in zip(message_ids(grd, original),
                                                message_ids(grd, renamed)):
        if old_id != new_id:
            # Translations are renamed only when every occurrence in the source was.
            whole = len(pattern.findall(old_text)) == len(word.findall(old_text))
            remap[old_id] = (new_id, whole)
    for path, text in renamed.items():
        path.write_bytes(text.encode('utf-8'))
    for xtb in re.findall(r'<file path="([^"]+\.xtb)"', original[grd]):
        path = grd.parent / xtb
        if not path.exists():
            continue

        def translation(m):
            new_id, whole = remap.get(m[2], (m[2], False))
            body = pattern.sub(PRODUCT, m[4]) if whole else m[4]
            return m[1] + new_id + m[3] + body + m[5]
        text = re.sub(r'(<translation id=")(\d+)(">)(.*?)(</translation>)', translation,
                      path.read_bytes().decode('utf-8'), flags=re.S)
        path.write_bytes(text.encode('utf-8'))


def main():
    for grd, rule in RESOURCES:
        rebrand(pathlib.Path(grd), rule)


if __name__ == '__main__':
    main()
