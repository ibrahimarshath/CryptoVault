"""Script to strip non-CP1252 characters from all project Python files."""
import os
import glob

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))

# Map non-CP1252 chars to ASCII replacements
REPLACEMENTS = {
    '\u2554': '+', '\u2550': '=', '\u2557': '+',
    '\u2551': '|', '\u255a': '+', '\u255d': '+',
    '\u2502': '|', '\u2500': '-', '\u251c': '+',
    '\u2524': '+', '\u2510': '+', '\u2514': '+',
    '\u2518': '+', '\u252c': '+', '\u2534': '+',
    '\u253c': '+', '\u2560': '+', '\u2563': '+',
    '\u2566': '+', '\u2569': '+', '\u256c': '+',
    '\u2588': '#', '\u2591': '.', '\u2592': ':',
    '\u2593': '#', '\u2580': '-', '\u2584': '-',
    '\u2015': '-', '\u2014': '--', '\u2013': '-',
    '\u2026': '...', '\u2019': "'", '\u2018': "'",
    '\u201c': '"', '\u201d': '"',
    '\u2713': '(OK)', '\u2717': '(X)',
    '\u2212': '-', '\u2192': '->', '\u2190': '<-',
    '\u2193': 'v', '\u2191': '^',
    '\u2022': '*', '\u25cf': '*', '\u25a0': '#',
    '\u2665': '<3', '\u2764': '<3',
    '\u2714': '(v)', '\u2716': '(X)',
    '\u25b6': '>', '\u25c0': '<',
    '\u2611': '[x]', '\u2610': '[ ]',
    '\u00b7': '.', '\u00b2': '2', '\u00b3': '3',
    '\u2139': 'i',
    '\u2562': '+', '\u255f': '+',
    '\u2561': '+', '\u255e': '+',
    '\u27a4': '->', '\u279c': '->',
    '\u2265': '>=', '\u2264': '<=', '\u2260': '!=',
    '\u221e': 'inf',
    '\u255b': '+', '\u255c': '+',
    '\u2558': '+', '\u2559': '+',
    '\u2555': '+', '\u2556': '+',
    '\u255d': '+', '\u2568': '+',
    '\u2567': '+', '\u2565': '+',
    '\u2564': '+', '\u2562': '+',
    '\u2561': '+', '\u255e': '+',
    '\u255f': '+',
}

files = glob.glob(os.path.join(PROJECT_DIR, '**', '*.py'), recursive=True)
count = 0
for fpath in files:
    try:
        with open(fpath, 'r', encoding='utf-8') as f:
            content = f.read()
        new_content = content
        for old, new in REPLACEMENTS.items():
            new_content = new_content.replace(old, new)
        if new_content != content:
            with open(fpath, 'w', encoding='utf-8') as f:
                f.write(new_content)
            print(f'  Fixed: {os.path.relpath(fpath, PROJECT_DIR)}')
            count += 1
    except Exception as e:
        print(f'  Error {fpath}: {e}')

print(f'\nDone. Fixed {count} file(s).')
