"""Report RPAs not using the ``production`` pipelineRef revision."""

import concurrent.futures
import sys
from pathlib import Path

import yaml

FOOT = (
    '† ⟨https://gitlab.com/konflux-ci/release-data/-/blob/main/hack/ci/revreport.py⟩'
)


def rev(f: str) -> str | None:
    """Return the pipelineRef revision, or None.

    Top-level function (not method/lambda/closure) so
    ProcessPoolExecutor.map() can pickle it. Guards with .get()
    only for the revision param (optional per the RPA schema);
    all others use direct access (required by the repo JSON
    schema, enforced by CI).

    :param f: path to an RPA YAML file
    :returns: revision string, or None if absent
    """
    spec = yaml.safe_load(Path(f).read_text('utf-8'))['spec']
    return {
        p['name']: p['value']
        for p in spec['pipeline']['pipelineRef']['params']
    }.get('revision')


def row(lab: str, n: int, acc: int, w: int) -> str:
    """Format a table row with percentage.

    :param lab: row label
    :param n: count for this category
    :param acc: total count
    :param w: number column width
    :returns: formatted row string
    """
    approx = '' if n*1000 % acc == 0 else '≈'
    return f'{lab:<20s}{n:>{w}d} ({approx}{n / acc * 100:.1f}%)'


def main(*files: str) -> None:
    """Count revisions and print the report.

    :param files: RPA YAML file paths to process
    """
    ok = 0
    nok = 0
    norev = 0
    with concurrent.futures.ProcessPoolExecutor() as pool:
        for r in pool.map(rev, files):
            if r == 'production':
                ok += 1
            elif r:
                nok += 1
            else:
                norev += 1

    acc = ok + nok + norev
    w = len(str(acc))
    rows = [
        row(lab, n, acc, w)
        for lab, n in (
            ('Production', ok),
            ('Non-production', nok),
            ('No revision', norev),
        )
        if n
    ]
    acc = f"{'Total':<20s}{acc:>{w}d}"

    rule = '━' * max(len(acc), *(len(r) for r in rows))

    print('\n'.join((
        'Konflux weekly report for non-production pipelineRef revisions†',
        rule, acc, *rows, rule,
        '',
        FOOT,
    )))


if __name__ == '__main__':
    argv = sys.argv
    argc = len(argv)
    pos = 1 + (argc > 1 and argv[1] == '--')
    argc -= pos
    if not argc:
        sys.exit('usage: revreport.py file...')
    del argv[:pos]
    main(*argv)
