"""Reviewed short names for human-facing 0.4 authoring files.

These are presentation paths, never native identity/proof authority. Adding a
new stream with a colliding short name is a review error, not a reason to add
silent hash suffixes.
"""
import re

ALIASES = {
    'active directory domain': 'active_directory_domain',
    'active directory forest': 'active_directory_forest',
    'adobe acrobat professional dc continuous track': 'adobe_acrobat_pro_dc',
    'adobe acrobat reader dc continuous track': 'adobe_acrobat_reader_dc',
    'apache server 2.4 unix site': 'apache_server_2-4_unix_site',
    'apache server 2.4 unix': 'apache_server_2-4_unix_server',
    'apache server 2.4 windows': 'apache_server_2-4_windows_server',
    'apache site 2.4 windows': 'apache_server_2-4_windows_site',
    'apple macos 13 (ventura)': 'macos_13',
    'apple macos 14 (sonoma)': 'macos_14',
    'apple macos 15 (sequoia)': 'macos_15',
    'apple macos 26 (tahoe)': 'macos_26',
    'microsoft defender antivirus': 'ms_defender_antivirus',
    'microsoft dns server': 'ms_windows_server_dns',
    'microsoft dotnet framework 4.0': 'ms_dotnet_4',
    'microsoft edge': 'ms_edge',
    'microsoft internet explorer 11': 'ms_ie_11',
    'microsoft office 365 proplus': 'ms_office_365',
    'microsoft onedrive': 'ms_onedrive',
    'microsoft windows defender firewall with advanced security': 'ms_windows_firewall',
    'microsoft windows server 2012/2012 r2 domain controller': 'ms_windows_server_2012_2012r2_dc',
    'microsoft windows server 2012/2012 r2 member server': 'ms_windows_server_2012_2012r2_member',
    'mozilla firefox for linux': 'firefox_linux',
    'mozilla firefox for windows': 'firefox_windows',
    'red hat enterprise linux 7': 'rhel_7',
    'red hat enterprise linux 8': 'rhel_8',
    'red hat enterprise linux 9': 'rhel_9',
    'tri-lab operating system stack (toss) 4': 'toss_4',
}


def benchmark_folder(title):
    original = re.split(r' STIG SCAP Benchmark', title, maxsplit=1)[0].lower()
    if original in ALIASES:
        return ALIASES[original]
    for old, new in (
        ('canonical ubuntu', 'ubuntu'),
        ('microsoft windows', 'ms windows'),
        ('microsoft exchange', 'ms exchange'),
        ('microsoft iis', 'ms iis'),
        ('google chrome current windows', 'chrome_windows'),
    ):
        original = original.replace(old, new)
    result = re.sub(r'[^a-z0-9]+', '_', original).strip('_')
    if not result or len(result) > 64 or result.casefold() in {'shared', 'standalone'}:
        raise ValueError('Benchmark needs an explicit reviewed short name: ' + title)
    return result


def source_sv(rule):
    match = re.search(r'SV-[0-9]+', rule['source_rule'])
    if not match:
        raise ValueError('native Rule lacks a source SV-ID: ' + rule['source_rule'])
    return match.group(0)


def native_relative(scope, kind, sv=None, mode='automated'):
    if kind in ('benchmark', 'applicability'):
        return f'{scope}/{kind}.yaml'
    if not isinstance(sv,str) or not re.fullmatch(r'SV-[0-9]+',sv):
        raise ValueError('imported native filename requires a verified source SV-ID')
    if kind == 'rule':
        return f'{scope}/rules/{sv}.rule.yaml'
    if kind == 'assessment' and mode in ('automated', 'manual'):
        return f'{scope}/assessments/{mode}/{sv}.{mode}.yaml'
    raise ValueError('unexpected native kind/mode; explicit owner review required')
