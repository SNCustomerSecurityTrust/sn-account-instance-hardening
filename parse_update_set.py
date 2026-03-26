#!/usr/bin/env python3
"""
Parse a ServiceNow Update Set XML and extract scan checks into
suite-based directory structure under /scans.
"""

import os
import re
import json
import html
import xml.etree.ElementTree as ET

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SCANS_DIR = os.path.join(BASE_DIR, 'scans')
DIST_DIR = os.path.join(BASE_DIR, 'dist')


def find_latest_xml():
    """Find the latest update set XML in dist/ by version number."""
    import glob
    xmls = glob.glob(os.path.join(DIST_DIR, '*.xml'))
    if not xmls:
        raise FileNotFoundError("No XML files found in dist/")
    # Sort by modification time, newest first
    xmls.sort(key=os.path.getmtime, reverse=True)
    return xmls[0]


def slugify(name):
    """Convert suite/check name to directory/file-friendly slug."""
    s = name.lower()
    s = s.replace('&', 'and')
    s = re.sub(r'[^a-z0-9]+', '-', s)
    s = s.strip('-')
    return s


def suite_dir_name(name):
    """Map suite names to directory names matching existing conventions."""
    mapping = {
        'level 1': 'level-1',
        'level 2': 'level-2',
        'level 3': 'level-3',
        'level next': 'level-next',
    }
    lower = name.lower()
    if lower in mapping:
        return mapping[lower]
    return slugify(name)


def parse_inner_xml(payload_text):
    """Parse the inner XML payload and return the root element."""
    try:
        return ET.fromstring(payload_text)
    except ET.ParseError:
        # Try wrapping in a root element if needed
        try:
            return ET.fromstring('<root>' + payload_text + '</root>')
        except ET.ParseError:
            return None


def get_text(elem, tag, default=''):
    """Get text content of a child element."""
    child = elem.find(tag)
    if child is not None and child.text:
        return child.text
    return default


def get_display_value(elem, tag):
    """Get display_value attribute of a child element."""
    child = elem.find(tag)
    if child is not None:
        return child.get('display_value', '')
    return ''


def decode_script(script_text):
    """Decode HTML entities in script text back to plain JavaScript."""
    if not script_text:
        return ''
    # The script may have been double-encoded; decode until stable
    prev = None
    decoded = script_text
    while decoded != prev:
        prev = decoded
        decoded = html.unescape(decoded)
    return decoded


def extract_cdata_script(payload_text):
    """Extract script content from CDATA in the inner XML payload."""
    # Look for CDATA section within <script> tags
    cdata_match = re.search(r'<!\[CDATA\[(.*?)\]\]>', payload_text, re.DOTALL)
    if cdata_match:
        return cdata_match.group(1)
    return None


def main():
    xml_file = find_latest_xml()
    print(f"Reading XML: {xml_file}")
    tree = ET.parse(xml_file)
    root = tree.getroot()

    suites = {}       # sys_id -> {name, dir_name, ...}
    m2m_records = []   # {check_sys_id, check_name, suite_sys_id, suite_name}
    checks = {}        # sys_id -> {name, script, metadata...}

    for update_xml in root.findall('.//sys_update_xml'):
        record_type = get_text(update_xml, 'type')
        name_elem = get_text(update_xml, 'name')
        payload_text = get_text(update_xml, 'payload')

        if not payload_text:
            continue

        # Parse inner XML from payload
        inner_root = parse_inner_xml(payload_text)
        if inner_root is None:
            print(f"  WARNING: Could not parse payload for {name_elem}")
            continue

        if record_type == 'Suite':
            # scan_check_suite record
            suite_elem = inner_root.find('.//scan_check_suite')
            if suite_elem is not None:
                sys_id = get_text(suite_elem, 'sys_id')
                suite_name = get_text(suite_elem, 'name')
                desc = get_text(suite_elem, 'description')
                dir_name = suite_dir_name(suite_name)
                suites[sys_id] = {
                    'name': suite_name,
                    'dir_name': dir_name,
                    'description': desc,
                    'sys_id': sys_id,
                }
                print(f"  Suite: {suite_name} ({sys_id}) -> {dir_name}/")

        elif record_type == 'Suite Check':
            # scan_check_suite_check (m2m) record
            m2m_elem = inner_root.find('.//scan_check_suite_check')
            if m2m_elem is not None:
                check_elem = m2m_elem.find('check')
                suite_elem = m2m_elem.find('suite')
                if check_elem is not None and suite_elem is not None:
                    check_sys_id = check_elem.text or ''
                    check_display = check_elem.get('display_value', '')
                    suite_sys_id = suite_elem.text or ''
                    suite_display = suite_elem.get('display_value', '')
                    m2m_records.append({
                        'check_sys_id': check_sys_id,
                        'check_name': check_display,
                        'suite_sys_id': suite_sys_id,
                        'suite_name': suite_display,
                    })

        elif record_type == 'Script Only Check':
            # scan_script_only_check record
            check_elem = inner_root.find('.//scan_script_only_check')
            if check_elem is not None:
                sys_id = get_text(check_elem, 'sys_id')
                check_name = get_text(check_elem, 'name')

                # Extract script - try CDATA first from raw payload
                script_content = extract_cdata_script(payload_text)
                if script_content is None:
                    # Fallback: get from parsed element
                    script_content = get_text(check_elem, 'script')
                    script_content = decode_script(script_content)

                checks[sys_id] = {
                    'sys_id': sys_id,
                    'name': check_name,
                    'script': script_content,
                    'active': get_text(check_elem, 'active') == 'true',
                    'category': get_text(check_elem, 'category'),
                    'description': get_text(check_elem, 'description'),
                    'documentation_url': get_text(check_elem, 'documentation_url'),
                    'finding_type': get_text(check_elem, 'finding_type'),
                    'priority': get_text(check_elem, 'priority'),
                    'resolution_details': get_text(check_elem, 'resolution_details'),
                    'run_condition': get_text(check_elem, 'run_condition'),
                    'score_max': get_text(check_elem, 'score_max'),
                    'score_min': get_text(check_elem, 'score_min'),
                    'score_scale': get_text(check_elem, 'score_scale'),
                    'short_description': get_text(check_elem, 'short_description'),
                    'sys_class_name': get_text(check_elem, 'sys_class_name'),
                }
                print(f"  Check: {check_name} ({sys_id})")

    # Build check -> suite mapping
    check_to_suites = {}  # check_sys_id -> [suite_name, ...]
    for m2m in m2m_records:
        cid = m2m['check_sys_id']
        sid = m2m['suite_sys_id']
        suite_info = suites.get(sid)
        suite_name = suite_info['name'] if suite_info else m2m['suite_name']
        if cid not in check_to_suites:
            check_to_suites[cid] = []
        check_to_suites[cid].append(suite_name)

    print(f"\nFound {len(suites)} suites, {len(m2m_records)} m2m records, {len(checks)} checks")

    # Create files
    files_written = 0
    for check_sys_id, check in checks.items():
        suite_names = check_to_suites.get(check_sys_id, ['unmapped'])

        for suite_name in suite_names:
            suite_info = None
            for s in suites.values():
                if s['name'] == suite_name:
                    suite_info = s
                    break

            dir_name = suite_info['dir_name'] if suite_info else suite_dir_name(suite_name)
            suite_dir = os.path.join(SCANS_DIR, dir_name)
            os.makedirs(suite_dir, exist_ok=True)

            # File name from check name
            file_slug = slugify(check['name'])
            js_path = os.path.join(suite_dir, file_slug + '.js')
            json_path = os.path.join(suite_dir, file_slug + '.json')

            # Write JS file
            script = check['script']
            if script:
                with open(js_path, 'w', encoding='utf-8') as f:
                    f.write(script)
                    if not script.endswith('\n'):
                        f.write('\n')
                print(f"  Wrote: scans/{dir_name}/{file_slug}.js")

            # Write JSON metadata
            # Convert numeric strings to numbers where appropriate
            priority = check.get('priority', '')
            try:
                priority = int(priority)
            except (ValueError, TypeError):
                pass

            score_max = check.get('score_max', '')
            try:
                score_max = int(score_max)
            except (ValueError, TypeError):
                pass

            score_min = check.get('score_min', '')
            try:
                score_min = int(score_min)
            except (ValueError, TypeError):
                pass

            score_scale = check.get('score_scale', '')
            try:
                score_scale = int(score_scale)
            except (ValueError, TypeError):
                pass

            metadata = {
                'active': check['active'],
                'category': check['category'],
                'description': check['description'],
                'documentation_url': check['documentation_url'],
                'finding_type': check['finding_type'],
                'name': check['name'],
                'priority': priority,
                'resolution_details': check['resolution_details'],
                'run_condition': check['run_condition'],
                'score_max': score_max,
                'score_min': score_min,
                'score_scale': score_scale,
                'short_description': check['short_description'],
                'sys_id': check['sys_id'],
                'sys_class_name': check['sys_class_name'],
                'suite': suite_name,
            }

            with open(json_path, 'w', encoding='utf-8') as f:
                json.dump(metadata, f, indent=2, ensure_ascii=False)
                f.write('\n')
            print(f"  Wrote: scans/{dir_name}/{file_slug}.json")
            files_written += 2

    print(f"\nDone! Wrote {files_written} files total.")


if __name__ == '__main__':
    main()
