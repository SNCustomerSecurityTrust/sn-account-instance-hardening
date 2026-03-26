#!/usr/bin/env python3
"""
Generate a new ServiceNow Update Set XML from the current source files.

Reads the previous update set XML to preserve sys_ids and ServiceNow-internal
metadata, merges updated content from .js and .json source files, increments
sys_mod_count, updates timestamps, and writes a new XML file.

Usage:
    python3 generate_update_set.py [--input dist/v1.3.xml] [--output dist/v1.4.xml] [--version 1.4]
"""

import json
import os
import re
import html
import uuid
import argparse
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SCANS_DIR = os.path.join(BASE_DIR, 'scans')
DIST_DIR = os.path.join(BASE_DIR, 'dist')

NOW = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')


# ── Helpers ──────────────────────────────────────────────────────────────────

def new_sys_id():
    return uuid.uuid4().hex


def java_string_hashcode(s):
    """Compute Java's String.hashCode() for payload_hash."""
    h = 0
    for c in s:
        h = (31 * h + ord(c)) & 0xFFFFFFFF
    if h >= 0x80000000:
        h -= 0x100000000
    return h


def xml_escape(text):
    """Standard XML escaping for element content."""
    if text is None:
        return ''
    text = str(text)
    text = text.replace('&', '&amp;')
    text = text.replace('<', '&lt;')
    text = text.replace('>', '&gt;')
    return text


def entity_encode(s):
    """Entity-encode an inner XML string for placement in outer <payload>."""
    s = s.replace('&', '&amp;')
    s = s.replace('<', '&lt;')
    s = s.replace('>', '&gt;')
    return s


def get_text(elem, tag, default=''):
    child = elem.find(tag)
    if child is not None and child.text:
        return child.text
    return default


def slugify(name):
    s = name.lower()
    s = s.replace('&', 'and')
    s = re.sub(r'[^a-z0-9]+', '-', s)
    return s.strip('-')


def suite_dir_name(name):
    mapping = {
        'level 1': 'level-1',
        'level 2': 'level-2',
        'level 3': 'level-3',
        'level next': 'level-next',
    }
    return mapping.get(name.lower(), slugify(name))


def xml_elem_or_empty(tag, value, attrs=''):
    """Return <tag>value</tag> or <tag/> if value is empty."""
    if value:
        return f'<{tag}{attrs}>{xml_escape(value)}</{tag}>'
    return f'<{tag}/>'


# ── Parsing ──────────────────────────────────────────────────────────────────

def parse_update_set(xml_path):
    """Parse a ServiceNow Update Set XML and return all record data."""
    print(f"Parsing: {xml_path}")
    tree = ET.parse(xml_path)
    root = tree.getroot()

    data = {
        'update_set_sys_id': '',
        'update_set_remote_sys_id': '',
        'suites': {},
        'm2m': {},
        'checks': {},
        'record_order': [],  # preserve original record order
    }

    # Parse sys_remote_update_set
    rus = root.find('sys_remote_update_set')
    if rus is not None:
        data['update_set_sys_id'] = get_text(rus, 'sys_id')
        data['update_set_remote_sys_id'] = get_text(rus, 'remote_sys_id')

    # Parse each sys_update_xml
    for ux in root.findall('.//sys_update_xml'):
        record_type = get_text(ux, 'type')
        payload_text = get_text(ux, 'payload')
        if not payload_text:
            continue

        # Parse inner XML
        try:
            inner = ET.fromstring(payload_text)
        except ET.ParseError:
            continue

        # Wrapper metadata
        wrapper = {
            'wrapper_sys_id': get_text(ux, 'sys_id'),
            'sys_recorded_at': get_text(ux, 'sys_recorded_at'),
            'update_guid': get_text(ux, 'update_guid'),
            'update_guid_history': get_text(ux, 'update_guid_history'),
        }

        if record_type == 'Suite':
            suite_elem = inner.find('.//scan_check_suite')
            if suite_elem is None:
                continue
            sid = get_text(suite_elem, 'sys_id')
            rec = {
                'sys_id': sid,
                'name': get_text(suite_elem, 'name'),
                'active': get_text(suite_elem, 'active', 'true'),
                'description': get_text(suite_elem, 'description'),
                'private': get_text(suite_elem, 'private', 'false'),
                'scorecard': get_text(suite_elem, 'scorecard', 'false'),
                'sys_created_by': get_text(suite_elem, 'sys_created_by', 'admin'),
                'sys_created_on': get_text(suite_elem, 'sys_created_on'),
                'sys_mod_count': int(get_text(suite_elem, 'sys_mod_count', '0')),
                'sys_updated_by': get_text(suite_elem, 'sys_updated_by', 'admin'),
                'sys_updated_on': get_text(suite_elem, 'sys_updated_on'),
                '_wrapper': wrapper,
            }
            data['suites'][sid] = rec
            data['record_order'].append(('suite', sid))
            print(f"  Suite: {rec['name']} ({sid})")

        elif record_type == 'Suite Check':
            m2m_elem = inner.find('.//scan_check_suite_check')
            if m2m_elem is None:
                continue
            mid = get_text(m2m_elem, 'sys_id')
            check_ref = m2m_elem.find('check')
            suite_ref = m2m_elem.find('suite')
            rec = {
                'sys_id': mid,
                'check_value': check_ref.text if check_ref is not None else '',
                'check_display': check_ref.get('display_value', '') if check_ref is not None else '',
                'suite_value': suite_ref.text if suite_ref is not None else '',
                'suite_display': suite_ref.get('display_value', '') if suite_ref is not None else '',
                'score_weight': get_text(m2m_elem, 'score_weight', '1'),
                'sys_created_by': get_text(m2m_elem, 'sys_created_by', 'admin'),
                'sys_created_on': get_text(m2m_elem, 'sys_created_on'),
                'sys_mod_count': int(get_text(m2m_elem, 'sys_mod_count', '0')),
                'sys_updated_by': get_text(m2m_elem, 'sys_updated_by', 'admin'),
                'sys_updated_on': get_text(m2m_elem, 'sys_updated_on'),
                '_wrapper': wrapper,
            }
            data['m2m'][mid] = rec
            data['record_order'].append(('m2m', mid))

        elif record_type == 'Script Only Check':
            check_elem = inner.find('.//scan_script_only_check')
            if check_elem is None:
                continue
            cid = get_text(check_elem, 'sys_id')

            # Extract script from CDATA
            cdata_match = re.search(r'<!\[CDATA\[(.*?)\]\]>', payload_text, re.DOTALL)
            script = cdata_match.group(1) if cdata_match else get_text(check_elem, 'script')

            # Extract sys_es_latest_script
            es_elem = inner.find('.//sys_es_latest_script')
            es_data = None
            if es_elem is not None:
                es_data = {
                    'sys_id': get_text(es_elem, 'sys_id'),
                    'sys_created_by': get_text(es_elem, 'sys_created_by', 'admin'),
                    'sys_created_on': get_text(es_elem, 'sys_created_on'),
                    'sys_mod_count': get_text(es_elem, 'sys_mod_count', '0'),
                    'sys_updated_by': get_text(es_elem, 'sys_updated_by', 'admin'),
                    'sys_updated_on': get_text(es_elem, 'sys_updated_on'),
                }

            rec = {
                'sys_id': cid,
                'name': get_text(check_elem, 'name'),
                'active': get_text(check_elem, 'active', 'true'),
                'category': get_text(check_elem, 'category', 'security'),
                'description': get_text(check_elem, 'description'),
                'documentation_url': get_text(check_elem, 'documentation_url'),
                'finding_type': get_text(check_elem, 'finding_type', 'scan_finding'),
                'priority': get_text(check_elem, 'priority', '3'),
                'resolution_details': get_text(check_elem, 'resolution_details'),
                'run_condition': get_text(check_elem, 'run_condition'),
                'score_max': get_text(check_elem, 'score_max', '100'),
                'score_min': get_text(check_elem, 'score_min', '0'),
                'score_scale': get_text(check_elem, 'score_scale', '1'),
                'script': script,
                'short_description': get_text(check_elem, 'short_description'),
                'sys_class_name': get_text(check_elem, 'sys_class_name', 'scan_script_only_check'),
                'sys_created_by': get_text(check_elem, 'sys_created_by', 'admin'),
                'sys_created_on': get_text(check_elem, 'sys_created_on'),
                'sys_mod_count': int(get_text(check_elem, 'sys_mod_count', '0')),
                'sys_updated_by': get_text(check_elem, 'sys_updated_by', 'admin'),
                'sys_updated_on': get_text(check_elem, 'sys_updated_on'),
                '_es_latest': es_data,
                '_wrapper': wrapper,
            }
            data['checks'][cid] = rec
            data['record_order'].append(('check', cid))
            print(f"  Check: {rec['name']} ({cid})")

    print(f"  Totals: {len(data['suites'])} suites, {len(data['m2m'])} m2m, {len(data['checks'])} checks")
    return data


# ── Source file merging ──────────────────────────────────────────────────────

def merge_source_files(data, scans_dir):
    """Read .json and .js files and merge updates into parsed data."""
    print(f"\nMerging source files from: {scans_dir}")
    merged = 0

    # Build a lookup of check sys_id -> check data for quick access
    checks = data['checks']

    for suite_dir in os.listdir(scans_dir):
        suite_path = os.path.join(scans_dir, suite_dir)
        if not os.path.isdir(suite_path):
            continue

        for fname in os.listdir(suite_path):
            if not fname.endswith('.json'):
                continue

            json_path = os.path.join(suite_path, fname)
            js_path = os.path.join(suite_path, fname.replace('.json', '.js'))

            with open(json_path, 'r', encoding='utf-8') as f:
                meta = json.load(f)

            sys_id = meta.get('sys_id', '')
            if sys_id not in checks:
                continue

            check = checks[sys_id]

            # Merge metadata fields from JSON
            for field in ['description', 'documentation_url', 'resolution_details',
                          'short_description', 'category', 'finding_type',
                          'run_condition']:
                if field in meta:
                    check[field] = str(meta[field])

            # Numeric fields
            for field in ['priority', 'score_max', 'score_min', 'score_scale']:
                if field in meta:
                    check[field] = str(meta[field])

            # Active flag
            if 'active' in meta:
                check['active'] = 'true' if meta['active'] else 'false'

            # Merge script from JS file
            if os.path.exists(js_path):
                with open(js_path, 'r', encoding='utf-8') as f:
                    script = f.read()
                # Strip trailing newline that was added by the extractor
                if script.endswith('\n') and not check.get('script', '').endswith('\n'):
                    script = script.rstrip('\n')
                check['script'] = script

            merged += 1

    print(f"  Merged {merged} source file(s) into check records")


# ── Payload builders ─────────────────────────────────────────────────────────

def build_suite_payload(rec):
    desc = xml_escape(rec.get('description', ''))
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<record_update table="scan_check_suite">'
        '<scan_check_suite action="INSERT_OR_UPDATE">'
        f'<active>{rec["active"]}</active>'
        f'{xml_elem_or_empty("description", rec.get("description", ""))}'
        f'<name>{xml_escape(rec["name"])}</name>'
        f'<private>{rec.get("private", "false")}</private>'
        f'<scorecard>{rec.get("scorecard", "false")}</scorecard>'
        '<sys_class_name>scan_check_suite</sys_class_name>'
        f'<sys_created_by>{rec["sys_created_by"]}</sys_created_by>'
        f'<sys_created_on>{rec["sys_created_on"]}</sys_created_on>'
        f'<sys_id>{rec["sys_id"]}</sys_id>'
        f'<sys_mod_count>{rec["sys_mod_count"]}</sys_mod_count>'
        f'<sys_name>{xml_escape(rec["name"])}</sys_name>'
        '<sys_package display_value="Global" source="global">global</sys_package>'
        '<sys_policy/>'
        '<sys_scope display_value="Global">global</sys_scope>'
        f'<sys_update_name>scan_check_suite_{rec["sys_id"]}</sys_update_name>'
        f'<sys_updated_by>{rec["sys_updated_by"]}</sys_updated_by>'
        f'<sys_updated_on>{rec["sys_updated_on"]}</sys_updated_on>'
        '<triggers/>'
        '</scan_check_suite>'
        f'<sys_translated_text action="delete_multiple" query="documentkey={rec["sys_id"]}"/>'
        '</record_update>'
    )


def build_m2m_payload(rec):
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<record_update table="scan_check_suite_check">'
        '<scan_check_suite_check action="INSERT_OR_UPDATE">'
        f'<check display_value="{rec["check_display"]}">{rec["check_value"]}</check>'
        f'<score_weight>{rec.get("score_weight", "1")}</score_weight>'
        f'<suite display_value="{rec["suite_display"]}">{rec["suite_value"]}</suite>'
        '<sys_class_name>scan_check_suite_check</sys_class_name>'
        f'<sys_created_by>{rec["sys_created_by"]}</sys_created_by>'
        f'<sys_created_on>{rec["sys_created_on"]}</sys_created_on>'
        f'<sys_id>{rec["sys_id"]}</sys_id>'
        f'<sys_mod_count>{rec["sys_mod_count"]}</sys_mod_count>'
        '<sys_name/>'
        '<sys_package display_value="Global" source="global">global</sys_package>'
        '<sys_policy/>'
        '<sys_scope display_value="Global">global</sys_scope>'
        f'<sys_update_name>scan_check_suite_check_{rec["sys_id"]}</sys_update_name>'
        f'<sys_updated_by>{rec["sys_updated_by"]}</sys_updated_by>'
        f'<sys_updated_on>{rec["sys_updated_on"]}</sys_updated_on>'
        '</scan_check_suite_check>'
        '</record_update>'
    )


def build_check_payload(rec):
    es = rec.get('_es_latest')
    es_section = ''
    if es:
        es_section = (
            '<sys_es_latest_script action="INSERT_OR_UPDATE">'
            f'<id>{rec["sys_id"]}</id>'
            f'<sys_created_by>{es["sys_created_by"]}</sys_created_by>'
            f'<sys_created_on>{es["sys_created_on"]}</sys_created_on>'
            f'<sys_id>{es["sys_id"]}</sys_id>'
            f'<sys_mod_count>{es["sys_mod_count"]}</sys_mod_count>'
            f'<sys_updated_by>{es["sys_updated_by"]}</sys_updated_by>'
            f'<sys_updated_on>{es["sys_updated_on"]}</sys_updated_on>'
            '<table>scan_script_only_check</table>'
            '<use_es_latest>true</use_es_latest>'
            '</sys_es_latest_script>'
        )

    script = rec.get('script', '')

    inner = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<record_update table="scan_script_only_check">'
        '<scan_script_only_check action="INSERT_OR_UPDATE">'
        f'<active>{rec["active"]}</active>'
        f'<category>{xml_escape(rec.get("category", "security"))}</category>'
        f'{xml_elem_or_empty("description", rec.get("description", ""))}'
        f'{xml_elem_or_empty("documentation_url", rec.get("documentation_url", ""))}'
        f'<finding_type>{xml_escape(rec.get("finding_type", "scan_finding"))}</finding_type>'
        f'<name>{xml_escape(rec["name"])}</name>'
        f'<priority>{rec.get("priority", "3")}</priority>'
        f'{xml_elem_or_empty("resolution_details", rec.get("resolution_details", ""))}'
        f'{xml_elem_or_empty("run_condition", rec.get("run_condition", ""))}'
        f'<score_max>{rec.get("score_max", "100")}</score_max>'
        f'<score_min>{rec.get("score_min", "0")}</score_min>'
        f'<score_scale>{rec.get("score_scale", "1")}</score_scale>'
        f'<script><![CDATA[{script}]]></script>'
        f'{xml_elem_or_empty("short_description", rec.get("short_description", ""))}'
        f'<sys_class_name>{rec.get("sys_class_name", "scan_script_only_check")}</sys_class_name>'
        f'<sys_created_by>{rec["sys_created_by"]}</sys_created_by>'
        f'<sys_created_on>{rec["sys_created_on"]}</sys_created_on>'
        f'<sys_id>{rec["sys_id"]}</sys_id>'
        f'<sys_mod_count>{rec["sys_mod_count"]}</sys_mod_count>'
        f'<sys_name>{xml_escape(rec["name"])}</sys_name>'
        '<sys_package display_value="Global" source="global">global</sys_package>'
        '<sys_policy/>'
        '<sys_scope display_value="Global">global</sys_scope>'
        f'<sys_update_name>scan_script_only_check_{rec["sys_id"]}</sys_update_name>'
        f'<sys_updated_by>{rec["sys_updated_by"]}</sys_updated_by>'
        f'<sys_updated_on>{rec["sys_updated_on"]}</sys_updated_on>'
        '</scan_script_only_check>'
        f'<sys_translated_text action="delete_multiple" query="documentkey={rec["sys_id"]}"/>'
        f'{es_section}'
        '</record_update>'
    )
    return inner


# ── XML generation ───────────────────────────────────────────────────────────

def build_wrapper(record_name, record_type, target_name, payload_str,
                  wrapper_meta, update_set_sys_id, update_set_name, is_cdata):
    """Build a sys_update_xml element as a list of lines."""
    if is_cdata:
        payload_content = f'<![CDATA[{payload_str}]]>'
    else:
        payload_content = entity_encode(payload_str)

    payload_hash = java_string_hashcode(payload_str)

    # Generate new update_guid, prepend to history
    new_guid = new_sys_id()
    old_history = wrapper_meta.get('update_guid_history', '')
    new_history = f'{new_guid}:{payload_hash}'
    if old_history:
        new_history = f'{new_history},{old_history}'

    lines = [
        '<sys_update_xml action="INSERT_OR_UPDATE">',
        '<action>INSERT_OR_UPDATE</action>',
        '<application display_value="Global">global</application>',
        '<category>customer</category>',
        '<comments/>',
        f'<name>{record_name}</name>',
        f'<payload>{payload_content}</payload>',
        f'<payload_hash>{payload_hash}</payload_hash>',
        f'<remote_update_set display_value="{xml_escape(update_set_name)}">{update_set_sys_id}</remote_update_set>',
        '<replace_on_upgrade>false</replace_on_upgrade>',
        f'<sys_created_by>admin</sys_created_by>',
        f'<sys_created_on>{NOW}</sys_created_on>',
        f'<sys_id>{wrapper_meta.get("wrapper_sys_id", new_sys_id())}</sys_id>',
        '<sys_mod_count>0</sys_mod_count>',
        f'<sys_recorded_at>{wrapper_meta.get("sys_recorded_at", new_sys_id()[:18])}</sys_recorded_at>',
        f'<sys_updated_by>admin</sys_updated_by>',
        f'<sys_updated_on>{NOW}</sys_updated_on>',
        '<table/>',
        f'<target_name>{xml_escape(target_name)}</target_name>',
        f'<type>{record_type}</type>',
        '<update_domain>global</update_domain>',
        f'<update_guid>{new_guid}</update_guid>',
        f'<update_guid_history>{new_history}</update_guid_history>',
        '<update_set display_value=""/>',
        '<view/>',
        '</sys_update_xml>',
    ]
    return lines


def generate_update_set(data, output_path, version):
    """Generate the complete Update Set XML."""
    update_set_name = f'CS&T Instance Hardening Checks v{version}'
    update_set_sys_id = new_sys_id()
    remote_sys_id = new_sys_id()

    print(f"\nGenerating: {output_path}")
    print(f"  Name: {update_set_name}")
    print(f"  Timestamp: {NOW}")

    all_lines = []

    # XML header and update set record
    all_lines.append(f'<?xml version="1.0" encoding="UTF-8"?><unload unload_date="{NOW}">')
    all_lines.append('<sys_remote_update_set action="INSERT_OR_UPDATE">')
    all_lines.append('<application display_value="Global">global</application>')
    all_lines.append('<application_name>Global</application_name>')
    all_lines.append('<application_scope>global</application_scope>')
    all_lines.append('<application_version/>')
    all_lines.append('<collisions/>')
    all_lines.append('<commit_date/>')
    all_lines.append('<deleted/>')
    all_lines.append('<description/>')
    all_lines.append('<inserted/>')
    all_lines.append(f'<name>{xml_escape(update_set_name)}</name>')
    all_lines.append('<origin_sys_id/>')
    all_lines.append('<parent display_value=""/>')
    all_lines.append('<release_date/>')
    all_lines.append('<remote_base_update_set display_value=""/>')
    all_lines.append('<remote_parent_id/>')
    all_lines.append(f'<remote_sys_id>{remote_sys_id}</remote_sys_id>')
    all_lines.append('<state>loaded</state>')
    all_lines.append('<summary/>')
    all_lines.append('<sys_class_name>sys_remote_update_set</sys_class_name>')
    all_lines.append('<sys_created_by>admin</sys_created_by>')
    all_lines.append(f'<sys_created_on>{NOW}</sys_created_on>')
    all_lines.append(f'<sys_id>{update_set_sys_id}</sys_id>')
    all_lines.append('<sys_mod_count>0</sys_mod_count>')
    all_lines.append('<sys_updated_by>admin</sys_updated_by>')
    all_lines.append(f'<sys_updated_on>{NOW}</sys_updated_on>')
    all_lines.append('<update_set display_value=""/>')
    all_lines.append('<update_source display_value=""/>')
    all_lines.append('<updated/>')
    all_lines.append('</sys_remote_update_set>')

    # Process records in original order
    for record_type, record_id in data['record_order']:
        if record_type == 'suite':
            rec = data['suites'][record_id]
            rec['sys_mod_count'] += 1
            rec['sys_updated_on'] = NOW
            rec['sys_updated_by'] = 'admin'
            payload = build_suite_payload(rec)
            lines = build_wrapper(
                record_name=f'scan_check_suite_{rec["sys_id"]}',
                record_type='Suite',
                target_name=rec['name'],
                payload_str=payload,
                wrapper_meta=rec['_wrapper'],
                update_set_sys_id=update_set_sys_id,
                update_set_name=update_set_name,
                is_cdata=True,
            )
            all_lines.extend(lines)

        elif record_type == 'm2m':
            rec = data['m2m'][record_id]
            rec['sys_mod_count'] += 1
            rec['sys_updated_on'] = NOW
            rec['sys_updated_by'] = 'admin'
            payload = build_m2m_payload(rec)
            lines = build_wrapper(
                record_name=f'scan_check_suite_check_{rec["sys_id"]}',
                record_type='Suite Check',
                target_name=rec['check_value'],
                payload_str=payload,
                wrapper_meta=rec['_wrapper'],
                update_set_sys_id=update_set_sys_id,
                update_set_name=update_set_name,
                is_cdata=True,
            )
            all_lines.extend(lines)

        elif record_type == 'check':
            rec = data['checks'][record_id]
            rec['sys_mod_count'] += 1
            rec['sys_updated_on'] = NOW
            rec['sys_updated_by'] = 'admin'
            payload = build_check_payload(rec)
            lines = build_wrapper(
                record_name=f'scan_script_only_check_{rec["sys_id"]}',
                record_type='Script Only Check',
                target_name=rec['name'],
                payload_str=payload,
                wrapper_meta=rec['_wrapper'],
                update_set_sys_id=update_set_sys_id,
                update_set_name=update_set_name,
                is_cdata=False,  # check payloads are entity-encoded
            )
            all_lines.extend(lines)

    all_lines.append('</unload>')

    # Write output
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(all_lines))
        f.write('\n')

    file_size = os.path.getsize(output_path)
    print(f"  Wrote {file_size:,} bytes")
    print(f"  Records: {len(data['suites'])} suites, {len(data['m2m'])} m2m, {len(data['checks'])} checks")


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description='Generate ServiceNow Update Set XML')
    parser.add_argument('--input', default=None, help='Input XML path (default: latest in dist/)')
    parser.add_argument('--output', default=None, help='Output XML path')
    parser.add_argument('--version', default=None, help='Version number (e.g., 1.4)')
    args = parser.parse_args()

    # Find latest input XML if not specified
    input_path = args.input
    if not input_path:
        xml_files = sorted([f for f in os.listdir(DIST_DIR) if f.endswith('.xml') and 'archive' not in f.lower()])
        if not xml_files:
            print("ERROR: No XML files found in dist/")
            return
        input_path = os.path.join(DIST_DIR, xml_files[-1])

    # Determine version
    version = args.version
    if not version:
        # Auto-increment from input filename
        m = re.search(r'v(\d+\.\d+)', os.path.basename(input_path))
        if m:
            old_ver = float(m.group(1))
            version = f'{old_ver + 0.1:.1f}'
        else:
            version = '1.0'

    # Determine output path
    output_path = args.output
    if not output_path:
        output_path = os.path.join(DIST_DIR, f'CS&T Instance Hardening Checks v{version}.xml')

    # Parse, merge, generate
    data = parse_update_set(input_path)
    merge_source_files(data, SCANS_DIR)
    generate_update_set(data, output_path, version)
    print("\nDone!")


if __name__ == '__main__':
    main()
