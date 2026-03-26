#!/usr/bin/env python3
"""
Update scan check JSON files with resolution_details, documentation_url,
and fix truncated short_descriptions.
"""

import json
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SCANS_DIR = os.path.join(BASE_DIR, 'scans')

# Updates for level-1, level-2, level-3, level-next
# Key: (suite_dir, filename_without_ext) -> {field: value}
UPDATES = {
    # ── Level 1 ──────────────────────────────────────────────────────────
    ('level-1', 'cstaces-1a-admin-users'): {
        'resolution_details': (
            'Review the list of users with admin, security_admin, and user_admin roles. '
            'Remove admin roles from users who do not have a documented business need. '
            'Replace admin with more specific roles where possible (e.g., catalog_admin, knowledge_admin). '
            'For service accounts, ensure the minimum required roles are assigned. '
            'Establish a quarterly access review process for all privileged accounts.'
        ),
        'documentation_url': 'https://support.servicenow.com/kb?id=kb_article_view&sysparm_article=KB0856250',
    },
    ('level-1', 'cstaces-1b-multiple-high'): {
        'resolution_details': (
            'Review each user holding multiple high-privilege roles. '
            'Determine whether role accumulation is justified by the user\'s job function. '
            'Where possible, consolidate to a single appropriate role or create a custom role with only the necessary permissions. '
            'Document approved exceptions with business justification and implement separation of duties policies to prevent future accumulation.'
        ),
        'documentation_url': 'https://support.servicenow.com/kb?id=kb_article_view&sysparm_article=KB0856250',
    },
    ('level-1', 'cstaces-1c-deprovioned-60newer'): {
        'resolution_details': (
            'Remove all privileged role assignments from inactive users immediately. '
            'For direct role assignments, navigate to the user record and remove each elevated role. '
            'For group-inherited roles, remove the user from groups that grant privileged access. '
            'Update offboarding procedures to include role revocation as a mandatory step before or upon account deactivation.'
        ),
        'documentation_url': 'https://support.servicenow.com/kb?id=kb_article_view&sysparm_article=KB0856250',
    },
    ('level-1', 'cstaces-1c2-deprovsioned-60older'): {
        'resolution_details': (
            'Remove all privileged role assignments from these long-inactive users. '
            'Since these accounts have been inactive for over 60 days, the risk of accidental reactivation restoring elevated access is significant. '
            'Prioritize removing direct role assignments first, then address group memberships. '
            'Consider implementing automated role revocation as part of your deprovisioning workflow.'
        ),
        'documentation_url': 'https://support.servicenow.com/kb?id=kb_article_view&sysparm_article=KB0856250',
    },
    ('level-1', 'cstaces-3b-has-impersonator'): {
        'resolution_details': (
            'Review all users with impersonation capability. '
            'Remove the impersonator role from users who do not have a documented need. '
            'For users who gain impersonation through admin or security_admin roles, evaluate whether those roles are necessary or if more restrictive roles would suffice. '
            'Enable impersonation audit logging via the glide.sys.audit_impersonation property.'
        ),
        'documentation_url': 'https://support.servicenow.com/kb?id=kb_article_view&sysparm_article=KB0856250',
    },
    ('level-1', 'cstaces-3b2-nested-impersonator'): {
        'resolution_details': (
            'Review roles that contain the impersonator role as a child in the role hierarchy. '
            'Evaluate whether impersonation capability is intentionally included in each parent role. '
            'Where impersonation is not required, remove the impersonator role from the role hierarchy. '
            'Document any approved exceptions with business justification.'
        ),
        'documentation_url': 'https://support.servicenow.com/kb?id=kb_article_view&sysparm_article=KB0856250',
    },
    ('level-1', 'cstaces-4a-secadmin'): {
        'resolution_details': (
            'Review all users with the security_admin role. '
            'This role controls ACLs, encryption keys, and role assignments — limit it to the smallest number of named administrators. '
            'Remove security_admin from users who do not actively manage access controls. '
            'Where possible, use delegated administration or more specific roles instead.'
        ),
        'documentation_url': 'https://support.servicenow.com/kb?id=kb_article_view&sysparm_article=KB0856250',
    },
    ('level-1', 'cstaces-5a-integration-admins'): {
        'resolution_details': (
            'Review all web-service-access-only users with admin roles. '
            'Replace admin with the minimum roles required for each integration\'s function (e.g., itil, catalog, or custom roles with specific table-level access). '
            'Test each integration after role changes to verify continued functionality. '
            'Document the required role set for each integration account.'
        ),
        'documentation_url': 'https://support.servicenow.com/kb?id=kb_article_view&sysparm_article=KB0856250',
    },

    # ── Level 2 ──────────────────────────────────────────────────────────
    ('level-2', 'cstaces-4a-secadmin'): {
        'resolution_details': (
            'Review all users with the security_admin role. '
            'This role controls ACLs, encryption keys, and role assignments — limit it to the smallest number of named administrators. '
            'Remove security_admin from users who do not actively manage access controls. '
            'Where possible, use delegated administration or more specific roles instead.'
        ),
        'documentation_url': 'https://support.servicenow.com/kb?id=kb_article_view&sysparm_article=KB0856250',
    },
    ('level-2', 'cstaces-4b-acl-modif'): {
        'resolution_details': (
            'Review recent ACL and role changes in the audit log. '
            'Verify each modification was authorized through your change management process. '
            'Investigate any unplanned or unauthorized changes, particularly those that weaken existing access controls. '
            'Implement alerts for ACL modifications to enable near-real-time detection of unauthorized changes.'
        ),
        'documentation_url': 'https://support.servicenow.com/kb?id=kb_article_view&sysparm_article=KB0856250',
    },
    ('level-2', 'cstaces-4c-self-role-grant'): {
        'resolution_details': (
            'Investigate each instance of self-granted roles, especially admin, security_admin, and impersonator. '
            'Determine whether the grants were authorized and documented. '
            'Revoke any unauthorized role assignments immediately. '
            'Implement controls to prevent or alert on self-grants of privileged roles, such as business rules or Flow Designer triggers on sys_user_has_role.'
        ),
        'documentation_url': 'https://support.servicenow.com/kb?id=kb_article_view&sysparm_article=KB0856250',
    },
    ('level-2', 'cstaces-4e-encryption-configs'): {
        'resolution_details': (
            'Review all recent changes to encryption configuration tables. '
            'Verify each modification was authorized through your change management process. '
            'Pay special attention to any deactivation of encryption contexts or key modifications. '
            'Ensure encryption keys are rotated on schedule and that key management follows your organization\'s cryptographic standards.'
        ),
        'documentation_url': 'https://docs.servicenow.com/bundle/latest/page/administer/encryption/concept/encryption-support.html',
    },
    ('level-2', 'cstaces-5b-active-oauth'): {
        'resolution_details': (
            'Review all active OAuth application registrations. '
            'Reduce access token lifetime to 30 minutes or less and refresh token lifetime to 24 hours or less where possible. '
            'Verify redirect URLs are valid and use HTTPS. '
            'Deactivate unused OAuth applications. '
            'Document business justification for any applications requiring extended token lifetimes.'
        ),
        'documentation_url': 'https://docs.servicenow.com/bundle/latest/page/administer/security/concept/c_OAuthApplications.html',
    },

    # ── Level 3 ──────────────────────────────────────────────────────────
    ('level-3', 'cstaces-2a-acl-overly-perm'): {
        'resolution_details': (
            'Review each flagged ACL and add appropriate role requirements, conditions, or scripts. '
            'For CRITICAL findings (wildcard operations), prioritize immediate remediation. '
            'Add at minimum a role requirement to each ACL. '
            'If the ACL is not needed, deactivate it rather than deleting to preserve audit history. '
            'Test changes in a sub-production instance first.'
        ),
        'documentation_url': 'https://docs.servicenow.com/bundle/latest/page/administer/contextual-security/concept/access-control-rules.html',
    },
    ('level-3', 'cstaces-2b-acls-dangerous'): {
        'resolution_details': (
            'Review each flagged ACL script for dangerous patterns. '
            'Replace unconditional grants (answer = true) with proper role or condition checks. '
            'Remove or replace dynamic references to external scripts or properties in ACL logic. '
            'Ensure ACL scripts follow deterministic evaluation patterns and do not rely on client-controllable inputs.'
        ),
        'documentation_url': 'https://docs.servicenow.com/bundle/latest/page/administer/contextual-security/concept/access-control-rules.html',
    },
    ('level-3', 'cstaces-8-domsep-users'): {
        'resolution_details': (
            'Assign an appropriate domain to each flagged user based on their organizational role. '
            'Users without domain assignment may have unintended cross-domain visibility. '
            'Review domain separation policies to ensure all new users are assigned a domain at creation. '
            'Consider implementing a business rule to enforce domain assignment on user creation.'
        ),
        'documentation_url': 'https://docs.servicenow.com/bundle/latest/page/administer/domain-separation/concept/c_DomainSeparation.html',
    },

    # ── Level Next ───────────────────────────────────────────────────────
    ('level-next', 'cstaces-5b-active-oauth'): {
        'resolution_details': (
            'Review all active OAuth application registrations. '
            'Reduce access token lifetime to 30 minutes or less and refresh token lifetime to 24 hours or less where possible. '
            'Verify redirect URLs are valid and use HTTPS. '
            'Deactivate unused OAuth applications. '
            'Document business justification for any applications requiring extended token lifetimes.'
        ),
        'documentation_url': 'https://docs.servicenow.com/bundle/latest/page/administer/security/concept/c_OAuthApplications.html',
    },
    ('level-next', 'cstaces-6-br-priv-esc'): {
        'resolution_details': (
            'Review each flagged business rule script for dangerous patterns. '
            'Replace direct table manipulation of sys_user and sys_user_has_role with controlled APIs or scoped applications. '
            'Remove gs.setProperty calls unless absolutely necessary and approved through change management. '
            'Ensure business rules do not bypass abort actions or inject session data. '
            'Restrict modification access to business rule records.'
        ),
        'documentation_url': 'https://docs.servicenow.com/bundle/latest/page/script/server-scripting/concept/c_BusinessRules.html',
    },
    ('level-next', 'cstaces-7-ui-bypass'): {
        'resolution_details': (
            'Review each UI policy that sets fields to non-mandatory. '
            'Determine whether the override is intentional and documented. '
            'Where the override is not justified, remove or modify the UI policy action. '
            'For justified exceptions, ensure server-side validation (e.g., business rules) enforces the mandatory requirement to prevent API-based bypasses.'
        ),
        'documentation_url': 'https://docs.servicenow.com/bundle/latest/page/administer/form-administration/concept/c_UIPolicies.html',
    },
    ('level-next', 'cstaces-9a-auth-session-prop'): {
        'resolution_details': (
            'Review the reported authentication and session properties. '
            'Disable guest access unless explicitly required (glide.security.disable.guest = true). '
            'Enable SSO enforcement where available. '
            'Set session timeout values to meet your organization\'s security policy (recommended: 30 minutes or less for idle timeout). '
            'Enable multi-provider SSO if multiple identity providers are in use.'
        ),
        'documentation_url': 'https://docs.servicenow.com/bundle/latest/page/administer/security/reference/hardening-instance-security.html',
    },
    ('level-next', 'cstaces-9b-admin-no-mfa'): {
        'resolution_details': (
            'Enroll all admin and security_admin users in multi-factor authentication. '
            'Navigate to Multi-Factor Authentication > MFA Policy and ensure policies cover all privileged roles. '
            'For users authenticating via SSO, verify that the identity provider enforces MFA. '
            'Consider requiring MFA for all users, not just administrators.'
        ),
        'documentation_url': 'https://docs.servicenow.com/bundle/latest/page/administer/security/concept/multi-factor-authentication.html',
    },
    ('level-next', 'cstaces-10-sched-job-admin'): {
        'resolution_details': (
            'Review each scheduled job running as an admin user. '
            'Create dedicated service accounts with minimum required roles for each job. '
            'Update the Run As field to use the least-privileged service account. '
            'Test each job after the change to verify it functions correctly. '
            'Document the required role set for each scheduled job.'
        ),
        'documentation_url': 'https://docs.servicenow.com/bundle/latest/page/administer/security/reference/hardening-instance-security.html',
    },
}

# Truncated short_description fixes for level-knowledge
SHORT_DESC_FIXES = {
    'cstaces-11a-prop-block-no-criteria':
        'glide.knowman.block_access_with_no_user_criteria must be set to true to block unauthenticated access to KBs without user criteria',
    'cstaces-11b-prop-apply-article-criteria':
        'glide.knowman.apply_article_read_criteria must be true so that article-level user criteria is enforced',
    'cstaces-11c-prop-search-role-security':
        'glide.knowman.search.apply_role_based_security must be true to enforce role-based security in knowledge search',
    'cstaces-11d-prop-show-unpublished':
        'glide.knowman.show_unpublished must not be true to prevent draft and review-state articles from being visible',
    'cstaces-11e-prop-draft-view-roles':
        'glide.knowman.section.view_roles.draft should be restricted to knowledge management roles only',
    'cstaces-11f-kb-no-can-read':
        'Active knowledge bases must have at least one Can Read user criteria to explicitly control access',
    'cstaces-11g-kb-no-cannot-read':
        'Active knowledge bases should have Cannot Read user criteria to explicitly deny unauthorized access',
    'cstaces-11h-kb-no-can-contrib-oob-is':
        'Active knowledge bases with empty Can Contribute criteria implicitly allow all authenticated users to contribute',
    'cstaces-11i-kb-uses-any-user':
        'Knowledge bases must not use the built-in Any User or Any user for kb criteria in Can Read',
    'cstaces-11j-kb-guest-not-denied':
        'The Guest user must be included in a Cannot Read user criteria on every active knowledge base',
    'cstaces-11k-kb-contrib-no-read':
        'Knowledge bases with Can Contribute set but no Can Read criteria create a dangerous access gap',
    'cstaces-11l-kb-pre-2022-no-guest-deny':
        'Knowledge bases created before mid-2022 lack automatic Guest user denial and must be updated manually',
    'cstaces-11m-br-guest-user-inactive':
        'The Guest User Business Rule that auto-denies Guest access on new KBs must remain active',
    'cstaces-11n-public-kb-pages':
        'KB endpoint pages (kb_view, kb_find, kb_home, kb_list) must not be listed in sys_public',
    'cstaces-11o-public-kb-widget':
        'Service Portal KB widgets must not have the public flag enabled, which allows unauthenticated access',
    'cstaces-11p-acl-km-no-auth':
        'The sn_km_api Knowledge Management REST API must require authentication to prevent unauthenticated access',
    'cstaces-11q-acl-kb-empty':
        'ACLs on the kb_knowledge table must not be empty (no role, condition, script, or security attribute)',
    'cstaces-11r-acl-kb-custom':
        'Custom ACLs on the kb_knowledge table may override user criteria restrictions and should be reviewed',
    'cstaces-11s-kba-no-criteria-open-kb-oob-is':
        'Published articles in knowledge bases with no Can Read user criteria are at high risk of exposure',
    'cstaces-11t-kba-public-role':
        'Articles with the public role in the roles field should be reviewed to confirm intentional public access',
    'cstaces-11u-uc-scripted-on-kb':
        'Knowledge bases using scripted (advanced) user criteria should be reviewed for potential bypasses',
    'cstaces-11v-kb-commenting-enabled-oob-sc':
        'Knowledge bases with commenting enabled should be reviewed, as comments can be used for data exfiltration',
}


def update_json_file(filepath, updates):
    """Read a JSON file, apply updates, write back."""
    with open(filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)

    changed = False
    for key, value in updates.items():
        if data.get(key) != value:
            data[key] = value
            changed = True

    if changed:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.write('\n')
        return True
    return False


def main():
    updated = 0

    # Update level-1/2/3/next files
    for (suite_dir, filename), fields in UPDATES.items():
        filepath = os.path.join(SCANS_DIR, suite_dir, filename + '.json')
        if not os.path.exists(filepath):
            print(f"  WARNING: {filepath} does not exist")
            continue

        if update_json_file(filepath, fields):
            updated += 1
            print(f"  Updated: scans/{suite_dir}/{filename}.json")
        else:
            print(f"  No change: scans/{suite_dir}/{filename}.json")

    # Fix truncated short_descriptions in level-knowledge
    for filename, new_sd in SHORT_DESC_FIXES.items():
        filepath = os.path.join(SCANS_DIR, 'level-knowledge', filename + '.json')
        if not os.path.exists(filepath):
            print(f"  WARNING: {filepath} does not exist")
            continue

        if update_json_file(filepath, {'short_description': new_sd}):
            updated += 1
            print(f"  Updated: scans/level-knowledge/{filename}.json (short_description)")
        else:
            print(f"  No change: scans/level-knowledge/{filename}.json")

    print(f"\nDone! Updated {updated} files.")


if __name__ == '__main__':
    main()
