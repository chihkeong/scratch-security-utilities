"""
AWS IAM Policy & Role Access Analyzer
This script:
- Lists all IAM policies attached to users, groups, and roles
- Shows who can assume each role (including group membership)
- Tracks where permissions come from (direct user or group)
- Outputs structured data to JSON, CSV, and HTML for analysis

Features:
- Uses policy cache to reduce redundant API calls
- Shows users in groups that can assume roles
- Returns structured output (JSON/CSV/HTML)
- No threading - keeps execution simple and predictable
- File-based caching for faster re-runs

Version: 4.0
Original file: testAWS4.py
"""

import boto3
import json
from botocore.exceptions import ClientError
from fnmatch import fnmatch
import csv
from jinja2 import Template  # Needed for save_to_html
import os  # For file-based caching

# File to cache list of policies with attachments
POLICY_CACHE_FILE = "attached_policies_cache.json"

# Use the 'cloudpt' AWS profile
session = boto3.Session(profile_name='cloudpt')
# Initialize the IAM client using the session
iam = session.client('iam')

# Toggle enhanced output showing why users can assume roles
# When True, shows {"user": {"source": "direct"}} or {"source": "group:GroupName"}
ENHANCED_USER_SOURCE = True

# Global policy cache to avoid redundant API calls
POLICY_CACHE = {}


def get_cached_policy(policy_arn):
    """
    Returns the default version of the IAM policy document from cache or AWS API.
    This reduces repeated network calls for the same policy.
    :param policy_arn: ARN of the IAM policy
    :return: policy document or empty dict on error
    """
    if policy_arn in POLICY_CACHE:
        return POLICY_CACHE[policy_arn]
    try:
        # Get policy metadata
        policy_meta = iam.get_policy(PolicyArn=policy_arn)
        version_id = policy_meta['Policy']['DefaultVersionId']
        # Get actual policy document
        policy_doc = iam.get_policy_version(
            PolicyArn=policy_arn,
            VersionId=version_id
        )['PolicyVersion']['Document']
        # Store in cache
        POLICY_CACHE[policy_arn] = policy_doc
        return policy_doc
    except Exception as e:
        print(f"[ERROR] Could not fetch policy {policy_arn}: {e}")
        return {}


def get_group_members(group_name):
    """
    Returns list of user names in the given IAM group.
    Used to enrich metadata block with group membership details.
    :param group_name: Name of the IAM group
    :return: List of usernames
    """
    try:
        paginator = iam.get_paginator('get_group')
        members = []
        for page in paginator.paginate(GroupName=group_name):
            for user in page.get('Users', []):
                members.append(user['UserName'])
        return list(set(members))
    except Exception as e:
        print(f"[ERROR] Could not fetch members for group '{group_name}': {e}")
        return []


def get_role_assume_info(role_name):
    """
    Given a single role name, returns detailed info about:
    - Trust policy
    - Who is allowed to assume it (users, groups, services, cross-account, federated)
    - Whether inline/wildcard permissions apply
    :param role_name: Name of IAM role
    :return: dict
    """
    session = boto3.Session(profile_name='cloudpt')
    iam = session.client('iam')
    current_account_id = session.client('sts').get_caller_identity()['Account']

    try:
        # Get role data
        role = iam.get_role(RoleName=role_name)['Role']
        role_arn = role['Arn']
        trust_policy = role['AssumeRolePolicyDocument']

        # Analyze trust policy
        trusted_principals = []
        cross_accounts = []
        services = []
        federated = []
        statements = trust_policy.get("Statement", [])
        for stmt in statements:
            principal = stmt.get("Principal", {})
            if isinstance(principal, dict):
                aws_principal = principal.get("AWS")
                service_principal = principal.get("Service")
                federated_principal = principal.get("Federated")
                if aws_principal:
                    if isinstance(aws_principal, str):
                        trusted_principals.append(aws_principal)
                    elif isinstance(aws_principal, list):
                        trusted_principals.extend(aws_principal)
                if service_principal:
                    if isinstance(service_principal, str):
                        services.append(service_principal)
                    elif isinstance(service_principal, list):
                        services.extend(service_principal)
                if federated_principal:
                    if isinstance(federated_principal, str):
                        federated.append(federated_principal)
                    elif isinstance(federated_principal, list):
                        federated.extend(federated_principal)

        # Extract cross-account principals
        for arn in trusted_principals:
            if ":root" in arn:
                account_id = arn.split(":")[4]
                if account_id != current_account_id:
                    cross_accounts.append(arn)
            elif arn.startswith("arn:aws:iam::"):
                account_id = arn.split(":")[4]
                if account_id != current_account_id:
                    cross_accounts.append(arn)

        # Find users/groups with sts:AssumeRole permission
        users_allowed = {}  # { username: { "source": "..."} }
        groups_allowed = set()
        resolved_users = {}  # Merged dict of all users with sources

        def check_policy_statements(policy_doc, resource_arn, matched_users=None, matched_groups=None):
            """
            Helper function to scan IAM policy documents for sts:AssumeRole permissions.
            Tracks which user/group gets permission and where it came from.
            """
            for statement in policy_doc.get('Statement', []):
                if statement.get('Effect') == 'Allow' and 'sts:AssumeRole' in statement.get('Action', []):
                    resource = statement.get('Resource', '')
                    if isinstance(resource, str):
                        if fnmatch(resource_arn, resource):
                            if matched_users:
                                matched_users[user_name] = {"source": f"direct (policy: {policy_arn})"}
                            if matched_groups:
                                matched_groups.add(group_name)
                    elif isinstance(resource, list):
                        for r in resource:
                            if fnmatch(resource_arn, r):
                                if matched_users:
                                    matched_users[user_name] = {"source": f"direct (policy: {policy_arn})"}
                                if matched_groups:
                                    matched_groups.add(group_name)

        global user_name, group_name
        # Check users
        user_paginator = iam.get_paginator('list_users')
        for page in user_paginator.paginate():
            for user in page['Users']:
                user_name = user['UserName']
                # Attached policies
                policy_paginator = iam.get_paginator('list_attached_user_policies')
                for pol_page in policy_paginator.paginate(UserName=user_name):
                    for policy in pol_page['AttachedPolicies']:
                        policy_arn = policy['PolicyArn']
                        policy_doc = get_cached_policy(policy_arn)
                        check_policy_statements(policy_doc, role_arn, matched_users=users_allowed)
                # Inline policies
                inline_paginator = iam.get_paginator('list_user_policies')
                for inline_page in inline_paginator.paginate(UserName=user_name):
                    for policy_name in inline_page['PolicyNames']:
                        policy_doc = iam.get_user_policy(UserName=user_name, PolicyName=policy_name)['PolicyDocument']
                        check_policy_statements(policy_doc, role_arn, matched_users=users_allowed)

        # Check groups
        group_paginator = iam.get_paginator('list_groups')
        for page in group_paginator.paginate():
            for group in page['Groups']:
                group_name = group['GroupName']
                # Attached policies
                policy_paginator = iam.get_paginator('list_attached_group_policies')
                for pol_page in policy_paginator.paginate(GroupName=group_name):
                    for policy in pol_page['AttachedPolicies']:
                        policy_arn = policy['PolicyArn']
                        policy_doc = get_cached_policy(policy_arn)
                        check_policy_statements(policy_doc, role_arn, matched_groups=groups_allowed)
                # Inline policies
                inline_paginator = iam.get_paginator('list_group_policies')
                for inline_page in inline_paginator.paginate(GroupName=group_name):
                    for policy_name in inline_page['PolicyNames']:
                        policy_doc = iam.get_group_policy(GroupName=group_name, PolicyName=policy_name)['PolicyDocument']
                        check_policy_statements(policy_doc, role_arn, matched_groups=groups_allowed)
                # Get users in this group
                user_in_group = iam.get_group(GroupName=group_name)
                for user in user_in_group.get('Users', []):
                    user_in_group_name = user['UserName']
                    if group_name in groups_allowed:
                        resolved_users[user_in_group_name] = {
                            "source": f"group:{group_name}"
                        }

        # Merge direct-assigned users
        for user, info in users_allowed.items():
            resolved_users[user] = info

        # Final format
        if not ENHANCED_USER_SOURCE:
            resolved_users = list(resolved_users.keys())

        return {
            "role_name": role_name,
            "role_arn": role_arn,
            "trust_policy": trust_policy,
            "trusted_principals": list(set(trusted_principals)),
            "cross_accounts": list(set(cross_accounts)),
            "services": list(set(services)),
            "federated": list(set(federated)),
            "allowed_users_direct": list(users_allowed.keys()),
            "allowed_groups": list(groups_allowed),
            "resolved_users": resolved_users
        }
    except Exception as e:
        print(f"[ERROR] Could not retrieve info for role '{role_name}': {e}")
        return {"role_name": role_name, "error": str(e)}


def get_roles_assume_info(role_names):
    """
    Given a list of role names, returns assume info for each.
    Uses simple loop (no threading).
    :param role_names: List of role names
    :return: Dict mapping role name to role info
    """
    results = {}
    for role_name in role_names:
        result = get_role_assume_info(role_name)
        results[role_name] = result
    return results


def get_policy_details(policy_arn):
    """
    Gets the latest version of an IAM policy document.
    :param policy_arn: ARN of the IAM policy
    :return: Policy document or empty dict
    """
    try:
        policy = iam.get_policy(PolicyArn=policy_arn)
        default_version_id = policy['Policy']['DefaultVersionId']
        policy_version = iam.get_policy_version(PolicyArn=policy_arn, VersionId=default_version_id)
        return policy_version['PolicyVersion']['Document']
    except ClientError as e:
        print(f"[ERROR] Unable to retrieve policy document: {e}")
        return {}


def list_entities_for_policy(policy_arn):
    """
    Lists users, roles, and groups that are attached to the given IAM policy.
    Also includes group members when available.
    :param policy_arn: ARN of the IAM policy
    :return: Dict of users, roles, and groups (with members)
    """
    users = []
    roles = []
    groups = {}
    paginator = iam.get_paginator('list_entities_for_policy')
    for page in paginator.paginate(PolicyArn=policy_arn):
        users.extend(page.get('PolicyUsers', []))
        roles.extend(page.get('PolicyRoles', []))
        for group in page.get('PolicyGroups', []):
            group_name = group['GroupName']
            groups[group_name] = get_group_members(group_name)
    return {
        'users': [u['UserName'] for u in users],
        'roles': [r['RoleName'] for r in roles],
        'groups': groups
    }


def save_attached_policies_to_file(policy_list):
    """
    Saves list of policy ARNs to a JSON file for faster reuse.
    :param policy_list: List of policy ARNs
    """
    with open(POLICY_CACHE_FILE, 'w') as f:
        json.dump({"policies": policy_list}, f, indent=2)
    print(f"✅ Saved {len(policy_list)} attached policy ARNs to {POLICY_CACHE_FILE}")


def load_attached_policies_from_file():
    """
    Loads list of policy ARNs from cache file if it exists.
    :return: List of policy ARNs or None if file doesn't exist
    """
    if os.path.exists(POLICY_CACHE_FILE):
        try:
            with open(POLICY_CACHE_FILE, 'r') as f:
                data = json.load(f)
                print(f"✅ Loaded {len(data['policies'])} policies from {POLICY_CACHE_FILE}")
                return data.get("policies", [])
        except Exception as e:
            print(f"[ERROR] Could not load cached policies: {e}")
    return None


def save_to_json(data):
    """Saves output to JSON file"""
    with open("output.json", "w") as f:
        json.dump(data, f, indent=4, default=str)
    print("✅ Saved output.json")


def save_to_csv(data):
    """Saves output to CSV file"""
    headers = [
        'Policy Name',
        'ARN',
        'Attached Users',
        'Attached Groups',
        'Roles (Who Can Assume)',
        'Policy Document'
    ]
    with open("output.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        for item in data:
            meta = item["metadata"]
            role_assume_info = meta.get("Role Assume Info", {})
            # Extract role assume info
            roles_info = []
            for role_name, role_data in role_assume_info.items():
                if "error" in role_data:
                    roles_info.append(f"{role_name} (Error: {role_data['error']})")
                    continue
                entities = []
                if role_data.get("resolved_users"):
                    entities.append("Users:\n" + "\n".join([
                        f"  {user} ({details['source']})"
                        for user, details in role_data["resolved_users"].items()
                    ]))
                if role_data.get("services"):
                    entities.append("Services:\n" + "\n".join([f"  {service}" for service in role_data["services"]]))
                if role_data.get("cross_accounts"):
                    entities.append("Cross-Accounts:\n" + "\n".join([f"  {account}" for account in role_data["cross_accounts"]]))
                if role_data.get("federated"):
                    entities.append("Federated Identities:\n" + "\n".join([f"  {identity}" for identity in role_data["federated"]]))
                if entities:
                    roles_info.append(f"{role_name}:\n" + "\n".join(entities))
                else:
                    roles_info.append(f"{role_name}: No entities allowed")
            # Write row
            writer.writerow({
                "Policy Name": meta["Policy Name"],
                "ARN": meta["ARN"],
                "Attached Users": ", ".join(meta["Attached To"]["Users"]),
                "Attached Groups": ", ".join([
                    f"{group}({len(users)})"
                    for group, users in meta["Attached To"]["Groups"].items()
                ]),
                "Roles (Who Can Assume)": "\n\n".join(roles_info),
                "Policy Document": json.dumps(item["policy_document"], indent=2)
            })
    print("✅ Saved output.csv")


def save_to_html(data):
    """Saves output to HTML file with expandable JSON view"""
    html_template = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>IAM Policies</title>
        <style>
            body { font-family: Arial, sans-serif; padding: 20px; }
            table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
            th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
            th { background-color: #f2f2f2; }
            h2 { color: #2c3e50; }
            .policy-json {
                white-space: pre-wrap;
                background-color: #f7f7f7;
                border: 1px solid #ccc;
                padding: 10px;
                display: none;
            }
            .toggle-btn {
                cursor: pointer;
                color: blue;
                text-decoration: underline;
            }
        </style>
    </head>
    <body>
        <h2>AWS IAM Policies - Attached to Users/Roles/Groups</h2>
        <table>
            <thead>
                <tr>
                    <th>Policy Name</th>
                    <th>ARN</th>
                    <th>Users</th>
                    <th>Groups</th>
                    <th>Roles (Who Can Assume)</th>
                    <th>Policy Document</th>
                </tr>
            </thead>
            <tbody>
                {% for item in data %}
                <tr>
                    <td>{{ item.metadata['Policy Name'] }}</td>
                    <td>{{ item.metadata['ARN'] }}</td>
                    <td>{{ item.metadata['Attached To']['Users'] | join(', ') }}</td>
                    <td>
                        {% for group, members in item.metadata['Attached To']['Groups'].items() %}
                        <strong>{{ group }}</strong>: {{ members | join(', ') }}<br>
                        {% endfor %}
                    </td>
                    <td>
                        {% for role_name, role_data in item.metadata['Role Assume Info'].items() %}
                        {% if 'error' in role_data %}
                            {{ role_name }} (Error: {{ role_data['error'] }})
                        {% else %}
                            {{ role_name }}:<br>
                            {% if role_data['resolved_users'] %}
                                Users:<br>
                                {% for user, details in role_data['resolved_users'].items() %}
                                    &nbsp;&nbsp;{{ user }} ({{ details['source'] }})<br>
                                {% endfor %}
                            {% endif %}
                            {% if role_data['services'] %}
                                Services:<br>
                                {% for service in role_data['services'] %}
                                    &nbsp;&nbsp;{{ service }}<br>
                                {% endfor %}
                            {% endif %}
                            {% if role_data['cross_accounts'] %}
                                Cross-Accounts:<br>
                                {% for account in role_data['cross_accounts'] %}
                                    &nbsp;&nbsp;{{ account }}<br>
                                {% endfor %}
                            {% endif %}
                            {% if role_data['federated'] %}
                                Federated Identities:<br>
                                {% for identity in role_data['federated'] %}
                                    &nbsp;&nbsp;{{ identity }}<br>
                                {% endfor %}
                            {% endif %}
                        {% endif %}
                        <br>
                        {% endfor %}
                    </td>
                    <td>
                        <span class="toggle-btn" onclick="togglePolicy(this)">Show</span>
                        <div class="policy-json">{{ item.policy_document_json }}</div>
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        <script>
            function togglePolicy(button) {
                const container = button.nextElementSibling;
                const isVisible = container.style.display === 'block';
                container.style.display = isVisible ? 'none' : 'block';
                button.textContent = isVisible ? 'Show' : 'Hide';
            }
        </script>
    </body>
    </html>
    """
    processed_data = []
    for item in data:
        processed_data.append({
            "metadata": item["metadata"],
            "policy_document_json": json.dumps(item["policy_document"], indent=2)
        })
    template = Template(html_template)
    rendered_html = template.render(data=processed_data)
    with open("output.html", "w", encoding="utf-8") as f:
        f.write(rendered_html)
    print("✅ Saved output.html")


def main():
    """
    Main entry point of the script. Does the following:
    - Fetches all IAM policies
    - Filters only those attached to users, groups, or roles
    - For each, collects policy document and role assume info
    - Exports final output to JSON, CSV, and HTML
    """
    output_data = []
    use_cached_policies = True  # Set to True to use saved list of attached policies
    all_policies = []

    # Try to load cached policies
    cached_policies = load_attached_policies_from_file()
    if use_cached_policies and cached_policies:
        print("📦 Using cached list of policies")
        for policy_arn in cached_policies:
            try:
                policy_meta = iam.get_policy(PolicyArn=policy_arn)
                all_policies.append(policy_meta['Policy'])
            except Exception as e:
                print(f"[ERROR] Could not fetch policy {policy_arn}: {e}")
        total_policies = len(all_policies)
        print(f"📊 Found {total_policies} policies from cache.")
    else:
        print("🔍 Fetching all IAM policies...")
        paginator = iam.get_paginator('list_policies')
        all_policies = []
        for page in paginator.paginate(Scope='All'):
            all_policies.extend(page['Policies'])
        total_policies = len(all_policies)
        print(f"📊 Found {total_policies} IAM policies. Filtering only attached ones...")

    count = 0
    policy_arns_with_attachments = []

    for i, policy in enumerate(all_policies, 1):
        policy_name = policy['PolicyName']
        policy_arn = policy['Arn']

        # Get attached entities
        entities = list_entities_for_policy(policy_arn)

        # Skip unattached policies
        if not any(entities.values()):
            if i % 50 == 0 or i == total_policies:
                print(f"⏳ Processed {i}/{total_policies} policies... (skipping unattached)")
            continue

        policy_arns_with_attachments.append(policy_arn)
        count += 1
        if count % 10 == 0 or i == total_policies:
            print(f"⏳ Processed {i}/{total_policies} policies... found {count} attached so far.")

        # Build metadata block
        metadata_block = {
            "Policy Name": policy_name,
            "ARN": policy_arn,
            "Attached To": {
                "Users": entities['users'],
                "Roles": entities['roles'],
                "Groups": entities['groups']
            },
            "Role Assume Info": {}
        }

        # If the policy is attached to one or more roles, fetch their assume info
        if entities['roles']:
            role_assume_data = get_roles_assume_info(entities['roles'])
            metadata_block["Role Assume Info"] = role_assume_data

        # Get policy document
        policy_doc = get_policy_details(policy_arn)

        # Combine metadata and policy document
        full_entry = {
            "metadata": metadata_block,
            "policy_document": policy_doc
        }
        output_data.append(full_entry)

    # Save policy ARNs with attachments (if not using cache)
    if not use_cached_policies:
        save_attached_policies_to_file(policy_arns_with_attachments)

    print(f"\n📦 Collected {len(output_data)} attached policies.")
    # Save to multiple formats
    save_to_json(output_data)
    save_to_csv(output_data)
    save_to_html(output_data)
    print(f"\n✅ Successfully wrote {len(output_data)} policies to 3 files:")
    print("   - output.json (structured)")
    print("   - output.csv (tabular with policy document as JSON string)")
    print("   - output.html (viewable in browser with expandable policy documents)")


if __name__ == "__main__":
    main()