"""
AWS IAM Policy Lister
Lists all IAM policies with their attachments (users, roles, groups)
Exports to JSON, CSV, and HTML formats

Version: 2.0
Original file: testAWSv2.py
"""

import boto3
import json
from botocore.exceptions import ClientError
import csv
from jinja2 import Template
from fnmatch import fnmatch


# Use the 'cloudpt' AWS profile
session = boto3.Session(profile_name='cloudpt')

# Initialize the IAM client using the session
iam = session.client('iam')

def get_role_assume_info(role_name):
    """
    Given a single role name, return detailed info about:
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
        users_allowed = set()
        groups_allowed = set()
        resolved_users = set()  # All users (via direct or group policy)

        def check_policy_statements(policy_doc, resource_arn, matched_users=None, matched_groups=None):
            for statement in policy_doc.get('Statement', []):
                if statement.get('Effect') == 'Allow' and 'sts:AssumeRole' in statement.get('Action', []):
                    resource = statement.get('Resource', '')
                    if isinstance(resource, str):
                        if fnmatch(resource_arn, resource):
                            if matched_users:
                                matched_users.add(user_name)
                            if matched_groups:
                                matched_groups.add(group_name)
                    elif isinstance(resource, list):
                        for r in resource:
                            if fnmatch(resource_arn, r):
                                if matched_users:
                                    matched_users.add(user_name)
                                if matched_groups:
                                    matched_groups.add(group_name)

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
                        doc = iam.get_policy(PolicyArn=policy_arn)
                        version = doc['Policy']['DefaultVersionId']
                        policy_doc = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version)['PolicyVersion']['Document']
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
                        doc = iam.get_policy(PolicyArn=policy_arn)
                        version = doc['Policy']['DefaultVersionId']
                        policy_doc = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version)['PolicyVersion']['Document']
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
                        resolved_users.add(user_in_group_name)

        # Combine resolved users from direct and group policies
        for u in users_allowed:
            resolved_users.add(u)

        return {
            "role_name": role_name,
            "role_arn": role_arn,
            "trust_policy": trust_policy,
            "trusted_principals": list(set(trusted_principals)),
            "cross_accounts": list(set(cross_accounts)),
            "services": list(set(services)),
            "federated": list(set(federated)),
            "allowed_users_direct": list(users_allowed),
            "allowed_groups": list(groups_allowed),
            "resolved_users": list(resolved_users)
        }

    except Exception as e:
        print(f"[ERROR] Could not retrieve info for role '{role_name}': {e}")
        return {"role_name": role_name, "error": str(e)}


def get_roles_assume_info(role_names):
    """
    Given a list of role names, returns info for each.
    """
    results = {}
    for role_name in role_names:
        result = get_role_assume_info(role_name)
        results[role_name] = result

def get_policy_details(policy_arn):
    try:
        # Get the default version of the policy
        policy = iam.get_policy(PolicyArn=policy_arn)
        default_version_id = policy['Policy']['DefaultVersionId']

        policy_version = iam.get_policy_version(
            PolicyArn=policy_arn,
            VersionId=default_version_id
        )
        return policy_version['PolicyVersion']['Document']
    except ClientError as e:
        print(f"[ERROR] Unable to retrieve policy document: {e}")
        return {}


def list_entities_for_policy(policy_arn):
    users = []
    roles = []
    groups = []

    paginator = iam.get_paginator('list_entities_for_policy')
    for page in paginator.paginate(PolicyArn=policy_arn):
        users.extend(page.get('PolicyUsers', []))
        roles.extend(page.get('PolicyRoles', []))
        groups.extend(page.get('PolicyGroups', []))

    return {
        'users': [u['UserName'] for u in users],
        'roles': [r['RoleName'] for r in roles],
        'groups': [g['GroupName'] for g in groups]
    }


def save_to_json(data):
    with open("output.json", "w") as f:
        json.dump(data, f, indent=4, default=str)
    print("✅ Saved output.json")


def save_to_csv(data):
    headers = ['Policy Name', 'ARN', 'Attached Users', 'Attached Roles', 'Attached Groups', 'Policy Document']
    with open("output.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()
        for item in data:
            meta = item["metadata"]
            writer.writerow({
                "Policy Name": meta["Policy Name"],
                "ARN": meta["ARN"],
                "Attached Users": ", ".join(meta["Attached To"]["Users"]),
                "Attached Roles": ", ".join(meta["Attached To"]["Roles"]),
                "Attached Groups": ", ".join(meta["Attached To"]["Groups"]),
                "Policy Document": json.dumps(item["policy_document"], indent=2)
            })
    print("✅ Saved output.csv")


def save_to_html(data):
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
                margin-top: 10px;
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
                    <th>Roles</th>
                    <th>Groups</th>
                    <th>Policy Document</th>
                </tr>
            </thead>
            <tbody>
                {% for item in data %}
                <tr>
                    <td>{{ item.metadata['Policy Name'] }}</td>
                    <td>{{ item.metadata['ARN'] }}</td>
                    <td>{{ item.metadata['Attached To']['Users'] | join(', ') }}</td>
                    <td>{{ item.metadata['Attached To']['Roles'] | join(', ') }}</td>
                    <td>{{ item.metadata['Attached To']['Groups'] | join(', ') }}</td>
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

    # Convert each policy document to pretty-printed JSON string
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
    output_data = []

    print("🔍 Fetching all IAM policies...")
    paginator = iam.get_paginator('list_policies')
    policy_pages = paginator.paginate(Scope='All')
    all_policies = []
    for page in policy_pages:
        all_policies.extend(page['Policies'])

    total_policies = len(all_policies)
    print(f"📊 Found {total_policies} IAM policies. Filtering only attached ones...\n")

    count = 0
    for i, policy in enumerate(all_policies, 1):
        policy_name = policy['PolicyName']
        policy_arn = policy['Arn']

        # Get attached entities
        entities = list_entities_for_policy(policy_arn)

        # Skip if not attached to anything
        if not any(entities.values()):
            if i % 50 == 0 or i == total_policies:
                print(f"⏳ Processed {i}/{total_policies} policies... (skipping unattached)")
            continue

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
            }
        }

        # Get policy document
        policy_doc = get_policy_details(policy_arn)

        # Combine metadata and policy document
        full_entry = {
            "metadata": metadata_block,
            "policy_document": policy_doc
        }

        output_data.append(full_entry)

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