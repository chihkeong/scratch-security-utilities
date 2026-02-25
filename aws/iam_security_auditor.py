import boto3
from botocore.exceptions import ClientError
from colorama import Fore, init

def get_aws_account_id():
    """Retrieve the AWS account ID using STS and the profile from .aws/credentials."""
    # Create a session using the 'cloudpt' profile
    session = boto3.Session(profile_name='cloudpt')
    
    # Initialize the STS client using the session
    sts = session.client('sts')
    
    # Retrieve the caller identity, which includes the AWS account ID
    response = sts.get_caller_identity()
    
    # Extract and return the account ID
    return response['Account']

def get_all_roles(iam):
    """Return a dict of all roles for quick lookup."""
    roles = {}
    paginator = iam.get_paginator('list_roles')
    for page in paginator.paginate():
        for role in page['Roles']:
            roles[role['RoleName']] = role
    return roles

def get_users_in_group(group_name, iam):
    """Return a list of user names in a group."""
    users = []
    paginator = iam.get_paginator('get_group')
    for page in paginator.paginate(GroupName=group_name):
        for user in page['Users']:
            users.append(user['UserName'])
    return users

def check_policies(policies, iam, user_name, all_roles, assumed_roles):
    """Check policies for sts:AssumeRole permissions and track which roles can be assumed.
    
    Args:
        policies: List of policy dictionaries to check
        iam: IAM client instance
        user_name: Name of the user being checked
        all_roles: Dict of all roles for lookup
        assumed_roles: Set to populate with assumable role names
    """
    for policy in policies:
        try:
            policy_version_id = iam.get_policy(PolicyArn=policy['PolicyArn'])['Policy']['DefaultVersionId']
            policy_doc = iam.get_policy_version(
                PolicyArn=policy['PolicyArn'],
                VersionId=policy_version_id
            )['PolicyVersion']['Document']

            if not isinstance(policy_doc, dict):
                print(Fore.LIGHTRED_EX + f"  [!] Invalid policy document for user: {user_name}")
                continue

            statements = policy_doc.get('Statement', [])
            if not isinstance(statements, list):
                statements = [statements]

            for stmt in statements:
                if stmt.get('Effect') != 'Allow':
                    continue
                actions = stmt.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                if any(a in ['sts:AssumeRole', 'sts:*', '*'] for a in actions):
                    resources = stmt.get('Resource', [])
                    if isinstance(resources, str):
                        resources = [resources]
                    for res in resources:
                        # Extract role name from ARN
                        if res.startswith('arn:aws:iam::') and ':role/' in res:
                            role_name = res.split(':role/')[-1]
                            if role_name in all_roles:
                                assumed_roles.add(role_name)
        except ClientError as e:
            print(Fore.LIGHTRED_EX + f"  [!] Error retrieving policy for user {user_name}: {e}")
def user_can_assume_roles(user_name, all_roles, iam):
    """Return a list of roles the user can assume based on their policies.
    
    Args:
        user_name: Name of the user to check
        all_roles: Dict of all roles for lookup
        iam: IAM client instance
        
    Returns:
        List of role names the user can assume
    """
    assumed_roles = set()

    # Check attached user policies
    attached_policies = iam.list_attached_user_policies(UserName=user_name)['AttachedPolicies']
    check_policies(attached_policies, iam, user_name, all_roles, assumed_roles)

    # Check group policies for each group the user is in
    groups = iam.list_groups_for_user(UserName=user_name)['Groups']
    for group in groups:
        group_name = group['GroupName']
        attached_policies = iam.list_attached_group_policies(GroupName=group_name)['AttachedPolicies']
        check_policies(attached_policies, iam, user_name, all_roles, assumed_roles)

    return list(assumed_roles)

def detect_external_trust_roles(iam, YOUR_AWS_ACCOUNT_ID):
    """Check for roles with external trust relationships."""
    print(Fore.LIGHTYELLOW_EX + "\n[+] Checking for roles with external trust relationships...")
    paginator = iam.get_paginator('list_roles')
    for page in paginator.paginate():
        for role in page['Roles']:
            role_name = role['RoleName']
            trust_policy = role['AssumeRolePolicyDocument']
            for stmt in trust_policy.get('Statement', []):
                principal = stmt.get('Principal', {})
                if 'AWS' in principal:
                    aws_principal = principal['AWS']
                    if isinstance(aws_principal, list):
                        for arn in aws_principal:
                            if not arn.startswith(f'arn:aws:iam::{YOUR_AWS_ACCOUNT_ID}'):
                                print(Fore.WHITE + f"  [!] Role '{role_name}' can be {Fore.LIGHTRED_EX} assumed by external account: {arn}")
                    else:
                        if not aws_principal.startswith(f'arn:aws:iam::{YOUR_AWS_ACCOUNT_ID}'):
                            print(Fore.WHITE + f"  [!] Role '{role_name}' can be assumed by {Fore.LIGHTRED_EX} external account: {aws_principal}")

def detect_publicly_accessible_roles(iam, YOUR_AWS_ACCOUNT_ID):
    """Check if any roles can be assumed by public principals or external AWS accounts."""
    print(Fore.LIGHTYELLOW_EX + "\n[+] Checking for roles that are publicly accessible or assumable by external accounts...")
    paginator = iam.get_paginator('list_roles')
    for page in paginator.paginate():
        for role in page['Roles']:
            role_name = role['RoleName']
            trust_policy = role['AssumeRolePolicyDocument']
            for stmt in trust_policy.get('Statement', []):
                principal = stmt.get('Principal', {})
                if principal == '*':
                    print(Fore.LIGHTRED_EX + f"  [!] Role '{role_name}' is publicly accessible (Principal: '*')")
                elif 'AWS' in principal:
                    aws_principal = principal['AWS']
                    if isinstance(aws_principal, list):
                        for arn in aws_principal:
                            if not arn.startswith(f'arn:aws:iam::{YOUR_AWS_ACCOUNT_ID}'):
                                print(Fore.WHITE + f"  [!] Role '{role_name}' can be {Fore.LIGHTRED_EX}assumed by external account: {arn}")
                    else:
                        if not aws_principal.startswith(f'arn:aws:iam::{YOUR_AWS_ACCOUNT_ID}'):
                            print(Fore.WHITE + f"  [!] Role '{role_name}' can be {Fore.LIGHTRED_EX}assumed by external account: {aws_principal}")

def detect_wildcards_in_role_inline_policies(iam):
    """Check for wildcards in role inline policies."""
    print(Fore.LIGHTYELLOW_EX + "\n[+] Checking for wildcards in role inline policies...")
    paginator = iam.get_paginator('list_roles')
    for page in paginator.paginate():
        for role in page['Roles']:
            role_name = role['RoleName']
            policy_names = iam.list_role_policies(RoleName=role_name)['PolicyNames']
            for policy_name in policy_names:
                try:
                    policy = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
                    policy_doc = policy['PolicyDocument']
                    statements = policy_doc.get('Statement', [])
                    if not isinstance(statements, list):
                        statements = [statements]
                    for stmt in statements:
                        actions = stmt.get('Action', [])
                        resources = stmt.get('Resource', [])
                        if isinstance(actions, str):
                            actions = [actions]
                        if isinstance(resources, str):
                            resources = [resources]
                        wildcard_actions = [a for a in actions if '*' in a]
                        wildcard_resources = [r for r in resources if '*' in r]
                        if wildcard_actions or wildcard_resources:
                            print(Fore.WHITE + f"  [!] Role: {role_name}, Policy: {policy_name}")
                            if wildcard_actions:
                                print(Fore.LIGHTRED_EX + f"      Wildcard Actions: {', '.join(wildcard_actions)}")
                            if wildcard_resources:
                                print(Fore.LIGHTRED_EX + f"      Wildcard Resources: {', '.join(wildcard_resources)}")
                except ClientError as e:
                    print(Fore.LIGHTRED_EX + f"  [!] Error retrieving inline policy for role {role_name}: {e}")

def detect_admin_roles(iam):
    """Check for roles with AdministratorAccess policy attached."""
    print(Fore.LIGHTYELLOW_EX + "\n[+] Checking for roles with AdministratorAccess policy attached...")
    paginator = iam.get_paginator('list_roles')
    for page in paginator.paginate():
        for role in page['Roles']:
            role_name = role['RoleName']
            attached = iam.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
            for policy in attached:
                if policy['PolicyName'] == 'AdministratorAccess':
                    print(Fore.WHITE + f"  [!] Role {role_name} has {Fore.LIGHTRED_EX}AdministratorAccess policy attached")

def detect_wildcards_in_group_inline_policies_and_list_users_and_roles(iam):
    """Check for wildcards in group inline policies and list users/roles."""
    print(Fore.LIGHTYELLOW_EX + "\n[+] Checking for wildcards in group inline policies and listing users/roles...")
    all_roles = get_all_roles(iam)
    paginator = iam.get_paginator('list_groups')
    for page in paginator.paginate():
        for group in page['Groups']:
            group_name = group['GroupName']
            policy_names = iam.list_group_policies(GroupName=group_name)['PolicyNames']
            for policy_name in policy_names:
                try:
                    policy = iam.get_group_policy(GroupName=group_name, PolicyName=policy_name)
                    policy_doc = policy['PolicyDocument']
                    statements = policy_doc.get('Statement', [])
                    if not isinstance(statements, list):
                        statements = [statements]
                    for stmt in statements:
                        actions = stmt.get('Action', [])
                        resources = stmt.get('Resource', [])
                        if isinstance(actions, str):
                            actions = [actions]
                        if isinstance(resources, str):
                            resources = [resources]
                        wildcard_actions = [a for a in actions if '*' in a]
                        wildcard_resources = [r for r in resources if '*' in r]
                        if wildcard_actions or wildcard_resources:
                            print(Fore.White + f"  [!] Group: {group_name}, Policy: {policy_name}")
                            if wildcard_actions:
                                print(Fore.LIGHTRED_EX + f"      Wildcard Actions: {', '.join(wildcard_actions)}")
                            if wildcard_resources:
                                print(Fore.LIGHTRED_EX + f"      Wildcard Resources: {', '.join(wildcard_resources)}")
                            # List users in this group
                            users = get_users_in_group(group_name, iam)
                            print(f"      Users in group: {', '.join(users)}")
                            # For each user, list roles they can assume
                            for user in users:
                                roles = user_can_assume_roles(user, all_roles, iam)
                                if roles:
                                    print(Fore.MAGENTA + f"User {user} can assume roles: {', '.join(roles)}")
                except ClientError as e:
                    print(Fore.LIGHTRED_EX + f"  [!] Error retrieving inline policy for group {group_name}: {e}")

def detect_users_with_access_keys(iam):
    """Check for IAM users with access keys."""
    print(Fore.LIGHTYELLOW_EX + "\n[+] Checking for IAM users with access keys...")
    paginator = iam.get_paginator('list_users')
    for page in paginator.paginate():
        for user in page['Users']:
            user_name = user['UserName']
            keys = iam.list_access_keys(UserName=user_name)['AccessKeyMetadata']
            if keys:
                print(Fore.LIGHTRED_EX + f"  [!] User {user_name} has access keys: {[k['AccessKeyId'] for k in keys]}")

def detect_users_with_console_password(iam):
    """Check for IAM users with console passwords enabled."""
    print(Fore.LIGHTYELLOW_EX + "\n[+] Checking for IAM users with console passwords enabled...")
    paginator = iam.get_paginator('list_users')
    for page in paginator.paginate():
        for user in page['Users']:
            user_name = user['UserName']
            try:
                iam.get_login_profile(UserName=user_name)
                print(Fore.White + f"  [!] User {user_name} has a {Fore.LIGHTRED_EX}console password enabled")
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchEntity':
                    continue
                else:
                    print(Fore.LIGHTRED_EX + f"  [!] Error checking user {user_name}: {e}")

def detect_admin_users(iam):
    """Check for users with AdministratorAccess policy attached."""
    print(Fore.LIGHTYELLOW_EX + "\n[+] Checking for users with AdministratorAccess policy attached...")
    paginator = iam.get_paginator('list_users')
    for page in paginator.paginate():
        for user in page['Users']:
            user_name = user['UserName']
            attached = iam.list_attached_user_policies(UserName=user_name)['AttachedPolicies']
            for policy in attached:
                if policy['PolicyName'] == 'AdministratorAccess':
                    print(Fore.WHITE + f"  [!] User {user_name} has {Fore.LIGHTRED_EX} AdministratorAccess policy attached")

def detect_service_roles_with_excessive_permissions(iam):
    """Check for service roles with excessive permissions."""
    print(Fore.LIGHTYELLOW_EX + "\n[+] Checking for service roles with excessive permissions...")
    paginator = iam.get_paginator('list_roles')
    for page in paginator.paginate():
        for role in page['Roles']:
            role_name = role['RoleName']
            if 'service-role' in role_name.lower():  # Check if it's a service role
                attached = iam.list_attached_role_policies(RoleName=role_name)['AttachedPolicies']
                for policy in attached:
                    if policy['PolicyName'] == 'AdministratorAccess':
                        print(Fore.LIGHTRED_EX + f"  [!] Service Role {role_name} has AdministratorAccess policy attached")

def check_inline_policies_for_users_and_groups(iam):
    """Check for inline policies attached to users and groups that may be overly permissive."""
    print(Fore.LIGHTYELLOW_EX + "\n[+] Checking for inline policies attached to users and groups...")
    # Check inline policies for users
    paginator = iam.get_paginator('list_users')
    for page in paginator.paginate():
        for user in page['Users']:
            user_name = user['UserName']
            policy_names = iam.list_user_policies(UserName=user_name)['PolicyNames']
            for policy_name in policy_names:
                try:
                    policy = iam.get_user_policy(UserName=user_name, PolicyName=policy_name)
                    policy_doc = policy['PolicyDocument']
                    statements = policy_doc.get('Statement', [])
                    if not isinstance(statements, list):
                        statements = [statements]
                    for stmt in statements:
                        if stmt.get('Effect') == 'Allow':
                            print(Fore.LIGHTRED_EX + f"  [!] User {user_name} has an inline policy: {policy_name} that may be overly permissive")
                except ClientError as e:
                    print(Fore.LIGHTRED_EX + f"  [!] Error retrieving inline policy for user {user_name}: {e}")
    # Check inline policies for groups
    paginator = iam.get_paginator('list_groups')
    for page in paginator.paginate():
        for group in page['Groups']:
            group_name = group['GroupName']
            policy_names = iam.list_group_policies(GroupName=group_name)['PolicyNames']
            for policy_name in policy_names:
                try:
                    policy = iam.get_group_policy(GroupName=group_name, PolicyName=policy_name)
                    policy_doc = policy['PolicyDocument']
                    statements = policy_doc.get('Statement', [])
                    if not isinstance(statements, list):
                        statements = [statements]
                    for stmt in statements:
                        if stmt.get('Effect') == 'Allow':
                            print(Fore.LIGHTRED_EX + f"  [!] Group {group_name} has an inline policy: {policy_name} that may be overly permissive")
                except ClientError as e:
                    print(Fore.LIGHTRED_EX + f"  [!] Error retrieving inline policy for group {group_name}: {e}")

def evaluate_trust_relationships(iam, YOUR_AWS_ACCOUNT_ID):
    """Evaluate trust relationships for roles that allow access to AWS services or other AWS accounts."""
    print(Fore.LIGHTYELLOW_EX + "\n[+] Evaluating trust relationships for roles...")
    paginator = iam.get_paginator('list_roles')
    for page in paginator.paginate():
        for role in page['Roles']:
            role_name = role['RoleName']
            trust_policy = role['AssumeRolePolicyDocument']
            for stmt in trust_policy.get('Statement', []):
                principal = stmt.get('Principal', {})
                if 'AWS' in principal:
                    aws_principal = principal['AWS']
                    if isinstance(aws_principal, list):
                        for arn in aws_principal:
                            if not arn.startswith(f'arn:aws:iam::{YOUR_AWS_ACCOUNT_ID}'):
                                print(Fore.LIGHTRED_EX + f"  [!] Role '{role_name}' can be assumed by external account: {arn}")
                    else:
                        if not aws_principal.startswith(f'arn:aws:iam::{YOUR_AWS_ACCOUNT_ID}'):
                            print(Fore.LIGHTRED_EX + f"  [!] Role '{role_name}' can be assumed by external account: {aws_principal}")
                # Check for service principals
                if 'Service' in principal:
                    service_principal = principal['Service']
                    print(Fore.LIGHTRED_EX + f"  [!] Role '{role_name}' has a trust relationship with {Fore.LIGHTBLUE_EX} service: {service_principal}")

def main():
    """Main entry point for the script."""
    print("[INFO]   Starting the script now...")
    # Initialize colorama
    init(autoreset=True)  # Initialize colorama
    profile = 'cloudpt'
    print(f"[INFO]  Loading IAM client .... using profile {Fore.LIGHTBLUE_EX} {profile}! ")
    session = boto3.Session(profile_name=profile)
    iam = session.client('iam')  # Initialize IAM client

    # Initialize the STS client using the session
    sts = session.client('sts')
    
    # Retrieve the caller identity, which includes the AWS account ID
    response = sts.get_caller_identity()
        # Retrieve AWS Account ID
    YOUR_AWS_ACCOUNT_ID = response['Account']
       
    print(Fore.LIGHTGREEN_EX + f"[INFO]   AWS Account ID: {Fore.LIGHTBLUE_EX}{YOUR_AWS_ACCOUNT_ID}")

    # Run all checks
    # detect_external_trust_roles(iam, YOUR_AWS_ACCOUNT_ID)
    # detect_publicly_accessible_roles(iam, YOUR_AWS_ACCOUNT_ID)
    # evaluate_trust_relationships(iam, YOUR_AWS_ACCOUNT_ID)
    # detect_wildcards_in_role_inline_policies(iam)
    # detect_admin_roles(iam)
    detect_wildcards_in_group_inline_policies_and_list_users_and_roles(iam)
    detect_users_with_access_keys(iam)
    detect_users_with_console_password(iam)
    detect_admin_users(iam)
    detect_service_roles_with_excessive_permissions(iam)
    check_inline_policies_for_users_and_groups(iam)
    

if __name__ == "__main__":
    main()  # Call the main function