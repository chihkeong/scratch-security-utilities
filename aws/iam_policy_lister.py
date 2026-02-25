"""
AWS IAM Policy Lister
Lists all IAM policies with their attachments (users, roles, groups)

Version: 1.0
Original file: testAWS.py
"""

import boto3
import json
from botocore.exceptions import ClientError

# Use the 'cloudpt' AWS profile
session = boto3.Session(profile_name='cloudpt')

# Initialize the IAM client using the session
iam = session.client('iam')


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


def main():
    # List all IAM policies
    paginator = iam.get_paginator('list_policies')
    for page in paginator.paginate(Scope='All'):
        for policy in page['Policies']:
            policy_name = policy['PolicyName']
            policy_arn = policy['Arn']

            # Get attached entities
            entities = list_entities_for_policy(policy_arn)

            # Only continue if policy is attached to at least one entity
            if not any(entities.values()):
                continue  # Skip policies with no attachments

            print(f"\n{'='*60}")
            print(f"Policy Name: {policy_name}")
            print(f"ARN: {policy_arn}")

            print("\nAttached to:")
            print(f"  Users: {entities['users'] or []}")
            print(f"  Roles: {entities['roles'] or []}")
            print(f"  Groups: {entities['groups'] or []}")

            # Get and pretty-print policy document
            policy_doc = get_policy_details(policy_arn)
            print("\nPermissions (Policy Document):")
            print(json.dumps(policy_doc, indent=4, sort_keys=True))


if __name__ == "__main__":
    main()