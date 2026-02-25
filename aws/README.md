# AWS Security Tools

## IAM Security Auditor (`iam_security_auditor.py`)

Comprehensive AWS IAM security auditing tool that identifies potential security risks in your AWS account.

### Features

- **External Trust Detection** - Identifies roles that can be assumed by external AWS accounts
- **Public Access Check** - Finds roles with wildcard (`*`) principals
- **Wildcard Policy Analysis** - Detects inline policies with overly permissive wildcards
- **Admin Discovery** - Lists all users and roles with AdministratorAccess
- **Service Role Audit** - Checks service roles for excessive permissions
- **Access Key Inventory** - Reports users with active access keys
- **Console Password Check** - Identifies users with console login enabled
- **Inline Policy Review** - Flags potentially overly permissive inline policies

### Usage

```bash
# Ensure AWS credentials are configured
aws configure --profile cloudpt

# Run the auditor
python iam_security_auditor.py
```

### Configuration

The script uses the `cloudpt` AWS profile by default. To use a different profile, edit the `profile` variable in the `main()` function.

### Requirements

```bash
pip install boto3 colorama
```

### Security Checks Reference

| Check | Description | Risk Level |
|-------|-------------|------------|
| External Trust | Roles assumable by external accounts | High |
| Public Access | Roles with `Principal: "*"` | Critical |
| Wildcard Actions | Policies with `Action: "*"` | High |
| Wildcard Resources | Policies with `Resource: "*"` | Medium |
| Admin Access | AdministratorAccess policy attached | Info |
| Access Keys | Users with active access keys | Info |
| Console Password | Users with console login | Info |