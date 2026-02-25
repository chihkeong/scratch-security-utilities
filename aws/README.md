# AWS Security Tools

A collection of Python scripts for AWS IAM security analysis and auditing.

## Tools

### iam_policy_lister.py

**Version:** 4.0

A comprehensive AWS IAM Policy & Role Access Analyzer that lists all IAM policies attached to users, groups, and roles, with detailed analysis of who can assume each role.

#### Features

- **Policy Listing**: Lists all IAM policies attached to users, groups, and roles
- **Role Assume Analysis**: Shows who can assume each role (including group membership)
- **Permission Tracking**: Tracks where permissions come from (direct user or group)
- **Multi-format Export**: Outputs to JSON, CSV, and HTML formats
- **Caching**: Uses in-memory and file-based caching to reduce API calls

#### Requirements

```bash
pip install boto3 jinja2
```

#### Configuration

The script uses the AWS profile `cloudpt` by default. Configure your AWS credentials in `~/.aws/credentials`:

```ini
[cloudpt]
aws_access_key_id = YOUR_ACCESS_KEY
aws_secret_access_key = YOUR_SECRET_KEY
```

#### Usage

```bash
python iam_policy_lister.py
```

#### Output Files

| File | Description |
|------|-------------|
| `output.json` | Structured JSON with all policy data |
| `output.csv` | Tabular format with policy document as JSON string |
| `output.html` | Viewable in browser with expandable policy documents |
| `attached_policies_cache.json` | Cache file for faster subsequent runs |

#### Key Functions

| Function | Description |
|----------|-------------|
| `get_role_assume_info()` | Analyzes a role's trust policy and who can assume it |
| `get_cached_policy()` | Returns policy document from cache or API |
| `list_entities_for_policy()` | Lists users, roles, groups attached to a policy |
| `get_group_members()` | Returns list of users in an IAM group |

#### Configuration Options

| Variable | Default | Description |
|----------|---------|-------------|
| `ENHANCED_USER_SOURCE` | `True` | Show detailed source info for user permissions |
| `use_cached_policies` | `True` | Use file-based cache for policy list |
| `POLICY_CACHE_FILE` | `"attached_policies_cache.json"` | Cache file path |

#### How It Works

1. Fetches all IAM policies (or loads from cache)
2. Filters to show only attached policies
3. For each policy, collects:
   - Attached users, roles, and groups
   - Policy document (permissions)
   - Role assume info (who can assume roles)
4. Exports results to JSON, CSV, and HTML

#### HTML Report

The HTML output includes:
- Sortable table of all policies
- Expandable policy documents (click "Show/Hide")
- Role assume information with user sources
- Cross-account access details
- Federated identity information

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history.

## Related Files

The following files were consolidated into `iam_policy_lister.py`:

| Original File | Version | Description |
|---------------|---------|-------------|
| `testAWS.py` | 1.0 | Basic policy lister |
| `testAWSv2.py` | 2.0 | Added role assume info, multi-format export |
| `testAWS3.py` | 3.0 | Added policy cache, enhanced user tracking |
| `testAWS4.py` | 4.0 | Added file-based caching (latest) |