# AWS Tools Changelog

All notable changes to the AWS tools in this repository will be documented in this file.

## iam_policy_lister.py

### [4.0] - 2026-02-25
**Original file: testAWS4.py**

- Added file-based caching (`attached_policies_cache.json`) for faster subsequent runs
- Added `save_attached_policies_to_file()` and `load_attached_policies_from_file()` functions
- Added `use_cached_policies` toggle in main() for cache control
- Improved performance by caching policy ARN list to avoid re-scanning all policies

### [3.0] - 2026-02-25
**Original file: testAWS3.py**

- Added in-memory policy cache (`POLICY_CACHE` dict) to reduce redundant API calls
- Added `get_cached_policy()` function for policy document caching
- Added enhanced user source tracking (`ENHANCED_USER_SOURCE` toggle)
- Added `get_group_members()` function to show group membership details
- Added detailed role assume info with source tracking (direct vs group)
- Improved CSV/HTML output with role assume information

### [2.0] - 2026-02-25
**Original file: testAWSv2.py**

- Added role assume info analysis (`get_role_assume_info()`, `get_roles_assume_info()`)
- Added trust policy analysis (trusted principals, cross-accounts, services, federated)
- Added multi-format export: JSON, CSV, HTML
- Added `save_to_json()`, `save_to_csv()`, `save_to_html()` functions
- Added HTML template with expandable policy documents
- Added progress indicators during policy processing

### [1.0] - 2026-02-25
**Original file: testAWS.py**

- Initial version
- Lists all IAM policies with attachments (users, roles, groups)
- Filters to show only attached policies
- Console output with policy details and JSON document
- Basic `get_policy_details()` and `list_entities_for_policy()` functions

---

## File Mapping

| Version | Original Filename | Description |
|---------|-------------------|-------------|
| 1.0 | testAWS.py | Basic policy lister |
| 2.0 | testAWSv2.py | Added role assume info, multi-format export |
| 3.0 | testAWS3.py | Added policy cache, enhanced user tracking |
| 4.0 | testAWS4.py | Added file-based caching (latest) |