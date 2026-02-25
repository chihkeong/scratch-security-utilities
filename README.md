# Scratch Security Utilities

A collection of security auditing and scanning utilities for various cloud platforms and infrastructure.

## 📁 Project Structure

```
scratch-security-utilities/
├── aws/           # AWS security tools
├── ssl/           # SSL/TLS scanning tools  
├── azure/         # Azure security tools (placeholder)
├── gcp/           # GCP security tools (placeholder)
└── kubernetes/    # Kubernetes security tools (placeholder)
```

## 🛠️ Available Tools

### AWS - IAM Security Auditor (`aws/iam_security_auditor.py`)

Comprehensive AWS IAM security auditing tool that checks for:

- **External trust relationships** - Roles that can be assumed by external AWS accounts
- **Publicly accessible roles** - Roles with wildcard principals
- **Wildcard permissions** - Inline policies with `*` actions or resources
- **Admin roles/users** - Entities with AdministratorAccess policy
- **Service role permissions** - Service roles with excessive permissions
- **Access keys** - Users with active access keys
- **Console passwords** - Users with console login enabled
- **Inline policies** - Overly permissive inline policies on users/groups

#### Usage

```bash
# Configure AWS credentials profile
aws configure --profile cloudpt

# Run the auditor
python aws/iam_security_auditor.py
```

#### Requirements
- boto3
- colorama

### SSL - SSL/TLS Scanner (`ssl/ssl_scanner.py`)

SSL/TLS security scanner for analyzing certificate configurations and vulnerabilities.

#### Requirements
- See `ssl/` directory for details

## 📋 Requirements

Install dependencies:

```bash
pip install -r requirements.txt
```

## ⚙️ Configuration

### AWS
Configure your AWS credentials:

```bash
aws configure --profile cloudpt
```

Or edit `~/.aws/credentials`:
```ini
[cloudpt]
aws_access_key_id = YOUR_ACCESS_KEY
aws_secret_access_key = YOUR_SECRET_KEY
region = ap-southeast-1
```

## 🔒 Security Notes

- These tools are read-only and do not modify any cloud resources
- Always follow your organization's security policies when running security scans
- Review findings carefully before taking remediation actions

## 📜 License

See [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests.