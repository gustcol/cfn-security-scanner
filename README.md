# CFN Security Scanner

A comprehensive security scanner for AWS CloudFormation templates. This tool analyzes your Infrastructure as Code (IaC) templates to identify security misconfigurations, compliance violations, and best practice deviations before deployment.

## Features

- **137 Security Rules**: Comprehensive coverage of AWS security best practices
- **Multiple Output Formats**: Console, JSON, SARIF (for IDE integration)
- **Compliance Frameworks**: Rules mapped to CIS, SOC2, HIPAA, and PCI-DSS
- **Flexible Configuration**: Skip rules, filter by severity, target specific frameworks
- **CI/CD Integration**: Exit codes and machine-readable output for automation
- **Fast & Lightweight**: No external dependencies required at runtime
- **Rule Update System**: Automated tools to sync with Checkov and AWS best practices
- **Automated Testing**: Comprehensive test framework for rule validation

## Supported Resource Types

| Service | Resource Types |
|---------|---------------|
| S3 | Bucket, BucketPolicy |
| EC2 | Instance, SecurityGroup, Volume, VPC, LaunchTemplate |
| IAM | Role, Policy, ManagedPolicy, User, Group |
| RDS | DBInstance, DBCluster |
| Lambda | Function, Permission |
| API Gateway | RestApi, Stage, Method, DomainName |
| CloudTrail | Trail |
| KMS | Key |
| SNS | Topic, TopicPolicy, Subscription |
| SQS | Queue, QueuePolicy |
| ECS | TaskDefinition, Service, Cluster |
| ElastiCache | ReplicationGroup, CacheCluster |
| ELB | LoadBalancer, Listener (v1 and v2) |
| CloudFront | Distribution |
| Secrets Manager | Secret, RotationSchedule |

## Installation

```bash
# Clone the repository
git clone https://github.com/gustcol/cfn-security-scanner.git
cd cfn-security-scanner

# Install dependencies
npm install

# Link for global usage (optional)
npm link
```

## Quick Start

```bash
# Scan a single file
cfn-scan template.yaml

# Scan a directory
cfn-scan ./infrastructure/

# Output as JSON
cfn-scan template.yaml --output json

# Filter by severity
cfn-scan template.yaml --severity HIGH

# Filter by compliance framework
cfn-scan template.yaml --framework PCI-DSS
```

## Usage

```
Usage: cfn-scan [options] [path]

Security scanner for AWS CloudFormation templates

Arguments:
  path                          File or directory to scan (default: ".")

Options:
  -V, --version                 output the version number
  -o, --output <format>         Output format (console, json, sarif, summary)
  -s, --severity <level>        Minimum severity to report (INFO, LOW, MEDIUM, HIGH, CRITICAL)
  -f, --fail-on <level>         Exit with error code if findings at this severity or higher
  --skip <rules>                Comma-separated list of rule IDs to skip
  --include <rules>             Comma-separated list of rule IDs to include
  --framework <framework>       Filter rules by compliance framework (CIS, SOC2, HIPAA, PCI-DSS)
  --list-rules                  List all available rules and exit
  --output-file <file>          Write output to file instead of stdout
  -q, --quiet                   Suppress banner and summary output
  --no-color                    Disable colored output
  -h, --help                    display help for command
```

## Examples

### Basic Scanning

```bash
# Scan current directory
cfn-scan

# Scan specific template
cfn-scan my-stack.yaml

# Scan entire infrastructure directory
cfn-scan ./cloudformation/
```

### Output Formats

```bash
# Human-readable console output (default)
cfn-scan template.yaml

# JSON for programmatic processing
cfn-scan template.yaml -o json > results.json

# SARIF for IDE integration (VS Code, GitHub)
cfn-scan template.yaml -o sarif > results.sarif

# Summary view
cfn-scan template.yaml -o summary
```

### Filtering

```bash
# Only show HIGH and CRITICAL findings
cfn-scan template.yaml --severity HIGH

# Filter by compliance framework
cfn-scan template.yaml --framework HIPAA

# Skip specific rules
cfn-scan template.yaml --skip CFN_S3_007,CFN_EC2_006

# Only run specific rules
cfn-scan template.yaml --include CFN_S3_001,CFN_S3_002,CFN_RDS_001
```

### CI/CD Integration

```bash
# Fail pipeline on HIGH or CRITICAL findings
cfn-scan template.yaml --fail-on HIGH --quiet

# Generate report for artifacts
cfn-scan ./infrastructure/ -o json --output-file scan-results.json
```

## Security Rules

### Rule Categories

| Category | Description |
|----------|-------------|
| `encryption` | Data encryption at rest and in transit |
| `access-control` | Authentication, authorization, and IAM policies |
| `network` | Security groups, VPCs, and network configuration |
| `logging` | Audit logging and monitoring |
| `data-protection` | Data backup, versioning, and protection |
| `monitoring` | CloudWatch, X-Ray, and observability |
| `availability` | High availability and disaster recovery |
| `general` | General best practices and documentation |

### Severity Levels

| Level | Description |
|-------|-------------|
| `CRITICAL` | Immediate security risk, potential for data breach or unauthorized access |
| `HIGH` | Significant security gap that should be addressed promptly |
| `MEDIUM` | Security improvement recommended |
| `LOW` | Minor security enhancement or best practice |
| `INFO` | Informational finding |

### Compliance Mapping

Rules are mapped to common compliance frameworks:

- **CIS**: CIS AWS Foundations Benchmark
- **SOC2**: SOC 2 Type II Controls
- **HIPAA**: HIPAA Security Rule
- **PCI-DSS**: Payment Card Industry Data Security Standard

### List All Rules

```bash
# List all available rules
cfn-scan --list-rules

# List rules for specific framework
cfn-scan --list-rules --framework HIPAA
```

## Sample Rules

### S3 Bucket Security

| Rule ID | Name | Severity |
|---------|------|----------|
| CFN_S3_001 | S3 Bucket Encryption Enabled | HIGH |
| CFN_S3_002 | S3 Bucket Public Access Block | CRITICAL |
| CFN_S3_003 | S3 Bucket Versioning Enabled | MEDIUM |
| CFN_S3_004 | S3 Bucket Logging Enabled | MEDIUM |
| CFN_S3_005 | S3 Bucket SSL Requests Only | HIGH |

### EC2 Security

| Rule ID | Name | Severity |
|---------|------|----------|
| CFN_EC2_001 | Security Group Unrestricted SSH | CRITICAL |
| CFN_EC2_002 | Security Group Unrestricted RDP | CRITICAL |
| CFN_EC2_004 | EC2 Instance IMDSv2 Required | HIGH |
| CFN_EC2_005 | EC2 Instance EBS Encryption | HIGH |

### IAM Security

| Rule ID | Name | Severity |
|---------|------|----------|
| CFN_IAM_001 | IAM Policy No Wildcard Actions | HIGH |
| CFN_IAM_003 | IAM Role Trust Policy Restricted | CRITICAL |
| CFN_IAM_007 | IAM Policy No Admin Access | CRITICAL |

### RDS Security

| Rule ID | Name | Severity |
|---------|------|----------|
| CFN_RDS_001 | RDS Storage Encryption | HIGH |
| CFN_RDS_002 | RDS Public Access Disabled | CRITICAL |
| CFN_RDS_003 | RDS Multi-AZ Deployment | MEDIUM |

## Programmatic Usage

```javascript
const { Scanner } = require('cfn-security-scanner');

async function scanTemplate() {
  const scanner = new Scanner({
    failOnSeverity: 'HIGH',
    skipRules: ['CFN_S3_007'],
    framework: 'SOC2',
  });

  await scanner.initialize();

  // Scan a single file
  const result = await scanner.scanFile('./template.yaml');

  // Or scan a directory
  const results = await scanner.scanDirectory('./infrastructure/');

  // Get summary
  const summary = scanner.getSummary();
  console.log(`Found ${summary.failed} issues`);

  // Get failed results
  const failed = scanner.getFailedResults();
  for (const finding of failed) {
    console.log(`${finding.ruleId}: ${finding.message}`);
  }

  // Check if should fail
  if (scanner.shouldFail()) {
    process.exit(1);
  }
}

scanTemplate();
```

## Configuration File

Create a `.cfn-scanner.json` file in your project root:

```json
{
  "skipRules": ["CFN_S3_007", "CFN_EC2_006"],
  "severity": "MEDIUM",
  "failOn": "HIGH",
  "framework": "SOC2",
  "exclude": ["**/test/**", "**/examples/**"]
}
```

## CI/CD Integration Examples

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '18'

      - name: Install CFN Scanner
        run: npm install -g cfn-security-scanner

      - name: Run Security Scan
        run: cfn-scan ./infrastructure/ --fail-on HIGH -o sarif --output-file results.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

### GitLab CI

```yaml
security-scan:
  image: node:18
  script:
    - npm install -g cfn-security-scanner
    - cfn-scan ./infrastructure/ --fail-on HIGH -o json --output-file gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
```

### Jenkins Pipeline

```groovy
pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                sh 'npm install -g cfn-security-scanner'
                sh 'cfn-scan ./infrastructure/ --fail-on HIGH -o json --output-file scan-results.json'
                archiveArtifacts artifacts: 'scan-results.json'
            }
        }
    }
}
```

## Extending with Custom Rules

Create custom rules by adding to the rules directory:

```javascript
// src/rules/custom.js
module.exports = [
  {
    id: 'CUSTOM_001',
    name: 'Custom Security Check',
    description: 'Ensure custom security requirement is met',
    severity: 'HIGH',
    category: 'custom',
    resourceTypes: ['AWS::EC2::Instance'],
    frameworks: ['SOC2'],
    remediation: 'Apply the custom security setting',
    documentation: 'https://example.com/docs',
    evaluate: (context) => {
      const { properties } = context;

      // Your custom logic here
      if (!properties.CustomProperty) {
        return {
          passed: false,
          message: 'Custom property is not configured',
        };
      }

      return {
        passed: true,
        message: 'Custom check passed',
      };
    },
  },
];
```

## Rule Maintenance & Updates

The scanner includes a comprehensive system for keeping security rules up-to-date with the latest best practices.

### Update Scripts

| Script | Purpose |
|--------|---------|
| `scripts/checkov-mapper.js` | Compare rules with Checkov, generate gap analysis |
| `scripts/rule-updater.js` | Check updates, validate rules, generate changelog |
| `scripts/generate-rule.js` | Interactive tool to create new rules |
| `scripts/test-rules.js` | Automated testing framework |

### Checking for Updates

```bash
# Fetch latest Checkov rules from GitHub
node scripts/checkov-mapper.js --fetch

# Generate gap analysis report
node scripts/checkov-mapper.js --report

# Check for updates from AWS Security Hub, CIS, etc.
node scripts/rule-updater.js --check-updates

# Validate all existing rules
node scripts/rule-updater.js --validate

# View rule statistics
node scripts/rule-updater.js --stats
```

### Creating New Rules

```bash
# Interactive rule generator
node scripts/generate-rule.js

# Run automated tests
node scripts/test-rules.js
```

### Update Sources

The update system checks multiple sources:

- **Checkov** - CloudFormation security rules comparison
- **AWS Security Hub** - Security Hub control mappings
- **CIS Benchmarks** - CIS AWS Foundations Benchmark
- **AWS Documentation** - New security features and best practices

### Automated Updates (GitHub Actions)

The included workflow (`.github/workflows/rule-updates.yml`) runs weekly to:
- Fetch latest Checkov rules
- Generate gap analysis reports
- Validate existing rules
- Create issues for high-priority updates

### Monthly Update Checklist

```bash
# 1. Fetch and compare with Checkov
node scripts/checkov-mapper.js --fetch
node scripts/checkov-mapper.js --report

# 2. Check for updates
node scripts/rule-updater.js --check-updates

# 3. Validate rules
node scripts/rule-updater.js --validate

# 4. Run tests
node scripts/test-rules.js

# 5. Generate changelog
node scripts/rule-updater.js --generate-changelog
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed guidelines on rule development and maintenance.

## Contributing

Contributions are welcome! Please read our [contributing guidelines](CONTRIBUTING.md) before submitting PRs.

1. Fork the repository
2. Create a feature branch
3. Add tests for new rules
4. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Acknowledgments

This project is inspired by [Checkov](https://github.com/bridgecrewio/checkov) and aims to provide a lightweight, Node.js-based alternative for CloudFormation security scanning.
