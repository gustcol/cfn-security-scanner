# Contributing to CFN Security Scanner

Thank you for your interest in contributing to CFN Security Scanner! This document provides guidelines and processes for contributing, with a focus on maintaining and updating security rules.

## Table of Contents

- [Getting Started](#getting-started)
- [Rule Development](#rule-development)
- [Rule Update Process](#rule-update-process)
- [Testing Guidelines](#testing-guidelines)
- [Compliance Mapping](#compliance-mapping)
- [Release Process](#release-process)

---

## Getting Started

### Prerequisites

- Node.js 18+
- Git
- Basic understanding of AWS CloudFormation
- Familiarity with security best practices

### Setup

```bash
# Clone the repository
git clone https://github.com/example/cfn-security-scanner.git
cd cfn-security-scanner

# Install dependencies
npm install

# Run tests
npm test

# Validate existing rules
node scripts/rule-updater.js --validate
```

---

## Rule Development

### Rule Structure

Each security rule must have the following structure:

```javascript
{
  id: 'CFN_SERVICE_NNN',      // Unique identifier
  name: 'Human Readable Name', // Short descriptive name
  description: 'Full description of what this rule checks',
  severity: 'CRITICAL|HIGH|MEDIUM|LOW|INFO',
  category: 'encryption|access-control|network|logging|data-protection|monitoring|availability|general',
  resourceTypes: ['AWS::Service::Resource'],
  frameworks: ['CIS', 'SOC2', 'HIPAA', 'PCI-DSS'],
  remediation: 'How to fix this issue',
  documentation: 'https://docs.aws.amazon.com/...',
  evaluate: (context) => {
    // Rule logic
    return {
      passed: boolean,
      message: string,
      details: object, // optional
    };
  },
}
```

### ID Naming Convention

- Format: `CFN_SERVICE_NNN`
- SERVICE: Abbreviated service name (S3, EC2, RDS, IAM, etc.)
- NNN: Three-digit sequential number

Examples:
- `CFN_S3_001` - First S3 rule
- `CFN_EC2_012` - Twelfth EC2 rule
- `CFN_LAMBDA_005` - Fifth Lambda rule

### Severity Guidelines

| Severity | Description | Examples |
|----------|-------------|----------|
| CRITICAL | Immediate security risk, potential data breach | Public S3 buckets, open security groups, admin IAM policies |
| HIGH | Significant security gap | Unencrypted storage, missing MFA, weak TLS |
| MEDIUM | Security improvement needed | Missing logging, no backup retention |
| LOW | Minor security enhancement | Missing tags, default configs |
| INFO | Informational, best practice | Documentation, metadata |

### Category Definitions

| Category | Description |
|----------|-------------|
| `encryption` | Data encryption at rest and in transit |
| `access-control` | IAM, authentication, authorization |
| `network` | Security groups, VPCs, firewalls |
| `logging` | Audit logs, access logs, CloudTrail |
| `data-protection` | Backups, versioning, deletion protection |
| `monitoring` | CloudWatch, X-Ray, alerting |
| `availability` | Multi-AZ, failover, disaster recovery |
| `general` | Tags, descriptions, general best practices |

### Creating a New Rule

#### Option 1: Use the Rule Generator (Recommended)

```bash
node scripts/generate-rule.js
```

This interactive tool will:
1. Guide you through rule creation
2. Generate properly formatted code
3. Assign the next available ID
4. Create test cases

#### Option 2: Manual Creation

1. Find the appropriate file in `src/rules/`
2. Add your rule following the structure above
3. Ensure unique ID
4. Add tests

### Rule Evaluation Context

The `evaluate` function receives a context object:

```javascript
{
  template,       // Full CloudFormation template
  resourceName,   // Logical resource name
  resource,       // Full resource definition
  resourceType,   // AWS::Service::Resource
  properties,     // Resource properties
  filePath,       // File being scanned
}
```

### Return Values

```javascript
// Passing check
return {
  passed: true,
  message: 'Check passed successfully',
};

// Failing check
return {
  passed: false,
  message: 'Specific failure reason',
  details: {
    actual: 'current value',
    expected: 'expected value',
  },
};

// Skip check (not applicable)
return null;
```

---

## Rule Update Process

### Automated Updates

We maintain scripts to help keep rules current:

```bash
# Check for updates from various sources
node scripts/rule-updater.js --check-updates

# Compare with Checkov rules
node scripts/checkov-mapper.js --compare

# Generate gap analysis report
node scripts/checkov-mapper.js --report

# Validate all rules
node scripts/rule-updater.js --validate

# View rule statistics
node scripts/rule-updater.js --stats
```

### Update Sources

1. **AWS Security Hub Controls**
   - Map to Security Hub finding types
   - Update when new controls are added

2. **CIS AWS Benchmarks**
   - Follow CIS Benchmark releases
   - Map rules to CIS control IDs

3. **Checkov Rules**
   - Compare with Checkov CloudFormation checks
   - Identify gaps and improvements

4. **AWS Documentation**
   - Monitor AWS security best practices
   - Update for new service features

5. **CVE/Security Advisories**
   - Add rules for new vulnerabilities
   - Update severity based on exploits

### Monthly Update Checklist

```markdown
- [ ] Run `node scripts/checkov-mapper.js --fetch` to get latest Checkov rules
- [ ] Run `node scripts/checkov-mapper.js --report` to generate gap analysis
- [ ] Review AWS Security Hub for new controls
- [ ] Check CIS Benchmark for updates
- [ ] Review AWS blog for new security features
- [ ] Run `node scripts/rule-updater.js --validate` to check all rules
- [ ] Update CHANGELOG.md with changes
- [ ] Update rule documentation if needed
```

### Quarterly Review Process

1. **Gap Analysis**
   ```bash
   node scripts/checkov-mapper.js --report
   ```
   Review `docs/GAP_ANALYSIS.md` for missing rules.

2. **Deprecation Check**
   - Remove rules for deprecated AWS features
   - Update runtime versions (Lambda, etc.)
   - Update TLS/SSL policy references

3. **Severity Review**
   - Adjust severities based on real-world impact
   - Review CRITICAL rules for accuracy

4. **Framework Mapping**
   - Verify CIS control mappings
   - Update for new framework versions

---

## Testing Guidelines

### Unit Tests

Each rule should have tests for:
1. Passing scenario
2. Failing scenario
3. Edge cases (missing properties, null values)

```javascript
test('CFN_S3_001 - S3 Bucket Encryption', async () => {
  // Passing case
  const passingTemplate = {
    Resources: {
      Bucket: {
        Type: 'AWS::S3::Bucket',
        Properties: {
          BucketEncryption: {
            ServerSideEncryptionConfiguration: [{
              ServerSideEncryptionByDefault: {
                SSEAlgorithm: 'AES256',
              },
            }],
          },
        },
      },
    },
  };

  const results = await scanner.ruleEngine.evaluate(passingTemplate, 'test.yaml');
  const check = results.find(r => r.ruleId === 'CFN_S3_001');
  assert.strictEqual(check.status, 'PASSED');

  // Failing case
  const failingTemplate = {
    Resources: {
      Bucket: {
        Type: 'AWS::S3::Bucket',
        Properties: {},
      },
    },
  };

  const failResults = await scanner.ruleEngine.evaluate(failingTemplate, 'test.yaml');
  const failCheck = failResults.find(r => r.ruleId === 'CFN_S3_001');
  assert.strictEqual(failCheck.status, 'FAILED');
});
```

### Running Tests

```bash
# Run all tests
npm test

# Run specific test file
node --test tests/unit/scanner.test.js
```

### Test Templates

Place test templates in `tests/fixtures/`:
- `insecure-*.yaml` - Templates that should fail
- `secure-*.yaml` - Templates that should pass

---

## Compliance Mapping

### CIS AWS Foundations Benchmark

Map rules to CIS controls in the `frameworks` array:

```javascript
frameworks: ['CIS'],
// Add CIS control ID in documentation
documentation: 'CIS Control 2.1.1 - https://...',
```

### SOC 2

Map to SOC 2 Trust Service Criteria:
- CC6.1 - Logical access security
- CC6.6 - System boundary protection
- CC6.7 - Transmission integrity

### HIPAA

Map to HIPAA Security Rule sections:
- 164.312(a) - Access controls
- 164.312(e) - Transmission security

### PCI-DSS

Map to PCI-DSS requirements:
- Requirement 2 - Default passwords
- Requirement 3 - Stored data protection
- Requirement 4 - Transmission encryption

---

## Release Process

### Version Numbering

- MAJOR: Breaking changes to rule behavior
- MINOR: New rules or significant improvements
- PATCH: Bug fixes, documentation updates

### Release Checklist

1. **Prepare Release**
   ```bash
   # Validate all rules
   node scripts/rule-updater.js --validate

   # Run all tests
   npm test

   # Update changelog
   node scripts/rule-updater.js --generate-changelog
   ```

2. **Update Version**
   ```bash
   npm version minor  # or major/patch
   ```

3. **Documentation**
   - Update README.md if needed
   - Update docs/RULES.md for new rules
   - Review CHANGELOG.md

4. **Tag and Release**
   ```bash
   git tag v1.x.x
   git push --tags
   ```

---

## Getting Help

- Open an issue for bugs or feature requests
- Join discussions for questions
- Check existing rules for examples

## Code of Conduct

- Be respectful and constructive
- Focus on security best practices
- Provide evidence for severity ratings
- Test thoroughly before submitting

---

## Quick Reference

### Add a New Rule

```bash
node scripts/generate-rule.js
```

### Check for Updates

```bash
node scripts/rule-updater.js --check-updates
node scripts/checkov-mapper.js --report
```

### Validate Rules

```bash
node scripts/rule-updater.js --validate
npm test
```

### View Statistics

```bash
node scripts/rule-updater.js --stats
```
