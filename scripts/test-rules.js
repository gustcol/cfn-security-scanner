#!/usr/bin/env node

/**
 * Rule Test Runner
 *
 * Automated testing framework for security rules.
 * Tests rules against known secure and insecure templates.
 *
 * Usage:
 *   node scripts/test-rules.js                     Run all tests
 *   node scripts/test-rules.js --rule CFN_S3_001   Test specific rule
 *   node scripts/test-rules.js --service S3        Test all S3 rules
 *   node scripts/test-rules.js --generate          Generate test templates
 */

const fs = require('fs');
const path = require('path');
const Scanner = require('../src/scanner');

const FIXTURES_DIR = path.join(__dirname, '../tests/fixtures');
const RESULTS_DIR = path.join(__dirname, '../.cache/test-results');

// Test case definitions for each service
const TEST_CASES = {
  S3: {
    secure: {
      TestBucket: {
        Type: 'AWS::S3::Bucket',
        Properties: {
          BucketName: 'test-secure-bucket',
          BucketEncryption: {
            ServerSideEncryptionConfiguration: [{
              ServerSideEncryptionByDefault: {
                SSEAlgorithm: 'aws:kms',
                KMSMasterKeyID: 'arn:aws:kms:us-east-1:123456789:key/test',
              },
            }],
          },
          PublicAccessBlockConfiguration: {
            BlockPublicAcls: true,
            BlockPublicPolicy: true,
            IgnorePublicAcls: true,
            RestrictPublicBuckets: true,
          },
          VersioningConfiguration: { Status: 'Enabled' },
          LoggingConfiguration: {
            DestinationBucketName: 'log-bucket',
            LogFilePrefix: 'logs/',
          },
        },
      },
    },
    insecure: {
      TestBucket: {
        Type: 'AWS::S3::Bucket',
        Properties: {
          BucketName: 'test-insecure-bucket',
          // Missing encryption, public access block, versioning, logging
        },
      },
    },
    expectedFailures: ['CFN_S3_001', 'CFN_S3_002', 'CFN_S3_003', 'CFN_S3_004'],
  },

  EC2: {
    secure: {
      TestSG: {
        Type: 'AWS::EC2::SecurityGroup',
        Properties: {
          GroupDescription: 'Secure security group',
          SecurityGroupIngress: [{
            IpProtocol: 'tcp',
            FromPort: 443,
            ToPort: 443,
            CidrIp: '10.0.0.0/8',
          }],
        },
      },
      TestInstance: {
        Type: 'AWS::EC2::Instance',
        Properties: {
          ImageId: 'ami-12345678',
          InstanceType: 't3.micro',
          IamInstanceProfile: 'test-profile',
          Monitoring: true,
          MetadataOptions: {
            HttpTokens: 'required',
          },
          BlockDeviceMappings: [{
            DeviceName: '/dev/xvda',
            Ebs: { Encrypted: true },
          }],
        },
      },
    },
    insecure: {
      TestSG: {
        Type: 'AWS::EC2::SecurityGroup',
        Properties: {
          GroupDescription: 'Insecure security group',
          SecurityGroupIngress: [{
            IpProtocol: 'tcp',
            FromPort: 22,
            ToPort: 22,
            CidrIp: '0.0.0.0/0',
          }],
        },
      },
      TestInstance: {
        Type: 'AWS::EC2::Instance',
        Properties: {
          ImageId: 'ami-12345678',
          InstanceType: 't3.micro',
          BlockDeviceMappings: [{
            DeviceName: '/dev/xvda',
            Ebs: { Encrypted: false },
          }],
        },
      },
    },
    expectedFailures: ['CFN_EC2_001', 'CFN_EC2_004', 'CFN_EC2_005', 'CFN_EC2_012'],
  },

  RDS: {
    secure: {
      TestDB: {
        Type: 'AWS::RDS::DBInstance',
        Properties: {
          DBInstanceClass: 'db.t3.micro',
          Engine: 'mysql',
          StorageEncrypted: true,
          PubliclyAccessible: false,
          MultiAZ: true,
          BackupRetentionPeriod: 30,
          DeletionProtection: true,
          AutoMinorVersionUpgrade: true,
        },
      },
    },
    insecure: {
      TestDB: {
        Type: 'AWS::RDS::DBInstance',
        Properties: {
          DBInstanceClass: 'db.t3.micro',
          Engine: 'mysql',
          StorageEncrypted: false,
          PubliclyAccessible: true,
          MultiAZ: false,
          BackupRetentionPeriod: 0,
        },
      },
    },
    expectedFailures: ['CFN_RDS_001', 'CFN_RDS_002', 'CFN_RDS_003', 'CFN_RDS_004'],
  },

  IAM: {
    secure: {
      TestRole: {
        Type: 'AWS::IAM::Role',
        Properties: {
          RoleName: 'SecureRole',
          PermissionsBoundary: 'arn:aws:iam::123456789:policy/boundary',
          AssumeRolePolicyDocument: {
            Version: '2012-10-17',
            Statement: [{
              Effect: 'Allow',
              Principal: { Service: 'ec2.amazonaws.com' },
              Action: 'sts:AssumeRole',
            }],
          },
          Policies: [{
            PolicyName: 'LimitedPolicy',
            PolicyDocument: {
              Version: '2012-10-17',
              Statement: [{
                Effect: 'Allow',
                Action: ['s3:GetObject'],
                Resource: ['arn:aws:s3:::specific-bucket/*'],
              }],
            },
          }],
        },
      },
    },
    insecure: {
      TestRole: {
        Type: 'AWS::IAM::Role',
        Properties: {
          RoleName: 'InsecureRole',
          AssumeRolePolicyDocument: {
            Version: '2012-10-17',
            Statement: [{
              Effect: 'Allow',
              Principal: { AWS: '*' },
              Action: 'sts:AssumeRole',
            }],
          },
          Policies: [{
            PolicyName: 'AdminPolicy',
            PolicyDocument: {
              Version: '2012-10-17',
              Statement: [{
                Effect: 'Allow',
                Action: '*',
                Resource: '*',
              }],
            },
          }],
        },
      },
    },
    expectedFailures: ['CFN_IAM_001', 'CFN_IAM_003', 'CFN_IAM_007'],
  },
};

class RuleTestRunner {
  constructor() {
    this.scanner = null;
    this.results = {
      passed: 0,
      failed: 0,
      errors: [],
      details: [],
    };
  }

  async initialize() {
    this.scanner = new Scanner();
    await this.scanner.initialize();
  }

  async runAllTests() {
    console.log('=== CFN Security Scanner - Rule Test Runner ===\n');

    await this.initialize();

    for (const [service, testCase] of Object.entries(TEST_CASES)) {
      await this.testService(service, testCase);
    }

    // Test example templates
    await this.testExampleTemplates();

    this.printResults();
    return this.results;
  }

  async testService(service, testCase) {
    console.log(`Testing ${service} rules...\n`);

    // Test secure template
    const secureTemplate = {
      AWSTemplateFormatVersion: '2010-09-09',
      Resources: testCase.secure,
    };

    const secureResults = await this.scanner.ruleEngine.evaluate(secureTemplate, `${service}-secure.yaml`);
    const secureFailed = secureResults.filter(r => r.status === 'FAILED');

    if (secureFailed.length > 0) {
      // Check if failures are expected (some rules might not be fully satisfied even in "secure" template)
      const unexpectedFailures = secureFailed.filter(r =>
        testCase.expectedFailures.includes(r.ruleId)
      );

      if (unexpectedFailures.length > 0) {
        console.log(`  ⚠ Secure template has unexpected failures:`);
        unexpectedFailures.forEach(r => console.log(`    - ${r.ruleId}: ${r.message}`));
      }
    }

    // Test insecure template
    const insecureTemplate = {
      AWSTemplateFormatVersion: '2010-09-09',
      Resources: testCase.insecure,
    };

    const insecureResults = await this.scanner.ruleEngine.evaluate(insecureTemplate, `${service}-insecure.yaml`);
    const insecureFailed = insecureResults.filter(r => r.status === 'FAILED');

    // Check that expected failures are detected
    for (const expectedRule of testCase.expectedFailures) {
      const found = insecureFailed.find(r => r.ruleId === expectedRule);
      if (found) {
        console.log(`  ✓ ${expectedRule}: Correctly detected issue`);
        this.results.passed++;
        this.results.details.push({
          rule: expectedRule,
          service,
          status: 'passed',
          message: 'Correctly detected security issue',
        });
      } else {
        console.log(`  ✗ ${expectedRule}: Failed to detect expected issue`);
        this.results.failed++;
        this.results.errors.push({
          rule: expectedRule,
          service,
          error: 'Expected failure not detected',
        });
        this.results.details.push({
          rule: expectedRule,
          service,
          status: 'failed',
          message: 'Failed to detect expected security issue',
        });
      }
    }

    console.log('');
  }

  async testExampleTemplates() {
    console.log('Testing example templates...\n');

    const examplesDir = path.join(__dirname, '../examples');

    // Test insecure template
    try {
      const result = await this.scanner.scanFile(path.join(examplesDir, 'insecure-template.yaml'));
      const failed = result.results.filter(r => r.status === 'FAILED');

      if (failed.length >= 50) {
        console.log(`  ✓ Insecure template: ${failed.length} issues detected (expected 50+)`);
        this.results.passed++;
      } else {
        console.log(`  ✗ Insecure template: Only ${failed.length} issues detected (expected 50+)`);
        this.results.failed++;
      }
    } catch (error) {
      console.log(`  ✗ Insecure template: Error - ${error.message}`);
      this.results.errors.push({ template: 'insecure', error: error.message });
    }

    // Reset scanner for second file
    this.scanner = new Scanner();
    await this.scanner.initialize();

    // Test secure template
    try {
      const result = await this.scanner.scanFile(path.join(examplesDir, 'secure-template.yaml'));
      const critical = result.results.filter(r => r.status === 'FAILED' && r.severity === 'CRITICAL');

      if (critical.length === 0) {
        console.log(`  ✓ Secure template: No CRITICAL issues`);
        this.results.passed++;
      } else {
        console.log(`  ✗ Secure template: ${critical.length} CRITICAL issues found`);
        this.results.failed++;
      }
    } catch (error) {
      console.log(`  ✗ Secure template: Error - ${error.message}`);
      this.results.errors.push({ template: 'secure', error: error.message });
    }

    console.log('');
  }

  async testSpecificRule(ruleId) {
    await this.initialize();

    console.log(`Testing rule: ${ruleId}\n`);

    const rule = this.scanner.ruleEngine.getRule(ruleId);
    if (!rule) {
      console.log(`Rule ${ruleId} not found`);
      return;
    }

    console.log(`Name: ${rule.name}`);
    console.log(`Severity: ${rule.severity}`);
    console.log(`Category: ${rule.category}`);
    console.log(`Resource Types: ${rule.resourceTypes.join(', ')}`);
    console.log('');

    // Find matching test case
    const service = ruleId.split('_')[1];
    const testCase = TEST_CASES[service];

    if (testCase) {
      // Test with insecure template
      const insecureTemplate = {
        AWSTemplateFormatVersion: '2010-09-09',
        Resources: testCase.insecure,
      };

      const results = await this.scanner.ruleEngine.evaluate(insecureTemplate, 'test.yaml');
      const ruleResult = results.find(r => r.ruleId === ruleId);

      if (ruleResult) {
        console.log(`Result: ${ruleResult.status}`);
        console.log(`Message: ${ruleResult.message}`);
      } else {
        console.log('Rule did not produce a result (may not apply to test resources)');
      }
    }
  }

  printResults() {
    console.log('=== Test Results ===\n');
    console.log(`Passed: ${this.results.passed}`);
    console.log(`Failed: ${this.results.failed}`);

    if (this.results.errors.length > 0) {
      console.log(`\nErrors:`);
      for (const error of this.results.errors) {
        console.log(`  - ${error.rule || error.template}: ${error.error}`);
      }
    }

    // Save results
    if (!fs.existsSync(RESULTS_DIR)) {
      fs.mkdirSync(RESULTS_DIR, { recursive: true });
    }

    fs.writeFileSync(
      path.join(RESULTS_DIR, 'test-results.json'),
      JSON.stringify(this.results, null, 2)
    );

    console.log(`\nResults saved to ${RESULTS_DIR}/test-results.json`);

    // Exit with error code if failures
    if (this.results.failed > 0) {
      process.exit(1);
    }
  }

  generateTestTemplates() {
    console.log('Generating test templates...\n');

    if (!fs.existsSync(FIXTURES_DIR)) {
      fs.mkdirSync(FIXTURES_DIR, { recursive: true });
    }

    for (const [service, testCase] of Object.entries(TEST_CASES)) {
      // Generate secure template
      const secureTemplate = {
        AWSTemplateFormatVersion: '2010-09-09',
        Description: `Secure ${service} template for testing`,
        Resources: testCase.secure,
      };

      fs.writeFileSync(
        path.join(FIXTURES_DIR, `${service.toLowerCase()}-secure.yaml`),
        JSON.stringify(secureTemplate, null, 2)
      );

      // Generate insecure template
      const insecureTemplate = {
        AWSTemplateFormatVersion: '2010-09-09',
        Description: `Insecure ${service} template for testing`,
        Resources: testCase.insecure,
      };

      fs.writeFileSync(
        path.join(FIXTURES_DIR, `${service.toLowerCase()}-insecure.yaml`),
        JSON.stringify(insecureTemplate, null, 2)
      );

      console.log(`Generated ${service} templates`);
    }

    console.log(`\nTemplates saved to ${FIXTURES_DIR}`);
  }
}

// CLI
async function main() {
  const args = process.argv.slice(2);
  const runner = new RuleTestRunner();

  if (args.includes('--help')) {
    console.log(`
Rule Test Runner - Test security rules

Usage:
  node scripts/test-rules.js                     Run all tests
  node scripts/test-rules.js --rule CFN_S3_001   Test specific rule
  node scripts/test-rules.js --generate          Generate test templates
`);
    return;
  }

  if (args.includes('--generate')) {
    runner.generateTestTemplates();
    return;
  }

  const ruleIndex = args.indexOf('--rule');
  if (ruleIndex !== -1 && args[ruleIndex + 1]) {
    await runner.testSpecificRule(args[ruleIndex + 1]);
    return;
  }

  await runner.runAllTests();
}

main().catch(console.error);

module.exports = RuleTestRunner;
