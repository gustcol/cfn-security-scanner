/**
 * Scanner Unit Tests
 */

const { test, describe, beforeEach } = require('node:test');
const assert = require('node:assert');
const path = require('path');
const Scanner = require('../../src/scanner');

describe('Scanner', () => {
  let scanner;

  beforeEach(async () => {
    scanner = new Scanner();
    await scanner.initialize();
  });

  test('should initialize with default options', async () => {
    assert.strictEqual(scanner.options.failOnSeverity, 'HIGH');
    assert.deepStrictEqual(scanner.options.skipRules, []);
    assert.deepStrictEqual(scanner.options.includeRules, []);
  });

  test('should scan a valid CloudFormation template', async () => {
    const templatePath = path.join(__dirname, '../fixtures/sample-template.yaml');
    const result = await scanner.scanFile(templatePath);

    assert.ok(result.file);
    assert.ok(Array.isArray(result.results));
    assert.strictEqual(scanner.stats.filesScanned, 1);
  });

  test('should detect S3 bucket without encryption', async () => {
    const template = {
      AWSTemplateFormatVersion: '2010-09-09',
      Resources: {
        TestBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {
            BucketName: 'test-bucket',
          },
        },
      },
    };

    const results = await scanner.ruleEngine.evaluate(template, 'test.yaml');
    const encryptionCheck = results.find(r => r.ruleId === 'CFN_S3_001');

    assert.ok(encryptionCheck);
    assert.strictEqual(encryptionCheck.status, 'FAILED');
  });

  test('should pass S3 bucket with encryption', async () => {
    const template = {
      AWSTemplateFormatVersion: '2010-09-09',
      Resources: {
        TestBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {
            BucketName: 'test-bucket',
            BucketEncryption: {
              ServerSideEncryptionConfiguration: [
                {
                  ServerSideEncryptionByDefault: {
                    SSEAlgorithm: 'AES256',
                  },
                },
              ],
            },
          },
        },
      },
    };

    const results = await scanner.ruleEngine.evaluate(template, 'test.yaml');
    const encryptionCheck = results.find(r => r.ruleId === 'CFN_S3_001');

    assert.ok(encryptionCheck);
    assert.strictEqual(encryptionCheck.status, 'PASSED');
  });

  test('should detect security group with open SSH', async () => {
    const template = {
      AWSTemplateFormatVersion: '2010-09-09',
      Resources: {
        TestSG: {
          Type: 'AWS::EC2::SecurityGroup',
          Properties: {
            GroupDescription: 'Test SG',
            SecurityGroupIngress: [
              {
                IpProtocol: 'tcp',
                FromPort: 22,
                ToPort: 22,
                CidrIp: '0.0.0.0/0',
              },
            ],
          },
        },
      },
    };

    const results = await scanner.ruleEngine.evaluate(template, 'test.yaml');
    const sshCheck = results.find(r => r.ruleId === 'CFN_EC2_001');

    assert.ok(sshCheck);
    assert.strictEqual(sshCheck.status, 'FAILED');
    assert.strictEqual(sshCheck.severity, 'CRITICAL');
  });

  test('should respect skipRules option', async () => {
    const skipScanner = new Scanner({
      skipRules: ['CFN_S3_001'],
    });
    await skipScanner.initialize();

    const template = {
      AWSTemplateFormatVersion: '2010-09-09',
      Resources: {
        TestBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {
            BucketName: 'test-bucket',
          },
        },
      },
    };

    const results = await skipScanner.ruleEngine.evaluate(template, 'test.yaml');
    const encryptionCheck = results.find(r => r.ruleId === 'CFN_S3_001');

    assert.strictEqual(encryptionCheck, undefined);
  });

  test('should calculate summary correctly', async () => {
    const template = {
      AWSTemplateFormatVersion: '2010-09-09',
      Resources: {
        TestBucket: {
          Type: 'AWS::S3::Bucket',
          Properties: {
            BucketName: 'test-bucket',
          },
        },
      },
    };

    await scanner.ruleEngine.evaluate(template, 'test.yaml');
    scanner.stats.filesScanned = 1;

    const templatePath = path.join(__dirname, '../fixtures/sample-template.yaml');
    await scanner.scanFile(templatePath);

    const summary = scanner.getSummary();

    assert.ok(summary.filesScanned > 0);
    assert.ok(typeof summary.passed === 'number');
    assert.ok(typeof summary.failed === 'number');
    assert.ok(summary.severityCounts);
  });

  test('should identify CloudFormation templates correctly', () => {
    assert.strictEqual(
      scanner.isCloudFormationTemplate(path.join(__dirname, '../fixtures/sample-template.yaml')),
      true
    );
  });

  test('should handle RDS public access check', async () => {
    const template = {
      AWSTemplateFormatVersion: '2010-09-09',
      Resources: {
        TestDB: {
          Type: 'AWS::RDS::DBInstance',
          Properties: {
            DBInstanceClass: 'db.t3.micro',
            Engine: 'mysql',
            PubliclyAccessible: true,
          },
        },
      },
    };

    const results = await scanner.ruleEngine.evaluate(template, 'test.yaml');
    const publicAccessCheck = results.find(r => r.ruleId === 'CFN_RDS_002');

    assert.ok(publicAccessCheck);
    assert.strictEqual(publicAccessCheck.status, 'FAILED');
    assert.strictEqual(publicAccessCheck.severity, 'CRITICAL');
  });

  test('should detect IAM wildcard actions', async () => {
    const template = {
      AWSTemplateFormatVersion: '2010-09-09',
      Resources: {
        TestPolicy: {
          Type: 'AWS::IAM::Policy',
          Properties: {
            PolicyName: 'TestPolicy',
            PolicyDocument: {
              Version: '2012-10-17',
              Statement: [
                {
                  Effect: 'Allow',
                  Action: '*',
                  Resource: '*',
                },
              ],
            },
          },
        },
      },
    };

    const results = await scanner.ruleEngine.evaluate(template, 'test.yaml');
    const wildcardCheck = results.find(r => r.ruleId === 'CFN_IAM_001');

    assert.ok(wildcardCheck);
    assert.strictEqual(wildcardCheck.status, 'FAILED');
  });
});

describe('Rule Engine', () => {
  let scanner;

  beforeEach(async () => {
    scanner = new Scanner();
    await scanner.initialize();
  });

  test('should register all rules', () => {
    const rules = scanner.ruleEngine.getRules();
    assert.ok(rules.length > 50, `Expected more than 50 rules, got ${rules.length}`);
  });

  test('should get rule by ID', () => {
    const rule = scanner.ruleEngine.getRule('CFN_S3_001');
    assert.ok(rule);
    assert.strictEqual(rule.id, 'CFN_S3_001');
    assert.strictEqual(rule.name, 'S3 Bucket Encryption Enabled');
  });
});
