#!/usr/bin/env node

/**
 * Rule Generator
 *
 * Interactive tool to generate new security rules based on templates.
 *
 * Usage:
 *   node scripts/generate-rule.js
 *   node scripts/generate-rule.js --service S3 --check encryption
 */

const fs = require('fs');
const path = require('path');
const readline = require('readline');

const RULES_DIR = path.join(__dirname, '../src/rules');

// Service configurations
const SERVICE_CONFIG = {
  S3: {
    file: 's3.js',
    prefix: 'CFN_S3',
    resourceTypes: ['AWS::S3::Bucket', 'AWS::S3::BucketPolicy'],
    commonChecks: ['encryption', 'public-access', 'versioning', 'logging', 'lifecycle'],
  },
  EC2: {
    file: 'ec2.js',
    prefix: 'CFN_EC2',
    resourceTypes: ['AWS::EC2::Instance', 'AWS::EC2::SecurityGroup', 'AWS::EC2::Volume', 'AWS::EC2::VPC'],
    commonChecks: ['security-group', 'encryption', 'imdsv2', 'monitoring'],
  },
  RDS: {
    file: 'rds.js',
    prefix: 'CFN_RDS',
    resourceTypes: ['AWS::RDS::DBInstance', 'AWS::RDS::DBCluster'],
    commonChecks: ['encryption', 'public-access', 'backup', 'multi-az', 'logging'],
  },
  IAM: {
    file: 'iam.js',
    prefix: 'CFN_IAM',
    resourceTypes: ['AWS::IAM::Role', 'AWS::IAM::Policy', 'AWS::IAM::User', 'AWS::IAM::ManagedPolicy'],
    commonChecks: ['wildcard', 'admin-access', 'trust-policy', 'permissions-boundary'],
  },
  Lambda: {
    file: 'lambda.js',
    prefix: 'CFN_LAMBDA',
    resourceTypes: ['AWS::Lambda::Function', 'AWS::Lambda::Permission'],
    commonChecks: ['vpc', 'encryption', 'tracing', 'dlq', 'runtime'],
  },
  ECS: {
    file: 'ecs.js',
    prefix: 'CFN_ECS',
    resourceTypes: ['AWS::ECS::TaskDefinition', 'AWS::ECS::Service', 'AWS::ECS::Cluster'],
    commonChecks: ['privileged', 'root-user', 'logging', 'secrets'],
  },
  CloudTrail: {
    file: 'cloudtrail.js',
    prefix: 'CFN_CLOUDTRAIL',
    resourceTypes: ['AWS::CloudTrail::Trail'],
    commonChecks: ['encryption', 'log-validation', 'multi-region', 'cloudwatch'],
  },
  KMS: {
    file: 'kms.js',
    prefix: 'CFN_KMS',
    resourceTypes: ['AWS::KMS::Key'],
    commonChecks: ['rotation', 'key-policy', 'deletion-window'],
  },
  SNS: {
    file: 'sns.js',
    prefix: 'CFN_SNS',
    resourceTypes: ['AWS::SNS::Topic', 'AWS::SNS::TopicPolicy', 'AWS::SNS::Subscription'],
    commonChecks: ['encryption', 'policy', 'https'],
  },
  SQS: {
    file: 'sqs.js',
    prefix: 'CFN_SQS',
    resourceTypes: ['AWS::SQS::Queue', 'AWS::SQS::QueuePolicy'],
    commonChecks: ['encryption', 'policy', 'dlq', 'ssl'],
  },
  ElastiCache: {
    file: 'elasticache.js',
    prefix: 'CFN_ELASTICACHE',
    resourceTypes: ['AWS::ElastiCache::ReplicationGroup', 'AWS::ElastiCache::CacheCluster'],
    commonChecks: ['encryption-rest', 'encryption-transit', 'auth', 'multi-az'],
  },
  APIGateway: {
    file: 'apiGateway.js',
    prefix: 'CFN_APIGW',
    resourceTypes: ['AWS::ApiGateway::RestApi', 'AWS::ApiGateway::Stage', 'AWS::ApiGateway::Method'],
    commonChecks: ['logging', 'waf', 'authorization', 'tls'],
  },
  CloudFront: {
    file: 'cloudfront.js',
    prefix: 'CFN_CLOUDFRONT',
    resourceTypes: ['AWS::CloudFront::Distribution'],
    commonChecks: ['https', 'tls-version', 'logging', 'waf', 'oai'],
  },
  ELB: {
    file: 'elb.js',
    prefix: 'CFN_ELB',
    resourceTypes: ['AWS::ElasticLoadBalancingV2::LoadBalancer', 'AWS::ElasticLoadBalancingV2::Listener'],
    commonChecks: ['logging', 'ssl-policy', 'https', 'waf'],
  },
  SecretsManager: {
    file: 'secretsmanager.js',
    prefix: 'CFN_SECRETS',
    resourceTypes: ['AWS::SecretsManager::Secret', 'AWS::SecretsManager::RotationSchedule'],
    commonChecks: ['encryption', 'rotation', 'hardcoded'],
  },
};

// Rule template
const RULE_TEMPLATE = `
  {
    id: '{{ID}}',
    name: '{{NAME}}',
    description: '{{DESCRIPTION}}',
    severity: '{{SEVERITY}}',
    category: '{{CATEGORY}}',
    resourceTypes: [{{RESOURCE_TYPES}}],
    frameworks: [{{FRAMEWORKS}}],
    remediation: '{{REMEDIATION}}',
    documentation: '{{DOCUMENTATION}}',
    evaluate: (context) => {
      const { properties } = context;

      {{EVALUATE_LOGIC}}

      return {
        passed: true,
        message: '{{PASS_MESSAGE}}',
      };
    },
  },
`;

class RuleGenerator {
  constructor() {
    this.rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });
  }

  async prompt(question, defaultValue = '') {
    return new Promise((resolve) => {
      const defaultStr = defaultValue ? ` (${defaultValue})` : '';
      this.rl.question(`${question}${defaultStr}: `, (answer) => {
        resolve(answer || defaultValue);
      });
    });
  }

  async promptChoice(question, choices) {
    console.log(`\n${question}`);
    choices.forEach((choice, index) => {
      console.log(`  ${index + 1}. ${choice}`);
    });
    const answer = await this.prompt('Enter number', '1');
    return choices[parseInt(answer) - 1] || choices[0];
  }

  async generate() {
    console.log('\n=== CFN Security Scanner - Rule Generator ===\n');

    // Select service
    const services = Object.keys(SERVICE_CONFIG);
    const service = await this.promptChoice('Select AWS service:', services);
    const config = SERVICE_CONFIG[service];

    // Get next rule ID
    const nextId = await this.getNextRuleId(config.prefix);
    console.log(`\nNext available ID: ${nextId}`);

    // Get rule details
    const name = await this.prompt('Rule name (e.g., "S3 Bucket Encryption Enabled")');
    const description = await this.prompt('Description');

    // Select severity
    const severity = await this.promptChoice('Severity:', ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']);

    // Select category
    const category = await this.promptChoice('Category:', [
      'encryption',
      'access-control',
      'network',
      'logging',
      'data-protection',
      'monitoring',
      'availability',
      'general',
    ]);

    // Select resource types
    console.log('\nAvailable resource types:');
    config.resourceTypes.forEach((rt, i) => console.log(`  ${i + 1}. ${rt}`));
    const rtChoice = await this.prompt('Enter numbers (comma-separated)', '1');
    const resourceTypes = rtChoice.split(',').map(n => config.resourceTypes[parseInt(n.trim()) - 1]);

    // Select frameworks
    const frameworks = await this.promptChoice('Compliance frameworks (multi-select with commas):', [
      'CIS',
      'SOC2',
      'HIPAA',
      'PCI-DSS',
      'CIS,SOC2',
      'CIS,SOC2,HIPAA',
      'CIS,SOC2,HIPAA,PCI-DSS',
    ]);

    const remediation = await this.prompt('Remediation guidance');
    const documentation = await this.prompt('Documentation URL', 'https://docs.aws.amazon.com/');

    // Get property to check
    const propertyName = await this.prompt('Property to check (e.g., "BucketEncryption")');
    const checkType = await this.promptChoice('Check type:', [
      'exists',
      'equals',
      'not-equals',
      'contains',
      'array-not-empty',
    ]);

    // Generate evaluate logic
    let evaluateLogic = '';
    switch (checkType) {
      case 'exists':
        evaluateLogic = `
      if (!properties.${propertyName}) {
        return {
          passed: false,
          message: '${name.split(' ')[0]} does not have ${propertyName} configured',
        };
      }`;
        break;
      case 'equals':
        const expectedValue = await this.prompt('Expected value');
        evaluateLogic = `
      if (properties.${propertyName} !== ${expectedValue}) {
        return {
          passed: false,
          message: '${propertyName} is not set to ${expectedValue}',
        };
      }`;
        break;
      case 'not-equals':
        const notValue = await this.prompt('Value that should NOT be set');
        evaluateLogic = `
      if (properties.${propertyName} === ${notValue}) {
        return {
          passed: false,
          message: '${propertyName} should not be ${notValue}',
        };
      }`;
        break;
      case 'contains':
        const containsValue = await this.prompt('Value to check for');
        evaluateLogic = `
      const value = properties.${propertyName};
      if (!value || !value.includes('${containsValue}')) {
        return {
          passed: false,
          message: '${propertyName} does not contain ${containsValue}',
        };
      }`;
        break;
      case 'array-not-empty':
        evaluateLogic = `
      const value = properties.${propertyName};
      if (!value || !Array.isArray(value) || value.length === 0) {
        return {
          passed: false,
          message: '${propertyName} is empty or not configured',
        };
      }`;
        break;
    }

    // Generate rule
    const rule = RULE_TEMPLATE
      .replace('{{ID}}', nextId)
      .replace('{{NAME}}', name)
      .replace('{{DESCRIPTION}}', description)
      .replace('{{SEVERITY}}', severity)
      .replace('{{CATEGORY}}', category)
      .replace('{{RESOURCE_TYPES}}', resourceTypes.map(rt => `'${rt}'`).join(', '))
      .replace('{{FRAMEWORKS}}', frameworks.split(',').map(f => `'${f.trim()}'`).join(', '))
      .replace('{{REMEDIATION}}', remediation)
      .replace('{{DOCUMENTATION}}', documentation)
      .replace('{{EVALUATE_LOGIC}}', evaluateLogic)
      .replace('{{PASS_MESSAGE}}', `${name.split(' ')[0]} ${propertyName} is properly configured`);

    console.log('\n=== Generated Rule ===\n');
    console.log(rule);

    // Save option
    const save = await this.prompt('\nSave to file? (y/n)', 'y');
    if (save.toLowerCase() === 'y') {
      await this.saveRule(config.file, rule);
      console.log(`\nRule saved to src/rules/${config.file}`);
    }

    // Generate test
    const genTest = await this.prompt('Generate test case? (y/n)', 'y');
    if (genTest.toLowerCase() === 'y') {
      await this.generateTest(nextId, name, resourceTypes[0], propertyName);
    }

    this.rl.close();
  }

  async getNextRuleId(prefix) {
    const rulesFile = path.join(RULES_DIR, SERVICE_CONFIG[Object.keys(SERVICE_CONFIG).find(k => SERVICE_CONFIG[k].prefix === prefix)].file);

    if (!fs.existsSync(rulesFile)) {
      return `${prefix}_001`;
    }

    const content = fs.readFileSync(rulesFile, 'utf8');
    const matches = content.match(new RegExp(`${prefix}_(\\d{3})`, 'g')) || [];
    const numbers = matches.map(m => parseInt(m.split('_')[2]));
    const maxNum = Math.max(0, ...numbers);

    return `${prefix}_${String(maxNum + 1).padStart(3, '0')}`;
  }

  async saveRule(file, rule) {
    const filePath = path.join(RULES_DIR, file);
    let content = fs.readFileSync(filePath, 'utf8');

    // Find the last rule and add new one before the closing bracket
    const lastBracket = content.lastIndexOf('];');
    content = content.slice(0, lastBracket) + rule + '\n];';

    fs.writeFileSync(filePath, content);
  }

  async generateTest(ruleId, name, resourceType, propertyName) {
    const testTemplate = `
  test('${ruleId} - ${name}', async () => {
    // Test passing case
    const passingTemplate = {
      AWSTemplateFormatVersion: '2010-09-09',
      Resources: {
        TestResource: {
          Type: '${resourceType}',
          Properties: {
            ${propertyName}: true, // Configure with valid value
          },
        },
      },
    };

    const passingResults = await scanner.ruleEngine.evaluate(passingTemplate, 'test.yaml');
    const passingCheck = passingResults.find(r => r.ruleId === '${ruleId}');
    assert.ok(passingCheck);
    assert.strictEqual(passingCheck.status, 'PASSED');

    // Test failing case
    const failingTemplate = {
      AWSTemplateFormatVersion: '2010-09-09',
      Resources: {
        TestResource: {
          Type: '${resourceType}',
          Properties: {
            // Missing ${propertyName}
          },
        },
      },
    };

    const failingResults = await scanner.ruleEngine.evaluate(failingTemplate, 'test.yaml');
    const failingCheck = failingResults.find(r => r.ruleId === '${ruleId}');
    assert.ok(failingCheck);
    assert.strictEqual(failingCheck.status, 'FAILED');
  });
`;

    console.log('\n=== Generated Test ===\n');
    console.log(testTemplate);
    console.log('\nAdd this to tests/unit/scanner.test.js');
  }
}

// CLI
const args = process.argv.slice(2);

if (args.includes('--help')) {
  console.log(`
Rule Generator - Create new security rules interactively

Usage:
  node scripts/generate-rule.js              Interactive mode
  node scripts/generate-rule.js --help       Show this help

The generator will:
  1. Prompt for service and rule details
  2. Generate the rule code
  3. Optionally save to the appropriate file
  4. Optionally generate a test case
`);
} else {
  const generator = new RuleGenerator();
  generator.generate().catch(console.error);
}
