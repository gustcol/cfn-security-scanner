/**
 * SQS Security Rules
 * Rules for Amazon SQS security best practices
 */

module.exports = [
  {
    id: 'CFN_SQS_001',
    name: 'SQS Queue Encryption',
    description: 'Ensure SQS queues are encrypted with KMS',
    severity: 'HIGH',
    category: 'encryption',
    resourceTypes: ['AWS::SQS::Queue'],
    frameworks: ['SOC2', 'HIPAA', 'PCI-DSS'],
    remediation: 'Configure KmsMasterKeyId for SQS queue encryption',
    documentation: 'https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-server-side-encryption.html',
    evaluate: (context) => {
      const { properties } = context;

      if (!properties.KmsMasterKeyId && properties.SqsManagedSseEnabled !== true) {
        return {
          passed: false,
          message: 'SQS queue is not encrypted',
        };
      }

      return {
        passed: true,
        message: 'SQS queue is encrypted',
      };
    },
  },

  {
    id: 'CFN_SQS_002',
    name: 'SQS Queue Policy Restricted',
    description: 'Ensure SQS queue policy does not allow public access',
    severity: 'CRITICAL',
    category: 'access-control',
    resourceTypes: ['AWS::SQS::QueuePolicy'],
    frameworks: ['SOC2', 'HIPAA', 'PCI-DSS'],
    remediation: 'Restrict PolicyDocument to specific principals',
    documentation: 'https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-basic-examples-of-sqs-policies.html',
    evaluate: (context) => {
      const { properties } = context;

      const policyDocument = properties.PolicyDocument;
      if (!policyDocument || !policyDocument.Statement) {
        return null;
      }

      for (const statement of policyDocument.Statement) {
        if (statement.Effect === 'Allow') {
          const principal = statement.Principal;

          if (principal === '*' && !statement.Condition) {
            return {
              passed: false,
              message: 'SQS queue policy allows unrestricted public access',
            };
          }

          if (typeof principal === 'object' && principal.AWS === '*' && !statement.Condition) {
            return {
              passed: false,
              message: 'SQS queue policy allows access to all AWS principals',
            };
          }
        }
      }

      return {
        passed: true,
        message: 'SQS queue policy restricts access appropriately',
      };
    },
  },

  {
    id: 'CFN_SQS_003',
    name: 'SQS Dead Letter Queue',
    description: 'Ensure SQS queues have a dead letter queue configured',
    severity: 'MEDIUM',
    category: 'availability',
    resourceTypes: ['AWS::SQS::Queue'],
    frameworks: ['SOC2'],
    remediation: 'Configure RedrivePolicy with deadLetterTargetArn',
    documentation: 'https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-dead-letter-queues.html',
    evaluate: (context) => {
      const { properties } = context;

      const redrivePolicy = properties.RedrivePolicy;
      if (!redrivePolicy || !redrivePolicy.deadLetterTargetArn) {
        return {
          passed: false,
          message: 'SQS queue does not have a dead letter queue configured',
        };
      }

      return {
        passed: true,
        message: 'SQS queue has a dead letter queue configured',
      };
    },
  },

  {
    id: 'CFN_SQS_004',
    name: 'SQS Queue SSL Required',
    description: 'Ensure SQS queue policy enforces SSL/TLS',
    severity: 'HIGH',
    category: 'encryption',
    resourceTypes: ['AWS::SQS::QueuePolicy'],
    frameworks: ['SOC2', 'HIPAA', 'PCI-DSS'],
    remediation: 'Add a Deny statement for aws:SecureTransport = false',
    documentation: 'https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-security-best-practices.html',
    evaluate: (context) => {
      const { properties } = context;

      const policyDocument = properties.PolicyDocument;
      if (!policyDocument || !policyDocument.Statement) {
        return {
          passed: false,
          message: 'SQS queue does not have a policy',
        };
      }

      const hasSSLDeny = policyDocument.Statement.some(statement => {
        const condition = statement.Condition;
        return (
          statement.Effect === 'Deny' &&
          condition &&
          (condition.Bool?.['aws:SecureTransport'] === 'false' ||
            condition.Bool?.['aws:SecureTransport'] === false)
        );
      });

      if (!hasSSLDeny) {
        return {
          passed: false,
          message: 'SQS queue policy does not enforce SSL/TLS',
        };
      }

      return {
        passed: true,
        message: 'SQS queue policy enforces SSL/TLS',
      };
    },
  },

  {
    id: 'CFN_SQS_005',
    name: 'SQS Queue Message Retention',
    description: 'Ensure SQS queues have appropriate message retention period',
    severity: 'LOW',
    category: 'data-protection',
    resourceTypes: ['AWS::SQS::Queue'],
    frameworks: ['SOC2'],
    remediation: 'Set MessageRetentionPeriod appropriate for your use case',
    documentation: 'https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-basic-architecture.html',
    evaluate: (context) => {
      const { properties } = context;

      const retention = properties.MessageRetentionPeriod;
      // Default is 4 days (345600 seconds)
      if (!retention) {
        return {
          passed: false,
          message: 'SQS queue uses default message retention (consider configuring explicitly)',
        };
      }

      return {
        passed: true,
        message: `SQS queue has message retention of ${retention} seconds`,
      };
    },
  },

  {
    id: 'CFN_SQS_006',
    name: 'SQS Queue Customer KMS Key',
    description: 'Ensure SQS queues use customer-managed KMS keys',
    severity: 'MEDIUM',
    category: 'encryption',
    resourceTypes: ['AWS::SQS::Queue'],
    frameworks: ['SOC2', 'HIPAA', 'PCI-DSS'],
    remediation: 'Use a customer-managed KMS key instead of AWS-managed key',
    documentation: 'https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-server-side-encryption.html',
    evaluate: (context) => {
      const { properties } = context;

      if (properties.SqsManagedSseEnabled === true) {
        return {
          passed: false,
          message: 'SQS queue uses SQS-managed encryption instead of customer-managed KMS key',
        };
      }

      if (!properties.KmsMasterKeyId) {
        return {
          passed: false,
          message: 'SQS queue is not encrypted with KMS',
        };
      }

      // Check if using alias/aws/sqs (default key)
      if (properties.KmsMasterKeyId === 'alias/aws/sqs') {
        return {
          passed: false,
          message: 'SQS queue uses AWS-managed key instead of customer-managed key',
        };
      }

      return {
        passed: true,
        message: 'SQS queue uses customer-managed KMS key',
      };
    },
  },
];
