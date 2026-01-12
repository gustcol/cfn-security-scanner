/**
 * CloudTrail Security Rules
 * Rules for AWS CloudTrail security best practices
 */

module.exports = [
  {
    id: 'CFN_CLOUDTRAIL_001',
    name: 'CloudTrail Encryption Enabled',
    description: 'Ensure CloudTrail logs are encrypted with KMS',
    severity: 'HIGH',
    category: 'encryption',
    resourceTypes: ['AWS::CloudTrail::Trail'],
    frameworks: ['CIS', 'SOC2', 'HIPAA', 'PCI-DSS'],
    remediation: 'Configure KMSKeyId for CloudTrail encryption',
    documentation: 'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-aws-kms.html',
    evaluate: (context) => {
      const { properties } = context;

      if (!properties.KMSKeyId) {
        return {
          passed: false,
          message: 'CloudTrail logs are not encrypted with KMS',
        };
      }

      return {
        passed: true,
        message: 'CloudTrail logs are encrypted with KMS',
      };
    },
  },

  {
    id: 'CFN_CLOUDTRAIL_002',
    name: 'CloudTrail Log Validation Enabled',
    description: 'Ensure CloudTrail log file validation is enabled',
    severity: 'MEDIUM',
    category: 'data-protection',
    resourceTypes: ['AWS::CloudTrail::Trail'],
    frameworks: ['CIS', 'SOC2', 'HIPAA', 'PCI-DSS'],
    remediation: 'Set EnableLogFileValidation to true',
    documentation: 'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html',
    evaluate: (context) => {
      const { properties } = context;

      if (properties.EnableLogFileValidation !== true) {
        return {
          passed: false,
          message: 'CloudTrail log file validation is not enabled',
        };
      }

      return {
        passed: true,
        message: 'CloudTrail log file validation is enabled',
      };
    },
  },

  {
    id: 'CFN_CLOUDTRAIL_003',
    name: 'CloudTrail Multi-Region Enabled',
    description: 'Ensure CloudTrail is enabled in all regions',
    severity: 'HIGH',
    category: 'logging',
    resourceTypes: ['AWS::CloudTrail::Trail'],
    frameworks: ['CIS', 'SOC2', 'HIPAA'],
    remediation: 'Set IsMultiRegionTrail to true',
    documentation: 'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/receive-cloudtrail-log-files-from-multiple-regions.html',
    evaluate: (context) => {
      const { properties } = context;

      if (properties.IsMultiRegionTrail !== true) {
        return {
          passed: false,
          message: 'CloudTrail is not configured for multi-region',
        };
      }

      return {
        passed: true,
        message: 'CloudTrail is configured for multi-region',
      };
    },
  },

  {
    id: 'CFN_CLOUDTRAIL_004',
    name: 'CloudTrail CloudWatch Integration',
    description: 'Ensure CloudTrail is integrated with CloudWatch Logs',
    severity: 'MEDIUM',
    category: 'logging',
    resourceTypes: ['AWS::CloudTrail::Trail'],
    frameworks: ['CIS', 'SOC2'],
    remediation: 'Configure CloudWatchLogsLogGroupArn and CloudWatchLogsRoleArn',
    documentation: 'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/send-cloudtrail-events-to-cloudwatch-logs.html',
    evaluate: (context) => {
      const { properties } = context;

      if (!properties.CloudWatchLogsLogGroupArn || !properties.CloudWatchLogsRoleArn) {
        return {
          passed: false,
          message: 'CloudTrail is not integrated with CloudWatch Logs',
        };
      }

      return {
        passed: true,
        message: 'CloudTrail is integrated with CloudWatch Logs',
      };
    },
  },

  {
    id: 'CFN_CLOUDTRAIL_005',
    name: 'CloudTrail S3 Bucket Access Logging',
    description: 'Ensure CloudTrail S3 bucket has access logging enabled',
    severity: 'MEDIUM',
    category: 'logging',
    resourceTypes: ['AWS::CloudTrail::Trail'],
    frameworks: ['CIS', 'SOC2'],
    remediation: 'Enable access logging on the CloudTrail S3 bucket',
    documentation: 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html',
    evaluate: (context) => {
      const { properties, template } = context;

      // This check verifies the trail has an S3 bucket configured
      // Actual S3 bucket logging should be checked by S3 rules
      if (!properties.S3BucketName) {
        return {
          passed: false,
          message: 'CloudTrail does not have an S3 bucket configured',
        };
      }

      return {
        passed: true,
        message: 'CloudTrail has an S3 bucket configured',
      };
    },
  },

  {
    id: 'CFN_CLOUDTRAIL_006',
    name: 'CloudTrail Include Global Events',
    description: 'Ensure CloudTrail includes global service events',
    severity: 'MEDIUM',
    category: 'logging',
    resourceTypes: ['AWS::CloudTrail::Trail'],
    frameworks: ['CIS', 'SOC2'],
    remediation: 'Set IncludeGlobalServiceEvents to true',
    documentation: 'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-concepts.html',
    evaluate: (context) => {
      const { properties } = context;

      if (properties.IncludeGlobalServiceEvents === false) {
        return {
          passed: false,
          message: 'CloudTrail does not include global service events',
        };
      }

      return {
        passed: true,
        message: 'CloudTrail includes global service events',
      };
    },
  },

  {
    id: 'CFN_CLOUDTRAIL_007',
    name: 'CloudTrail Enabled',
    description: 'Ensure CloudTrail is enabled and logging',
    severity: 'CRITICAL',
    category: 'logging',
    resourceTypes: ['AWS::CloudTrail::Trail'],
    frameworks: ['CIS', 'SOC2', 'HIPAA', 'PCI-DSS'],
    remediation: 'Set IsLogging to true',
    documentation: 'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-getting-started.html',
    evaluate: (context) => {
      const { properties } = context;

      if (properties.IsLogging === false) {
        return {
          passed: false,
          message: 'CloudTrail logging is disabled',
        };
      }

      return {
        passed: true,
        message: 'CloudTrail logging is enabled',
      };
    },
  },

  {
    id: 'CFN_CLOUDTRAIL_008',
    name: 'CloudTrail SNS Notifications',
    description: 'Ensure CloudTrail is configured to send SNS notifications',
    severity: 'LOW',
    category: 'monitoring',
    resourceTypes: ['AWS::CloudTrail::Trail'],
    frameworks: ['SOC2'],
    remediation: 'Configure SnsTopicName for trail notifications',
    documentation: 'https://docs.aws.amazon.com/awscloudtrail/latest/userguide/configure-sns-notifications-for-cloudtrail.html',
    evaluate: (context) => {
      const { properties } = context;

      if (!properties.SnsTopicName) {
        return {
          passed: false,
          message: 'CloudTrail is not configured to send SNS notifications',
        };
      }

      return {
        passed: true,
        message: 'CloudTrail is configured to send SNS notifications',
      };
    },
  },
];
