/**
 * S3 Security Rules
 * Rules for Amazon S3 bucket security best practices
 */

module.exports = [
  {
    id: 'CFN_S3_001',
    name: 'S3 Bucket Encryption Enabled',
    description: 'Ensure S3 bucket has server-side encryption enabled',
    severity: 'HIGH',
    category: 'encryption',
    resourceTypes: ['AWS::S3::Bucket'],
    frameworks: ['CIS', 'SOC2', 'HIPAA', 'PCI-DSS'],
    remediation: 'Enable server-side encryption using SSE-S3, SSE-KMS, or SSE-C',
    documentation: 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/serv-side-encryption.html',
    evaluate: (context) => {
      const { properties } = context;

      const encryption = properties.BucketEncryption;
      if (!encryption) {
        return {
          passed: false,
          message: 'S3 bucket does not have encryption enabled',
        };
      }

      const rules = encryption.ServerSideEncryptionConfiguration;
      if (!rules || !Array.isArray(rules) || rules.length === 0) {
        return {
          passed: false,
          message: 'S3 bucket encryption configuration is missing or empty',
        };
      }

      return {
        passed: true,
        message: 'S3 bucket has encryption enabled',
      };
    },
  },

  {
    id: 'CFN_S3_002',
    name: 'S3 Bucket Public Access Block',
    description: 'Ensure S3 bucket has public access block configuration',
    severity: 'CRITICAL',
    category: 'access-control',
    resourceTypes: ['AWS::S3::Bucket'],
    frameworks: ['CIS', 'SOC2', 'HIPAA', 'PCI-DSS'],
    remediation: 'Enable PublicAccessBlockConfiguration with all settings set to true',
    documentation: 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html',
    evaluate: (context) => {
      const { properties } = context;

      const publicAccessBlock = properties.PublicAccessBlockConfiguration;
      if (!publicAccessBlock) {
        return {
          passed: false,
          message: 'S3 bucket does not have public access block configuration',
        };
      }

      const requiredSettings = [
        'BlockPublicAcls',
        'BlockPublicPolicy',
        'IgnorePublicAcls',
        'RestrictPublicBuckets',
      ];

      const missingSettings = requiredSettings.filter(
        setting => publicAccessBlock[setting] !== true
      );

      if (missingSettings.length > 0) {
        return {
          passed: false,
          message: `S3 bucket public access block is missing: ${missingSettings.join(', ')}`,
          details: { missingSettings },
        };
      }

      return {
        passed: true,
        message: 'S3 bucket has all public access block settings enabled',
      };
    },
  },

  {
    id: 'CFN_S3_003',
    name: 'S3 Bucket Versioning Enabled',
    description: 'Ensure S3 bucket has versioning enabled for data protection',
    severity: 'MEDIUM',
    category: 'data-protection',
    resourceTypes: ['AWS::S3::Bucket'],
    frameworks: ['CIS', 'SOC2'],
    remediation: 'Enable versioning on the S3 bucket',
    documentation: 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html',
    evaluate: (context) => {
      const { properties } = context;

      const versioning = properties.VersioningConfiguration;
      if (!versioning || versioning.Status !== 'Enabled') {
        return {
          passed: false,
          message: 'S3 bucket versioning is not enabled',
        };
      }

      return {
        passed: true,
        message: 'S3 bucket versioning is enabled',
      };
    },
  },

  {
    id: 'CFN_S3_004',
    name: 'S3 Bucket Logging Enabled',
    description: 'Ensure S3 bucket has access logging enabled',
    severity: 'MEDIUM',
    category: 'logging',
    resourceTypes: ['AWS::S3::Bucket'],
    frameworks: ['CIS', 'SOC2', 'HIPAA'],
    remediation: 'Enable access logging on the S3 bucket',
    documentation: 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html',
    evaluate: (context) => {
      const { properties } = context;

      const logging = properties.LoggingConfiguration;
      if (!logging || !logging.DestinationBucketName) {
        return {
          passed: false,
          message: 'S3 bucket access logging is not enabled',
        };
      }

      return {
        passed: true,
        message: 'S3 bucket access logging is enabled',
      };
    },
  },

  {
    id: 'CFN_S3_005',
    name: 'S3 Bucket SSL Requests Only',
    description: 'Ensure S3 bucket policy requires SSL/TLS for all requests',
    severity: 'HIGH',
    category: 'encryption',
    resourceTypes: ['AWS::S3::BucketPolicy'],
    frameworks: ['CIS', 'SOC2', 'HIPAA', 'PCI-DSS'],
    remediation: 'Add a bucket policy that denies requests without SSL',
    documentation: 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html',
    evaluate: (context) => {
      const { properties } = context;

      const policyDocument = properties.PolicyDocument;
      if (!policyDocument || !policyDocument.Statement) {
        return {
          passed: false,
          message: 'S3 bucket policy is missing',
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
          message: 'S3 bucket policy does not enforce SSL/TLS requests',
        };
      }

      return {
        passed: true,
        message: 'S3 bucket policy enforces SSL/TLS requests',
      };
    },
  },

  {
    id: 'CFN_S3_006',
    name: 'S3 Bucket KMS Encryption',
    description: 'Ensure S3 bucket uses KMS for server-side encryption',
    severity: 'MEDIUM',
    category: 'encryption',
    resourceTypes: ['AWS::S3::Bucket'],
    frameworks: ['SOC2', 'HIPAA', 'PCI-DSS'],
    remediation: 'Configure S3 bucket to use SSE-KMS encryption',
    documentation: 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingKMSEncryption.html',
    evaluate: (context) => {
      const { properties } = context;

      const encryption = properties.BucketEncryption;
      if (!encryption || !encryption.ServerSideEncryptionConfiguration) {
        return {
          passed: false,
          message: 'S3 bucket does not have encryption configured',
        };
      }

      const usesKMS = encryption.ServerSideEncryptionConfiguration.some(config => {
        const rule = config.ServerSideEncryptionByDefault;
        return rule && rule.SSEAlgorithm === 'aws:kms';
      });

      if (!usesKMS) {
        return {
          passed: false,
          message: 'S3 bucket is not using KMS encryption',
        };
      }

      return {
        passed: true,
        message: 'S3 bucket uses KMS encryption',
      };
    },
  },

  {
    id: 'CFN_S3_007',
    name: 'S3 Bucket Lifecycle Configuration',
    description: 'Ensure S3 bucket has lifecycle configuration for data management',
    severity: 'LOW',
    category: 'data-protection',
    resourceTypes: ['AWS::S3::Bucket'],
    frameworks: ['SOC2'],
    remediation: 'Configure lifecycle rules for the S3 bucket',
    documentation: 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lifecycle-mgmt.html',
    evaluate: (context) => {
      const { properties } = context;

      const lifecycle = properties.LifecycleConfiguration;
      if (!lifecycle || !lifecycle.Rules || lifecycle.Rules.length === 0) {
        return {
          passed: false,
          message: 'S3 bucket does not have lifecycle configuration',
        };
      }

      return {
        passed: true,
        message: 'S3 bucket has lifecycle configuration',
      };
    },
  },

  {
    id: 'CFN_S3_008',
    name: 'S3 Bucket MFA Delete Enabled',
    description: 'Ensure S3 bucket has MFA delete enabled for versioned buckets',
    severity: 'MEDIUM',
    category: 'data-protection',
    resourceTypes: ['AWS::S3::Bucket'],
    frameworks: ['CIS', 'SOC2'],
    remediation: 'Enable MFA delete on the versioned S3 bucket',
    documentation: 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/MultiFactorAuthenticationDelete.html',
    evaluate: (context) => {
      const { properties } = context;

      const versioning = properties.VersioningConfiguration;
      if (!versioning || versioning.Status !== 'Enabled') {
        return null; // Only check if versioning is enabled
      }

      // Note: MFADelete cannot be enabled via CloudFormation, only via CLI/SDK
      // This rule checks if the configuration is present
      if (versioning.MFADelete !== 'Enabled') {
        return {
          passed: false,
          message: 'S3 bucket does not have MFA delete enabled (note: must be configured via CLI)',
        };
      }

      return {
        passed: true,
        message: 'S3 bucket has MFA delete enabled',
      };
    },
  },

  {
    id: 'CFN_S3_009',
    name: 'S3 Bucket Object Lock Enabled',
    description: 'Ensure S3 bucket has object lock enabled for compliance',
    severity: 'LOW',
    category: 'data-protection',
    resourceTypes: ['AWS::S3::Bucket'],
    frameworks: ['SOC2', 'HIPAA'],
    remediation: 'Enable object lock on the S3 bucket',
    documentation: 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html',
    evaluate: (context) => {
      const { properties } = context;

      if (!properties.ObjectLockEnabled) {
        return {
          passed: false,
          message: 'S3 bucket does not have object lock enabled',
        };
      }

      return {
        passed: true,
        message: 'S3 bucket has object lock enabled',
      };
    },
  },

  {
    id: 'CFN_S3_010',
    name: 'S3 Bucket Cross-Region Replication',
    description: 'Ensure S3 bucket has cross-region replication for disaster recovery',
    severity: 'LOW',
    category: 'data-protection',
    resourceTypes: ['AWS::S3::Bucket'],
    frameworks: ['SOC2'],
    remediation: 'Configure cross-region replication for the S3 bucket',
    documentation: 'https://docs.aws.amazon.com/AmazonS3/latest/userguide/replication.html',
    evaluate: (context) => {
      const { properties } = context;

      const replication = properties.ReplicationConfiguration;
      if (!replication || !replication.Rules || replication.Rules.length === 0) {
        return {
          passed: false,
          message: 'S3 bucket does not have replication configuration',
        };
      }

      return {
        passed: true,
        message: 'S3 bucket has replication configuration',
      };
    },
  },
];
