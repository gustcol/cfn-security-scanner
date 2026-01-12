/**
 * RDS Security Rules
 * Rules for Amazon RDS security best practices
 */

module.exports = [
  {
    id: 'CFN_RDS_001',
    name: 'RDS Storage Encryption',
    description: 'Ensure RDS instances have storage encryption enabled',
    severity: 'HIGH',
    category: 'encryption',
    resourceTypes: ['AWS::RDS::DBInstance'],
    frameworks: ['CIS', 'SOC2', 'HIPAA', 'PCI-DSS'],
    remediation: 'Enable StorageEncrypted property on the RDS instance',
    documentation: 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html',
    evaluate: (context) => {
      const { properties } = context;

      if (properties.StorageEncrypted !== true) {
        return {
          passed: false,
          message: 'RDS instance does not have storage encryption enabled',
        };
      }

      return {
        passed: true,
        message: 'RDS instance has storage encryption enabled',
      };
    },
  },

  {
    id: 'CFN_RDS_002',
    name: 'RDS Public Access Disabled',
    description: 'Ensure RDS instances are not publicly accessible',
    severity: 'CRITICAL',
    category: 'network',
    resourceTypes: ['AWS::RDS::DBInstance'],
    frameworks: ['CIS', 'SOC2', 'HIPAA', 'PCI-DSS'],
    remediation: 'Set PubliclyAccessible to false',
    documentation: 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html',
    evaluate: (context) => {
      const { properties } = context;

      if (properties.PubliclyAccessible === true) {
        return {
          passed: false,
          message: 'RDS instance is publicly accessible',
        };
      }

      return {
        passed: true,
        message: 'RDS instance is not publicly accessible',
      };
    },
  },

  {
    id: 'CFN_RDS_003',
    name: 'RDS Multi-AZ Deployment',
    description: 'Ensure RDS instances have Multi-AZ enabled for high availability',
    severity: 'MEDIUM',
    category: 'availability',
    resourceTypes: ['AWS::RDS::DBInstance'],
    frameworks: ['SOC2'],
    remediation: 'Enable MultiAZ property on the RDS instance',
    documentation: 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.MultiAZ.html',
    evaluate: (context) => {
      const { properties } = context;

      if (properties.MultiAZ !== true) {
        return {
          passed: false,
          message: 'RDS instance does not have Multi-AZ enabled',
        };
      }

      return {
        passed: true,
        message: 'RDS instance has Multi-AZ enabled',
      };
    },
  },

  {
    id: 'CFN_RDS_004',
    name: 'RDS Backup Retention',
    description: 'Ensure RDS instances have backup retention enabled',
    severity: 'MEDIUM',
    category: 'data-protection',
    resourceTypes: ['AWS::RDS::DBInstance'],
    frameworks: ['SOC2', 'HIPAA'],
    remediation: 'Set BackupRetentionPeriod to at least 7 days',
    documentation: 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html',
    evaluate: (context) => {
      const { properties } = context;

      const retention = properties.BackupRetentionPeriod;
      if (retention === undefined || retention === 0 || retention < 7) {
        return {
          passed: false,
          message: `RDS backup retention period is ${retention || 0} days (should be at least 7)`,
          details: { currentRetention: retention || 0 },
        };
      }

      return {
        passed: true,
        message: `RDS backup retention period is ${retention} days`,
      };
    },
  },

  {
    id: 'CFN_RDS_005',
    name: 'RDS Auto Minor Version Upgrade',
    description: 'Ensure RDS instances have auto minor version upgrade enabled',
    severity: 'LOW',
    category: 'general',
    resourceTypes: ['AWS::RDS::DBInstance'],
    frameworks: ['SOC2'],
    remediation: 'Enable AutoMinorVersionUpgrade property',
    documentation: 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_UpgradeDBInstance.Upgrading.html',
    evaluate: (context) => {
      const { properties } = context;

      if (properties.AutoMinorVersionUpgrade === false) {
        return {
          passed: false,
          message: 'RDS instance does not have auto minor version upgrade enabled',
        };
      }

      return {
        passed: true,
        message: 'RDS instance has auto minor version upgrade enabled',
      };
    },
  },

  {
    id: 'CFN_RDS_006',
    name: 'RDS Deletion Protection',
    description: 'Ensure RDS instances have deletion protection enabled',
    severity: 'MEDIUM',
    category: 'data-protection',
    resourceTypes: ['AWS::RDS::DBInstance'],
    frameworks: ['SOC2'],
    remediation: 'Enable DeletionProtection property',
    documentation: 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_DeleteInstance.html',
    evaluate: (context) => {
      const { properties } = context;

      if (properties.DeletionProtection !== true) {
        return {
          passed: false,
          message: 'RDS instance does not have deletion protection enabled',
        };
      }

      return {
        passed: true,
        message: 'RDS instance has deletion protection enabled',
      };
    },
  },

  {
    id: 'CFN_RDS_007',
    name: 'RDS Enhanced Monitoring',
    description: 'Ensure RDS instances have enhanced monitoring enabled',
    severity: 'LOW',
    category: 'monitoring',
    resourceTypes: ['AWS::RDS::DBInstance'],
    frameworks: ['SOC2'],
    remediation: 'Set MonitoringInterval to 1, 5, 10, 15, 30, or 60 seconds',
    documentation: 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_Monitoring.OS.html',
    evaluate: (context) => {
      const { properties } = context;

      const interval = properties.MonitoringInterval;
      if (!interval || interval === 0) {
        return {
          passed: false,
          message: 'RDS instance does not have enhanced monitoring enabled',
        };
      }

      return {
        passed: true,
        message: `RDS instance has enhanced monitoring enabled (${interval}s interval)`,
      };
    },
  },

  {
    id: 'CFN_RDS_008',
    name: 'RDS IAM Authentication',
    description: 'Ensure RDS instances have IAM database authentication enabled',
    severity: 'MEDIUM',
    category: 'access-control',
    resourceTypes: ['AWS::RDS::DBInstance'],
    frameworks: ['SOC2'],
    remediation: 'Enable EnableIAMDatabaseAuthentication property',
    documentation: 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.IAMDBAuth.html',
    evaluate: (context) => {
      const { properties } = context;

      if (properties.EnableIAMDatabaseAuthentication !== true) {
        return {
          passed: false,
          message: 'RDS instance does not have IAM database authentication enabled',
        };
      }

      return {
        passed: true,
        message: 'RDS instance has IAM database authentication enabled',
      };
    },
  },

  {
    id: 'CFN_RDS_009',
    name: 'RDS CloudWatch Logs Export',
    description: 'Ensure RDS instances export logs to CloudWatch',
    severity: 'MEDIUM',
    category: 'logging',
    resourceTypes: ['AWS::RDS::DBInstance'],
    frameworks: ['SOC2', 'HIPAA'],
    remediation: 'Configure EnableCloudwatchLogsExports with appropriate log types',
    documentation: 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_LogAccess.Concepts.html',
    evaluate: (context) => {
      const { properties } = context;

      const exports = properties.EnableCloudwatchLogsExports;
      if (!exports || exports.length === 0) {
        return {
          passed: false,
          message: 'RDS instance does not export logs to CloudWatch',
        };
      }

      return {
        passed: true,
        message: `RDS instance exports logs to CloudWatch: ${exports.join(', ')}`,
      };
    },
  },

  {
    id: 'CFN_RDS_010',
    name: 'RDS KMS Encryption Key',
    description: 'Ensure RDS instances use customer-managed KMS keys for encryption',
    severity: 'MEDIUM',
    category: 'encryption',
    resourceTypes: ['AWS::RDS::DBInstance'],
    frameworks: ['SOC2', 'HIPAA', 'PCI-DSS'],
    remediation: 'Specify a KmsKeyId for encryption',
    documentation: 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html',
    evaluate: (context) => {
      const { properties } = context;

      if (properties.StorageEncrypted === true && !properties.KmsKeyId) {
        return {
          passed: false,
          message: 'RDS instance uses default AWS-managed KMS key instead of customer-managed key',
        };
      }

      if (properties.StorageEncrypted === true && properties.KmsKeyId) {
        return {
          passed: true,
          message: 'RDS instance uses customer-managed KMS key',
        };
      }

      return null; // Skip if encryption is not enabled
    },
  },

  {
    id: 'CFN_RDS_011',
    name: 'RDS Performance Insights',
    description: 'Ensure RDS instances have Performance Insights enabled',
    severity: 'LOW',
    category: 'monitoring',
    resourceTypes: ['AWS::RDS::DBInstance'],
    frameworks: ['SOC2'],
    remediation: 'Enable EnablePerformanceInsights property',
    documentation: 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_PerfInsights.html',
    evaluate: (context) => {
      const { properties } = context;

      if (properties.EnablePerformanceInsights !== true) {
        return {
          passed: false,
          message: 'RDS instance does not have Performance Insights enabled',
        };
      }

      return {
        passed: true,
        message: 'RDS instance has Performance Insights enabled',
      };
    },
  },

  {
    id: 'CFN_RDS_012',
    name: 'RDS Copy Tags to Snapshots',
    description: 'Ensure RDS instances copy tags to snapshots',
    severity: 'LOW',
    category: 'general',
    resourceTypes: ['AWS::RDS::DBInstance'],
    frameworks: ['SOC2'],
    remediation: 'Enable CopyTagsToSnapshot property',
    documentation: 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_Tagging.html',
    evaluate: (context) => {
      const { properties } = context;

      if (properties.CopyTagsToSnapshot !== true) {
        return {
          passed: false,
          message: 'RDS instance does not copy tags to snapshots',
        };
      }

      return {
        passed: true,
        message: 'RDS instance copies tags to snapshots',
      };
    },
  },
];
