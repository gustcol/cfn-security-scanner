/**
 * KMS Security Rules
 * Rules for AWS KMS security best practices
 */

module.exports = [
  {
    id: 'CFN_KMS_001',
    name: 'KMS Key Rotation Enabled',
    description: 'Ensure KMS keys have automatic rotation enabled',
    severity: 'MEDIUM',
    category: 'encryption',
    resourceTypes: ['AWS::KMS::Key'],
    frameworks: ['CIS', 'SOC2', 'HIPAA', 'PCI-DSS'],
    remediation: 'Set EnableKeyRotation to true',
    documentation: 'https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html',
    evaluate: (context) => {
      const { properties } = context;

      // Skip for asymmetric keys (rotation not supported)
      if (properties.KeySpec && !properties.KeySpec.includes('SYMMETRIC')) {
        return null;
      }

      if (properties.EnableKeyRotation !== true) {
        return {
          passed: false,
          message: 'KMS key does not have automatic rotation enabled',
        };
      }

      return {
        passed: true,
        message: 'KMS key has automatic rotation enabled',
      };
    },
  },

  {
    id: 'CFN_KMS_002',
    name: 'KMS Key Policy Restricted',
    description: 'Ensure KMS key policy does not allow public access',
    severity: 'CRITICAL',
    category: 'access-control',
    resourceTypes: ['AWS::KMS::Key'],
    frameworks: ['CIS', 'SOC2', 'HIPAA', 'PCI-DSS'],
    remediation: 'Restrict KeyPolicy to specific principals',
    documentation: 'https://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html',
    evaluate: (context) => {
      const { properties } = context;

      const keyPolicy = properties.KeyPolicy;
      if (!keyPolicy || !keyPolicy.Statement) {
        return null;
      }

      for (const statement of keyPolicy.Statement) {
        if (statement.Effect === 'Allow') {
          const principal = statement.Principal;

          if (principal === '*') {
            // Check for conditions that might restrict access
            if (!statement.Condition) {
              return {
                passed: false,
                message: 'KMS key policy allows unrestricted public access',
              };
            }
          }

          if (typeof principal === 'object' && principal.AWS === '*') {
            if (!statement.Condition) {
              return {
                passed: false,
                message: 'KMS key policy allows access to all AWS principals',
              };
            }
          }
        }
      }

      return {
        passed: true,
        message: 'KMS key policy restricts access appropriately',
      };
    },
  },

  {
    id: 'CFN_KMS_003',
    name: 'KMS Key Description',
    description: 'Ensure KMS keys have a meaningful description',
    severity: 'LOW',
    category: 'general',
    resourceTypes: ['AWS::KMS::Key'],
    frameworks: ['SOC2'],
    remediation: 'Add a Description to the KMS key',
    documentation: 'https://docs.aws.amazon.com/kms/latest/developerguide/create-keys.html',
    evaluate: (context) => {
      const { properties } = context;

      if (!properties.Description || properties.Description.trim() === '') {
        return {
          passed: false,
          message: 'KMS key does not have a description',
        };
      }

      return {
        passed: true,
        message: 'KMS key has a description',
      };
    },
  },

  {
    id: 'CFN_KMS_004',
    name: 'KMS Key Pending Deletion Window',
    description: 'Ensure KMS keys have appropriate pending deletion window',
    severity: 'MEDIUM',
    category: 'data-protection',
    resourceTypes: ['AWS::KMS::Key'],
    frameworks: ['SOC2'],
    remediation: 'Set PendingWindowInDays to at least 14 days',
    documentation: 'https://docs.aws.amazon.com/kms/latest/developerguide/deleting-keys.html',
    evaluate: (context) => {
      const { properties } = context;

      const pendingWindow = properties.PendingWindowInDays;
      if (pendingWindow && pendingWindow < 14) {
        return {
          passed: false,
          message: `KMS key pending deletion window is ${pendingWindow} days (should be at least 14)`,
          details: { pendingWindow },
        };
      }

      return {
        passed: true,
        message: 'KMS key has appropriate pending deletion window',
      };
    },
  },

  {
    id: 'CFN_KMS_005',
    name: 'KMS Key Multi-Region',
    description: 'Check if KMS keys are configured as multi-region for disaster recovery',
    severity: 'LOW',
    category: 'availability',
    resourceTypes: ['AWS::KMS::Key'],
    frameworks: ['SOC2'],
    remediation: 'Consider using MultiRegion: true for disaster recovery scenarios',
    documentation: 'https://docs.aws.amazon.com/kms/latest/developerguide/multi-region-keys-overview.html',
    evaluate: (context) => {
      const { properties } = context;

      if (properties.MultiRegion !== true) {
        return {
          passed: false,
          message: 'KMS key is not configured as multi-region',
        };
      }

      return {
        passed: true,
        message: 'KMS key is configured as multi-region',
      };
    },
  },

  {
    id: 'CFN_KMS_006',
    name: 'KMS Key Usage Restricted',
    description: 'Ensure KMS key policy restricts key usage appropriately',
    severity: 'MEDIUM',
    category: 'access-control',
    resourceTypes: ['AWS::KMS::Key'],
    frameworks: ['SOC2'],
    remediation: 'Use conditions in key policy to restrict key usage',
    documentation: 'https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-modifying.html',
    evaluate: (context) => {
      const { properties } = context;

      const keyPolicy = properties.KeyPolicy;
      if (!keyPolicy || !keyPolicy.Statement) {
        return {
          passed: false,
          message: 'KMS key does not have a key policy defined',
        };
      }

      // Check if at least one statement has conditions
      const hasConditions = keyPolicy.Statement.some(
        s => s.Condition && Object.keys(s.Condition).length > 0
      );

      if (!hasConditions) {
        return {
          passed: false,
          message: 'KMS key policy does not use conditions to restrict access',
        };
      }

      return {
        passed: true,
        message: 'KMS key policy uses conditions to restrict access',
      };
    },
  },
];
