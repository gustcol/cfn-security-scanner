/**
 * Secrets Manager Security Rules
 * Rules for AWS Secrets Manager security best practices
 */

module.exports = [
  {
    id: 'CFN_SECRETS_001',
    name: 'Secret KMS Encryption',
    description: 'Ensure Secrets Manager secrets use customer-managed KMS keys',
    severity: 'MEDIUM',
    category: 'encryption',
    resourceTypes: ['AWS::SecretsManager::Secret'],
    frameworks: ['SOC2', 'HIPAA', 'PCI-DSS'],
    remediation: 'Configure KmsKeyId with a customer-managed KMS key',
    documentation: 'https://docs.aws.amazon.com/secretsmanager/latest/userguide/security-encryption.html',
    evaluate: (context) => {
      const { properties } = context;

      if (!properties.KmsKeyId) {
        return {
          passed: false,
          message: 'Secret uses AWS-managed key instead of customer-managed KMS key',
        };
      }

      return {
        passed: true,
        message: 'Secret uses customer-managed KMS key',
      };
    },
  },

  {
    id: 'CFN_SECRETS_002',
    name: 'Secret Rotation Enabled',
    description: 'Ensure Secrets Manager secrets have rotation enabled',
    severity: 'HIGH',
    category: 'access-control',
    resourceTypes: ['AWS::SecretsManager::Secret'],
    frameworks: ['SOC2', 'HIPAA', 'PCI-DSS'],
    remediation: 'Configure secret rotation with a Lambda function',
    documentation: 'https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html',
    evaluate: (context) => {
      const { properties, template, resourceName } = context;

      // Check if there's a rotation schedule for this secret
      const resources = template.Resources || {};
      const hasRotation = Object.values(resources).some(resource => {
        if (resource.Type === 'AWS::SecretsManager::RotationSchedule') {
          const secretId = resource.Properties?.SecretId;
          if (typeof secretId === 'object' && secretId.Ref === resourceName) {
            return true;
          }
        }
        return false;
      });

      if (!hasRotation) {
        return {
          passed: false,
          message: 'Secret does not have rotation enabled',
        };
      }

      return {
        passed: true,
        message: 'Secret has rotation enabled',
      };
    },
  },

  {
    id: 'CFN_SECRETS_003',
    name: 'Secret No Hardcoded Values',
    description: 'Ensure secrets do not have hardcoded secret values',
    severity: 'CRITICAL',
    category: 'encryption',
    resourceTypes: ['AWS::SecretsManager::Secret'],
    frameworks: ['SOC2', 'HIPAA', 'PCI-DSS'],
    remediation: 'Use GenerateSecretString instead of SecretString with hardcoded values',
    documentation: 'https://docs.aws.amazon.com/secretsmanager/latest/userguide/create_secret.html',
    evaluate: (context) => {
      const { properties } = context;

      // Check if SecretString is used with a literal value
      if (properties.SecretString && typeof properties.SecretString === 'string') {
        // If it's a simple string (not a CloudFormation intrinsic function)
        if (!properties.SecretString.startsWith('{{') && !properties.SecretString.includes('!')) {
          return {
            passed: false,
            message: 'Secret has hardcoded value in SecretString (use GenerateSecretString)',
          };
        }
      }

      return {
        passed: true,
        message: 'Secret does not have obvious hardcoded values',
      };
    },
  },

  {
    id: 'CFN_SECRETS_004',
    name: 'Secret Resource Policy',
    description: 'Ensure secrets have a resource policy for access control',
    severity: 'MEDIUM',
    category: 'access-control',
    resourceTypes: ['AWS::SecretsManager::Secret'],
    frameworks: ['SOC2'],
    remediation: 'Add a ResourcePolicy to restrict access to the secret',
    documentation: 'https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access_resource-policies.html',
    evaluate: (context) => {
      const { properties, template, resourceName } = context;

      // Check if there's a resource policy for this secret
      const resources = template.Resources || {};
      const hasResourcePolicy = Object.values(resources).some(resource => {
        if (resource.Type === 'AWS::SecretsManager::ResourcePolicy') {
          const secretId = resource.Properties?.SecretId;
          if (typeof secretId === 'object' && secretId.Ref === resourceName) {
            return true;
          }
        }
        return false;
      });

      if (!hasResourcePolicy) {
        return {
          passed: false,
          message: 'Secret does not have a resource policy',
        };
      }

      return {
        passed: true,
        message: 'Secret has a resource policy',
      };
    },
  },

  {
    id: 'CFN_SECRETS_005',
    name: 'Secret Description',
    description: 'Ensure secrets have a description for documentation',
    severity: 'LOW',
    category: 'general',
    resourceTypes: ['AWS::SecretsManager::Secret'],
    frameworks: ['SOC2'],
    remediation: 'Add a Description to the secret',
    documentation: 'https://docs.aws.amazon.com/secretsmanager/latest/userguide/create_secret.html',
    evaluate: (context) => {
      const { properties } = context;

      if (!properties.Description || properties.Description.trim() === '') {
        return {
          passed: false,
          message: 'Secret does not have a description',
        };
      }

      return {
        passed: true,
        message: 'Secret has a description',
      };
    },
  },

  {
    id: 'CFN_SECRETS_006',
    name: 'Secret Rotation Schedule',
    description: 'Ensure secret rotation schedule is appropriately configured',
    severity: 'MEDIUM',
    category: 'access-control',
    resourceTypes: ['AWS::SecretsManager::RotationSchedule'],
    frameworks: ['SOC2', 'HIPAA', 'PCI-DSS'],
    remediation: 'Set RotationRules with AutomaticallyAfterDays of 90 or less',
    documentation: 'https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html',
    evaluate: (context) => {
      const { properties } = context;

      const rotationRules = properties.RotationRules;
      if (!rotationRules) {
        return {
          passed: false,
          message: 'Secret rotation schedule does not have rotation rules',
        };
      }

      const days = rotationRules.AutomaticallyAfterDays;
      if (days && days > 90) {
        return {
          passed: false,
          message: `Secret rotation interval is ${days} days (should be 90 or less)`,
          details: { rotationDays: days },
        };
      }

      return {
        passed: true,
        message: `Secret rotation is configured for ${days} days`,
      };
    },
  },
];
