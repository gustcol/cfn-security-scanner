/**
 * IAM Security Rules
 * Rules for AWS IAM security best practices
 */

module.exports = [
  {
    id: 'CFN_IAM_001',
    name: 'IAM Policy No Wildcard Actions',
    description: 'Ensure IAM policies do not allow wildcard (*) actions',
    severity: 'HIGH',
    category: 'access-control',
    resourceTypes: ['AWS::IAM::Policy', 'AWS::IAM::ManagedPolicy', 'AWS::IAM::Role'],
    frameworks: ['CIS', 'SOC2', 'HIPAA', 'PCI-DSS'],
    remediation: 'Replace wildcard actions with specific required actions',
    documentation: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html',
    evaluate: (context) => {
      const { properties, resourceType } = context;

      let policyDocument;

      if (resourceType === 'AWS::IAM::Role') {
        // Check inline policies and AssumeRolePolicyDocument
        const policies = properties.Policies || [];
        for (const policy of policies) {
          policyDocument = policy.PolicyDocument;
          if (policyDocument) {
            const result = checkWildcardActions(policyDocument);
            if (!result.passed) return result;
          }
        }
        return { passed: true, message: 'IAM role does not use wildcard actions' };
      }

      policyDocument = properties.PolicyDocument;
      return checkWildcardActions(policyDocument);
    },
  },

  {
    id: 'CFN_IAM_002',
    name: 'IAM Policy No Wildcard Resources',
    description: 'Ensure IAM policies do not allow wildcard (*) resources with sensitive actions',
    severity: 'HIGH',
    category: 'access-control',
    resourceTypes: ['AWS::IAM::Policy', 'AWS::IAM::ManagedPolicy', 'AWS::IAM::Role'],
    frameworks: ['CIS', 'SOC2', 'HIPAA', 'PCI-DSS'],
    remediation: 'Specify explicit resource ARNs instead of wildcard',
    documentation: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html',
    evaluate: (context) => {
      const { properties, resourceType } = context;

      let policyDocument;

      if (resourceType === 'AWS::IAM::Role') {
        const policies = properties.Policies || [];
        for (const policy of policies) {
          policyDocument = policy.PolicyDocument;
          if (policyDocument) {
            const result = checkWildcardResources(policyDocument);
            if (!result.passed) return result;
          }
        }
        return { passed: true, message: 'IAM role does not use wildcard resources with sensitive actions' };
      }

      policyDocument = properties.PolicyDocument;
      return checkWildcardResources(policyDocument);
    },
  },

  {
    id: 'CFN_IAM_003',
    name: 'IAM Role Trust Policy Restricted',
    description: 'Ensure IAM role trust policies do not allow all principals',
    severity: 'CRITICAL',
    category: 'access-control',
    resourceTypes: ['AWS::IAM::Role'],
    frameworks: ['CIS', 'SOC2', 'HIPAA', 'PCI-DSS'],
    remediation: 'Restrict AssumeRolePolicyDocument to specific principals',
    documentation: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-user.html',
    evaluate: (context) => {
      const { properties } = context;

      const assumeRolePolicy = properties.AssumeRolePolicyDocument;
      if (!assumeRolePolicy || !assumeRolePolicy.Statement) {
        return {
          passed: false,
          message: 'IAM role does not have an AssumeRolePolicyDocument',
        };
      }

      for (const statement of assumeRolePolicy.Statement) {
        if (statement.Effect === 'Allow') {
          const principal = statement.Principal;

          if (principal === '*') {
            return {
              passed: false,
              message: 'IAM role trust policy allows all principals (*)',
            };
          }

          if (typeof principal === 'object') {
            if (principal.AWS === '*' || (Array.isArray(principal.AWS) && principal.AWS.includes('*'))) {
              return {
                passed: false,
                message: 'IAM role trust policy allows all AWS principals (*)',
              };
            }
          }
        }
      }

      return {
        passed: true,
        message: 'IAM role trust policy restricts principals',
      };
    },
  },

  {
    id: 'CFN_IAM_004',
    name: 'IAM User No Inline Policies',
    description: 'Ensure IAM users do not have inline policies attached',
    severity: 'MEDIUM',
    category: 'access-control',
    resourceTypes: ['AWS::IAM::User'],
    frameworks: ['CIS', 'SOC2'],
    remediation: 'Use managed policies instead of inline policies for IAM users',
    documentation: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html',
    evaluate: (context) => {
      const { properties } = context;

      const policies = properties.Policies;
      if (policies && policies.length > 0) {
        return {
          passed: false,
          message: 'IAM user has inline policies attached',
          details: { policyCount: policies.length },
        };
      }

      return {
        passed: true,
        message: 'IAM user does not have inline policies',
      };
    },
  },

  {
    id: 'CFN_IAM_005',
    name: 'IAM Group Membership',
    description: 'Ensure IAM users are members of groups for policy management',
    severity: 'MEDIUM',
    category: 'access-control',
    resourceTypes: ['AWS::IAM::User'],
    frameworks: ['CIS', 'SOC2'],
    remediation: 'Add IAM users to groups and manage permissions through groups',
    documentation: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html',
    evaluate: (context) => {
      const { properties } = context;

      const groups = properties.Groups;
      if (!groups || groups.length === 0) {
        return {
          passed: false,
          message: 'IAM user is not a member of any groups',
        };
      }

      return {
        passed: true,
        message: 'IAM user is a member of groups',
      };
    },
  },

  {
    id: 'CFN_IAM_006',
    name: 'IAM Password Policy Configured',
    description: 'Ensure IAM account password policy is configured',
    severity: 'MEDIUM',
    category: 'access-control',
    resourceTypes: ['AWS::IAM::AccountPasswordPolicy'],
    frameworks: ['CIS', 'SOC2', 'HIPAA', 'PCI-DSS'],
    remediation: 'Configure a strong password policy',
    documentation: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html',
    evaluate: (context) => {
      const { properties } = context;

      const issues = [];

      if (properties.MinimumPasswordLength < 14) {
        issues.push('Minimum password length should be at least 14 characters');
      }

      if (!properties.RequireUppercaseCharacters) {
        issues.push('Password policy should require uppercase characters');
      }

      if (!properties.RequireLowercaseCharacters) {
        issues.push('Password policy should require lowercase characters');
      }

      if (!properties.RequireNumbers) {
        issues.push('Password policy should require numbers');
      }

      if (!properties.RequireSymbols) {
        issues.push('Password policy should require symbols');
      }

      if (properties.MaxPasswordAge > 90 || !properties.MaxPasswordAge) {
        issues.push('Password should expire within 90 days');
      }

      if (properties.PasswordReusePrevention < 24) {
        issues.push('Password reuse prevention should be at least 24 passwords');
      }

      if (issues.length > 0) {
        return {
          passed: false,
          message: 'IAM password policy does not meet security requirements',
          details: { issues },
        };
      }

      return {
        passed: true,
        message: 'IAM password policy meets security requirements',
      };
    },
  },

  {
    id: 'CFN_IAM_007',
    name: 'IAM Policy No Admin Access',
    description: 'Ensure IAM policies do not grant full administrative access',
    severity: 'CRITICAL',
    category: 'access-control',
    resourceTypes: ['AWS::IAM::Policy', 'AWS::IAM::ManagedPolicy', 'AWS::IAM::Role'],
    frameworks: ['CIS', 'SOC2', 'HIPAA', 'PCI-DSS'],
    remediation: 'Follow least privilege principle and grant only required permissions',
    documentation: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege',
    evaluate: (context) => {
      const { properties, resourceType } = context;

      let policyDocument;

      if (resourceType === 'AWS::IAM::Role') {
        const policies = properties.Policies || [];
        for (const policy of policies) {
          policyDocument = policy.PolicyDocument;
          if (policyDocument) {
            const result = checkAdminAccess(policyDocument);
            if (!result.passed) return result;
          }
        }
        return { passed: true, message: 'IAM role does not grant admin access' };
      }

      policyDocument = properties.PolicyDocument;
      return checkAdminAccess(policyDocument);
    },
  },

  {
    id: 'CFN_IAM_008',
    name: 'IAM Role Permissions Boundary',
    description: 'Ensure IAM roles have permissions boundaries set',
    severity: 'MEDIUM',
    category: 'access-control',
    resourceTypes: ['AWS::IAM::Role'],
    frameworks: ['SOC2'],
    remediation: 'Add a PermissionsBoundary to the IAM role',
    documentation: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html',
    evaluate: (context) => {
      const { properties } = context;

      if (!properties.PermissionsBoundary) {
        return {
          passed: false,
          message: 'IAM role does not have a permissions boundary',
        };
      }

      return {
        passed: true,
        message: 'IAM role has a permissions boundary',
      };
    },
  },

  {
    id: 'CFN_IAM_009',
    name: 'IAM Policy Condition Keys',
    description: 'Ensure IAM policies use condition keys for additional security',
    severity: 'LOW',
    category: 'access-control',
    resourceTypes: ['AWS::IAM::Policy', 'AWS::IAM::ManagedPolicy'],
    frameworks: ['SOC2'],
    remediation: 'Add condition keys to IAM policy statements',
    documentation: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html',
    evaluate: (context) => {
      const { properties } = context;

      const policyDocument = properties.PolicyDocument;
      if (!policyDocument || !policyDocument.Statement) {
        return null;
      }

      const statementsWithConditions = policyDocument.Statement.filter(
        s => s.Condition && Object.keys(s.Condition).length > 0
      );

      if (statementsWithConditions.length === 0) {
        return {
          passed: false,
          message: 'IAM policy does not use condition keys',
        };
      }

      return {
        passed: true,
        message: 'IAM policy uses condition keys',
      };
    },
  },

  {
    id: 'CFN_IAM_010',
    name: 'IAM User No Direct Policies',
    description: 'Ensure IAM users do not have policies attached directly',
    severity: 'MEDIUM',
    category: 'access-control',
    resourceTypes: ['AWS::IAM::User'],
    frameworks: ['CIS', 'SOC2'],
    remediation: 'Use groups to assign policies to users',
    documentation: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html',
    evaluate: (context) => {
      const { properties } = context;

      const managedPolicies = properties.ManagedPolicyArns;
      if (managedPolicies && managedPolicies.length > 0) {
        return {
          passed: false,
          message: 'IAM user has managed policies attached directly',
          details: { policyCount: managedPolicies.length },
        };
      }

      return {
        passed: true,
        message: 'IAM user does not have policies attached directly',
      };
    },
  },
];

// Helper function to check for wildcard actions
function checkWildcardActions(policyDocument) {
  if (!policyDocument || !policyDocument.Statement) {
    return { passed: true, message: 'Policy document is empty' };
  }

  for (const statement of policyDocument.Statement) {
    if (statement.Effect === 'Allow') {
      const actions = Array.isArray(statement.Action) ? statement.Action : [statement.Action];

      for (const action of actions) {
        if (action === '*' || action === '*:*') {
          return {
            passed: false,
            message: 'IAM policy allows wildcard actions (*)',
            details: { action },
          };
        }
      }
    }
  }

  return {
    passed: true,
    message: 'IAM policy does not use wildcard actions',
  };
}

// Helper function to check for wildcard resources with sensitive actions
function checkWildcardResources(policyDocument) {
  if (!policyDocument || !policyDocument.Statement) {
    return { passed: true, message: 'Policy document is empty' };
  }

  const sensitiveActionPrefixes = [
    'iam:', 'sts:', 'kms:', 'secretsmanager:', 'ssm:GetParameter',
    'ec2:RunInstances', 'lambda:InvokeFunction', 's3:DeleteBucket',
  ];

  for (const statement of policyDocument.Statement) {
    if (statement.Effect === 'Allow') {
      const actions = Array.isArray(statement.Action) ? statement.Action : [statement.Action];
      const resources = Array.isArray(statement.Resource) ? statement.Resource : [statement.Resource];

      const hasSensitiveAction = actions.some(action =>
        sensitiveActionPrefixes.some(prefix => action.startsWith(prefix) || action === '*')
      );

      if (hasSensitiveAction && resources.includes('*')) {
        return {
          passed: false,
          message: 'IAM policy allows sensitive actions on wildcard resources',
          details: { actions, resources },
        };
      }
    }
  }

  return {
    passed: true,
    message: 'IAM policy does not use wildcard resources with sensitive actions',
  };
}

// Helper function to check for admin access
function checkAdminAccess(policyDocument) {
  if (!policyDocument || !policyDocument.Statement) {
    return { passed: true, message: 'Policy document is empty' };
  }

  for (const statement of policyDocument.Statement) {
    if (statement.Effect === 'Allow') {
      const actions = Array.isArray(statement.Action) ? statement.Action : [statement.Action];
      const resources = Array.isArray(statement.Resource) ? statement.Resource : [statement.Resource];

      // Check for Action: * with Resource: *
      if ((actions.includes('*') || actions.includes('*:*')) && resources.includes('*')) {
        return {
          passed: false,
          message: 'IAM policy grants full administrative access (Action: *, Resource: *)',
        };
      }
    }
  }

  return {
    passed: true,
    message: 'IAM policy does not grant full administrative access',
  };
}
