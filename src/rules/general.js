/**
 * General Security Rules
 * Template-wide and general security best practices
 */

module.exports = [
  {
    id: 'CFN_GEN_001',
    name: 'No Hardcoded Credentials',
    description: 'Ensure templates do not contain hardcoded credentials',
    severity: 'CRITICAL',
    category: 'encryption',
    resourceTypes: ['AWS::CloudFormation::Template'],
    frameworks: ['SOC2', 'HIPAA', 'PCI-DSS'],
    remediation: 'Use AWS Secrets Manager, Parameter Store, or dynamic references',
    documentation: 'https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/dynamic-references.html',
    evaluate: (context) => {
      const { template } = context;

      const sensitivePatterns = [
        { pattern: /AKIA[0-9A-Z]{16}/g, name: 'AWS Access Key ID' },
        { pattern: /[A-Za-z0-9/+=]{40}/g, name: 'Potential AWS Secret Key' },
        { pattern: /password\s*[:=]\s*["'][^"']+["']/gi, name: 'Hardcoded Password' },
        { pattern: /secret\s*[:=]\s*["'][^"']+["']/gi, name: 'Hardcoded Secret' },
        { pattern: /api[_-]?key\s*[:=]\s*["'][^"']+["']/gi, name: 'Hardcoded API Key' },
      ];

      const templateStr = JSON.stringify(template);

      for (const { pattern, name } of sensitivePatterns) {
        if (pattern.test(templateStr)) {
          return {
            passed: false,
            message: `Template may contain ${name}`,
            details: { type: name },
          };
        }
      }

      return {
        passed: true,
        message: 'No obvious hardcoded credentials detected',
      };
    },
  },

  {
    id: 'CFN_GEN_002',
    name: 'Stack Termination Protection',
    description: 'Recommend enabling stack termination protection for production stacks',
    severity: 'LOW',
    category: 'data-protection',
    resourceTypes: ['AWS::CloudFormation::Template'],
    frameworks: ['SOC2'],
    remediation: 'Enable termination protection when deploying the stack',
    documentation: 'https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-protect-stacks.html',
    evaluate: (context) => {
      // This is informational - termination protection is set at deployment time
      return {
        passed: true,
        message: 'Remember to enable termination protection for production stacks',
      };
    },
  },

  {
    id: 'CFN_GEN_003',
    name: 'DeletionPolicy Configured',
    description: 'Ensure critical resources have DeletionPolicy configured',
    severity: 'MEDIUM',
    category: 'data-protection',
    resourceTypes: ['AWS::CloudFormation::Template'],
    frameworks: ['SOC2'],
    remediation: 'Add DeletionPolicy: Retain or Snapshot to critical resources',
    documentation: 'https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-deletionpolicy.html',
    evaluate: (context) => {
      const { template } = context;

      const criticalResourceTypes = [
        'AWS::RDS::DBInstance',
        'AWS::RDS::DBCluster',
        'AWS::DynamoDB::Table',
        'AWS::S3::Bucket',
        'AWS::EFS::FileSystem',
        'AWS::ElastiCache::ReplicationGroup',
      ];

      const resources = template.Resources || {};
      const missingDeletionPolicy = [];

      for (const [name, resource] of Object.entries(resources)) {
        if (criticalResourceTypes.includes(resource.Type)) {
          if (!resource.DeletionPolicy) {
            missingDeletionPolicy.push(name);
          }
        }
      }

      if (missingDeletionPolicy.length > 0) {
        return {
          passed: false,
          message: `Critical resources without DeletionPolicy: ${missingDeletionPolicy.join(', ')}`,
          details: { resources: missingDeletionPolicy },
        };
      }

      return {
        passed: true,
        message: 'Critical resources have DeletionPolicy configured',
      };
    },
  },

  {
    id: 'CFN_GEN_004',
    name: 'Resource Tags',
    description: 'Ensure resources have appropriate tags for management and compliance',
    severity: 'LOW',
    category: 'general',
    resourceTypes: ['AWS::CloudFormation::Template'],
    frameworks: ['SOC2'],
    remediation: 'Add Tags property to all taggable resources',
    documentation: 'https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html',
    evaluate: (context) => {
      const { template } = context;

      const taggableResourceTypes = [
        'AWS::EC2::Instance',
        'AWS::EC2::SecurityGroup',
        'AWS::EC2::VPC',
        'AWS::S3::Bucket',
        'AWS::RDS::DBInstance',
        'AWS::Lambda::Function',
        'AWS::ECS::Service',
        'AWS::ECS::Cluster',
      ];

      const resources = template.Resources || {};
      const missingTags = [];

      for (const [name, resource] of Object.entries(resources)) {
        if (taggableResourceTypes.includes(resource.Type)) {
          const tags = resource.Properties?.Tags;
          if (!tags || tags.length === 0) {
            missingTags.push(name);
          }
        }
      }

      if (missingTags.length > 0) {
        return {
          passed: false,
          message: `Resources without tags: ${missingTags.slice(0, 5).join(', ')}${missingTags.length > 5 ? '...' : ''}`,
          details: { resources: missingTags },
        };
      }

      return {
        passed: true,
        message: 'Resources have tags configured',
      };
    },
  },

  {
    id: 'CFN_GEN_005',
    name: 'Parameters NoEcho',
    description: 'Ensure sensitive parameters use NoEcho property',
    severity: 'HIGH',
    category: 'encryption',
    resourceTypes: ['AWS::CloudFormation::Template'],
    frameworks: ['SOC2', 'HIPAA', 'PCI-DSS'],
    remediation: 'Set NoEcho: true for parameters containing sensitive data',
    documentation: 'https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/parameters-section-structure.html',
    evaluate: (context) => {
      const { template } = context;

      const parameters = template.Parameters || {};
      const sensitivePatterns = [
        /password/i,
        /secret/i,
        /key/i,
        /token/i,
        /credential/i,
      ];

      const missingNoEcho = [];

      for (const [name, param] of Object.entries(parameters)) {
        if (sensitivePatterns.some(pattern => pattern.test(name))) {
          if (param.NoEcho !== true) {
            missingNoEcho.push(name);
          }
        }
      }

      if (missingNoEcho.length > 0) {
        return {
          passed: false,
          message: `Sensitive parameters without NoEcho: ${missingNoEcho.join(', ')}`,
          details: { parameters: missingNoEcho },
        };
      }

      return {
        passed: true,
        message: 'Sensitive parameters use NoEcho',
      };
    },
  },

  {
    id: 'CFN_GEN_006',
    name: 'CloudWatch Alarms',
    description: 'Ensure critical resources have CloudWatch alarms configured',
    severity: 'MEDIUM',
    category: 'monitoring',
    resourceTypes: ['AWS::CloudFormation::Template'],
    frameworks: ['SOC2'],
    remediation: 'Add CloudWatch alarms for critical metrics',
    documentation: 'https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html',
    evaluate: (context) => {
      const { template } = context;

      const resources = template.Resources || {};
      const hasAlarms = Object.values(resources).some(
        resource => resource.Type === 'AWS::CloudWatch::Alarm'
      );

      if (!hasAlarms) {
        return {
          passed: false,
          message: 'Template does not define any CloudWatch alarms',
        };
      }

      return {
        passed: true,
        message: 'Template includes CloudWatch alarms',
      };
    },
  },

  {
    id: 'CFN_GEN_007',
    name: 'Template Description',
    description: 'Ensure template has a description',
    severity: 'LOW',
    category: 'general',
    resourceTypes: ['AWS::CloudFormation::Template'],
    frameworks: ['SOC2'],
    remediation: 'Add a Description to the template',
    documentation: 'https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/template-anatomy.html',
    evaluate: (context) => {
      const { template } = context;

      if (!template.Description || template.Description.trim() === '') {
        return {
          passed: false,
          message: 'Template does not have a description',
        };
      }

      return {
        passed: true,
        message: 'Template has a description',
      };
    },
  },

  {
    id: 'CFN_GEN_008',
    name: 'Template Metadata',
    description: 'Check if template has metadata for documentation',
    severity: 'LOW',
    category: 'general',
    resourceTypes: ['AWS::CloudFormation::Template'],
    frameworks: ['SOC2'],
    remediation: 'Add Metadata section for documentation',
    documentation: 'https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/metadata-section-structure.html',
    evaluate: (context) => {
      const { template } = context;

      if (!template.Metadata) {
        return {
          passed: false,
          message: 'Template does not have metadata section',
        };
      }

      return {
        passed: true,
        message: 'Template has metadata section',
      };
    },
  },

  {
    id: 'CFN_GEN_009',
    name: 'UpdateReplacePolicy Configured',
    description: 'Ensure stateful resources have UpdateReplacePolicy configured',
    severity: 'MEDIUM',
    category: 'data-protection',
    resourceTypes: ['AWS::CloudFormation::Template'],
    frameworks: ['SOC2'],
    remediation: 'Add UpdateReplacePolicy: Retain or Snapshot to stateful resources',
    documentation: 'https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-attribute-updatereplacepolicy.html',
    evaluate: (context) => {
      const { template } = context;

      const statefulResourceTypes = [
        'AWS::RDS::DBInstance',
        'AWS::RDS::DBCluster',
        'AWS::DynamoDB::Table',
        'AWS::EFS::FileSystem',
      ];

      const resources = template.Resources || {};
      const missingPolicy = [];

      for (const [name, resource] of Object.entries(resources)) {
        if (statefulResourceTypes.includes(resource.Type)) {
          if (!resource.UpdateReplacePolicy) {
            missingPolicy.push(name);
          }
        }
      }

      if (missingPolicy.length > 0) {
        return {
          passed: false,
          message: `Stateful resources without UpdateReplacePolicy: ${missingPolicy.join(', ')}`,
          details: { resources: missingPolicy },
        };
      }

      return {
        passed: true,
        message: 'Stateful resources have UpdateReplacePolicy configured',
      };
    },
  },

  {
    id: 'CFN_GEN_010',
    name: 'No Deprecated Resource Types',
    description: 'Ensure template does not use deprecated resource types',
    severity: 'MEDIUM',
    category: 'general',
    resourceTypes: ['AWS::CloudFormation::Template'],
    frameworks: ['SOC2'],
    remediation: 'Replace deprecated resources with their modern equivalents',
    documentation: 'https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-template-resource-type-ref.html',
    evaluate: (context) => {
      const { template } = context;

      const deprecatedTypes = [
        'AWS::ElasticLoadBalancing::LoadBalancer', // Use ELBv2 instead
      ];

      const resources = template.Resources || {};
      const deprecated = [];

      for (const [name, resource] of Object.entries(resources)) {
        if (deprecatedTypes.includes(resource.Type)) {
          deprecated.push({ name, type: resource.Type });
        }
      }

      if (deprecated.length > 0) {
        return {
          passed: false,
          message: `Template uses deprecated resource types: ${deprecated.map(d => d.type).join(', ')}`,
          details: { deprecated },
        };
      }

      return {
        passed: true,
        message: 'Template does not use deprecated resource types',
      };
    },
  },
];
