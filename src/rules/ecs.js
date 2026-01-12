/**
 * ECS Security Rules
 * Rules for Amazon ECS security best practices
 */

module.exports = [
  {
    id: 'CFN_ECS_001',
    name: 'ECS Task Definition Encryption',
    description: 'Ensure ECS task definitions use encrypted volumes',
    severity: 'HIGH',
    category: 'encryption',
    resourceTypes: ['AWS::ECS::TaskDefinition'],
    frameworks: ['SOC2', 'HIPAA', 'PCI-DSS'],
    remediation: 'Configure encrypted EFS volumes or encrypted EBS volumes',
    documentation: 'https://docs.aws.amazon.com/AmazonECS/latest/developerguide/efs-volumes.html',
    evaluate: (context) => {
      const { properties } = context;

      const volumes = properties.Volumes || [];
      for (const volume of volumes) {
        if (volume.EFSVolumeConfiguration) {
          const transitEncryption = volume.EFSVolumeConfiguration.TransitEncryption;
          if (transitEncryption !== 'ENABLED') {
            return {
              passed: false,
              message: 'ECS task definition EFS volume does not have transit encryption enabled',
              details: { volumeName: volume.Name },
            };
          }
        }
      }

      return {
        passed: true,
        message: 'ECS task definition volumes have encryption configured',
      };
    },
  },

  {
    id: 'CFN_ECS_002',
    name: 'ECS Task Definition Read-Only Root',
    description: 'Ensure ECS containers have read-only root filesystem',
    severity: 'MEDIUM',
    category: 'access-control',
    resourceTypes: ['AWS::ECS::TaskDefinition'],
    frameworks: ['SOC2'],
    remediation: 'Set ReadonlyRootFilesystem to true in container definitions',
    documentation: 'https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html',
    evaluate: (context) => {
      const { properties } = context;

      const containers = properties.ContainerDefinitions || [];
      for (const container of containers) {
        if (container.ReadonlyRootFilesystem !== true) {
          return {
            passed: false,
            message: `Container ${container.Name} does not have read-only root filesystem`,
            details: { containerName: container.Name },
          };
        }
      }

      return {
        passed: true,
        message: 'All ECS containers have read-only root filesystem',
      };
    },
  },

  {
    id: 'CFN_ECS_003',
    name: 'ECS Task Definition No Privileged',
    description: 'Ensure ECS containers do not run in privileged mode',
    severity: 'CRITICAL',
    category: 'access-control',
    resourceTypes: ['AWS::ECS::TaskDefinition'],
    frameworks: ['SOC2', 'HIPAA', 'PCI-DSS'],
    remediation: 'Set Privileged to false in container definitions',
    documentation: 'https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html',
    evaluate: (context) => {
      const { properties } = context;

      const containers = properties.ContainerDefinitions || [];
      for (const container of containers) {
        if (container.Privileged === true) {
          return {
            passed: false,
            message: `Container ${container.Name} runs in privileged mode`,
            details: { containerName: container.Name },
          };
        }
      }

      return {
        passed: true,
        message: 'No ECS containers run in privileged mode',
      };
    },
  },

  {
    id: 'CFN_ECS_004',
    name: 'ECS Task Definition Logging',
    description: 'Ensure ECS containers have logging configured',
    severity: 'MEDIUM',
    category: 'logging',
    resourceTypes: ['AWS::ECS::TaskDefinition'],
    frameworks: ['SOC2', 'HIPAA'],
    remediation: 'Configure LogConfiguration for container definitions',
    documentation: 'https://docs.aws.amazon.com/AmazonECS/latest/developerguide/using_awslogs.html',
    evaluate: (context) => {
      const { properties } = context;

      const containers = properties.ContainerDefinitions || [];
      for (const container of containers) {
        if (!container.LogConfiguration) {
          return {
            passed: false,
            message: `Container ${container.Name} does not have logging configured`,
            details: { containerName: container.Name },
          };
        }
      }

      return {
        passed: true,
        message: 'All ECS containers have logging configured',
      };
    },
  },

  {
    id: 'CFN_ECS_005',
    name: 'ECS Task Definition No Secrets in Env',
    description: 'Ensure ECS containers do not have hardcoded secrets in environment variables',
    severity: 'CRITICAL',
    category: 'encryption',
    resourceTypes: ['AWS::ECS::TaskDefinition'],
    frameworks: ['SOC2', 'HIPAA', 'PCI-DSS'],
    remediation: 'Use Secrets property with references to Secrets Manager or Parameter Store',
    documentation: 'https://docs.aws.amazon.com/AmazonECS/latest/developerguide/specifying-sensitive-data.html',
    evaluate: (context) => {
      const { properties } = context;

      const sensitivePatterns = [
        /password/i,
        /secret/i,
        /api_key/i,
        /apikey/i,
        /access_key/i,
        /private_key/i,
        /token/i,
        /credential/i,
      ];

      const containers = properties.ContainerDefinitions || [];
      for (const container of containers) {
        const envVars = container.Environment || [];
        for (const env of envVars) {
          if (sensitivePatterns.some(pattern => pattern.test(env.Name))) {
            return {
              passed: false,
              message: `Container ${container.Name} has potentially sensitive environment variable: ${env.Name}`,
              details: { containerName: container.Name, variableName: env.Name },
            };
          }
        }
      }

      return {
        passed: true,
        message: 'No obvious sensitive data in ECS container environment variables',
      };
    },
  },

  {
    id: 'CFN_ECS_006',
    name: 'ECS Service Platform Version',
    description: 'Ensure ECS Fargate services use latest platform version',
    severity: 'MEDIUM',
    category: 'general',
    resourceTypes: ['AWS::ECS::Service'],
    frameworks: ['SOC2'],
    remediation: 'Set PlatformVersion to LATEST',
    documentation: 'https://docs.aws.amazon.com/AmazonECS/latest/developerguide/platform_versions.html',
    evaluate: (context) => {
      const { properties } = context;

      const launchType = properties.LaunchType;
      if (launchType !== 'FARGATE') {
        return null; // Only applies to Fargate
      }

      const platformVersion = properties.PlatformVersion;
      if (platformVersion && platformVersion !== 'LATEST') {
        return {
          passed: false,
          message: `ECS Fargate service uses platform version ${platformVersion} instead of LATEST`,
        };
      }

      return {
        passed: true,
        message: 'ECS Fargate service uses LATEST platform version',
      };
    },
  },

  {
    id: 'CFN_ECS_007',
    name: 'ECS Cluster Container Insights',
    description: 'Ensure ECS clusters have Container Insights enabled',
    severity: 'LOW',
    category: 'monitoring',
    resourceTypes: ['AWS::ECS::Cluster'],
    frameworks: ['SOC2'],
    remediation: 'Enable containerInsights in ClusterSettings',
    documentation: 'https://docs.aws.amazon.com/AmazonECS/latest/developerguide/cloudwatch-container-insights.html',
    evaluate: (context) => {
      const { properties } = context;

      const settings = properties.ClusterSettings || [];
      const hasContainerInsights = settings.some(
        s => s.Name === 'containerInsights' && s.Value === 'enabled'
      );

      if (!hasContainerInsights) {
        return {
          passed: false,
          message: 'ECS cluster does not have Container Insights enabled',
        };
      }

      return {
        passed: true,
        message: 'ECS cluster has Container Insights enabled',
      };
    },
  },

  {
    id: 'CFN_ECS_008',
    name: 'ECS Task Definition User Not Root',
    description: 'Ensure ECS containers do not run as root user',
    severity: 'HIGH',
    category: 'access-control',
    resourceTypes: ['AWS::ECS::TaskDefinition'],
    frameworks: ['SOC2', 'HIPAA'],
    remediation: 'Set User to a non-root user in container definitions',
    documentation: 'https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html',
    evaluate: (context) => {
      const { properties } = context;

      const containers = properties.ContainerDefinitions || [];
      for (const container of containers) {
        if (!container.User || container.User === 'root' || container.User === '0') {
          return {
            passed: false,
            message: `Container ${container.Name} may run as root user`,
            details: { containerName: container.Name },
          };
        }
      }

      return {
        passed: true,
        message: 'All ECS containers run as non-root users',
      };
    },
  },
];
