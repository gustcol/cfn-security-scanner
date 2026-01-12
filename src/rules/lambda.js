/**
 * Lambda Security Rules
 * Rules for AWS Lambda security best practices
 */

module.exports = [
  {
    id: 'CFN_LAMBDA_001',
    name: 'Lambda Function VPC Configuration',
    description: 'Ensure Lambda functions are deployed within a VPC for network isolation',
    severity: 'MEDIUM',
    category: 'network',
    resourceTypes: ['AWS::Lambda::Function'],
    frameworks: ['SOC2', 'HIPAA'],
    remediation: 'Configure VpcConfig with SubnetIds and SecurityGroupIds',
    documentation: 'https://docs.aws.amazon.com/lambda/latest/dg/configuration-vpc.html',
    evaluate: (context) => {
      const { properties } = context;

      const vpcConfig = properties.VpcConfig;
      if (!vpcConfig || !vpcConfig.SubnetIds || vpcConfig.SubnetIds.length === 0) {
        return {
          passed: false,
          message: 'Lambda function is not deployed within a VPC',
        };
      }

      return {
        passed: true,
        message: 'Lambda function is deployed within a VPC',
      };
    },
  },

  {
    id: 'CFN_LAMBDA_002',
    name: 'Lambda Function Environment Variables Encryption',
    description: 'Ensure Lambda function environment variables are encrypted with KMS',
    severity: 'HIGH',
    category: 'encryption',
    resourceTypes: ['AWS::Lambda::Function'],
    frameworks: ['SOC2', 'HIPAA', 'PCI-DSS'],
    remediation: 'Configure KmsKeyArn for environment variable encryption',
    documentation: 'https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars.html',
    evaluate: (context) => {
      const { properties } = context;

      const envVars = properties.Environment?.Variables;
      if (!envVars || Object.keys(envVars).length === 0) {
        return null; // No environment variables, skip
      }

      if (!properties.KmsKeyArn) {
        return {
          passed: false,
          message: 'Lambda function environment variables are not encrypted with a custom KMS key',
        };
      }

      return {
        passed: true,
        message: 'Lambda function environment variables are encrypted with KMS',
      };
    },
  },

  {
    id: 'CFN_LAMBDA_003',
    name: 'Lambda Function Tracing Enabled',
    description: 'Ensure Lambda functions have X-Ray tracing enabled',
    severity: 'LOW',
    category: 'monitoring',
    resourceTypes: ['AWS::Lambda::Function'],
    frameworks: ['SOC2'],
    remediation: 'Set TracingConfig.Mode to Active',
    documentation: 'https://docs.aws.amazon.com/lambda/latest/dg/services-xray.html',
    evaluate: (context) => {
      const { properties } = context;

      const tracingConfig = properties.TracingConfig;
      if (!tracingConfig || tracingConfig.Mode !== 'Active') {
        return {
          passed: false,
          message: 'Lambda function does not have X-Ray tracing enabled',
        };
      }

      return {
        passed: true,
        message: 'Lambda function has X-Ray tracing enabled',
      };
    },
  },

  {
    id: 'CFN_LAMBDA_004',
    name: 'Lambda Function Dead Letter Queue',
    description: 'Ensure Lambda functions have a dead letter queue configured',
    severity: 'MEDIUM',
    category: 'availability',
    resourceTypes: ['AWS::Lambda::Function'],
    frameworks: ['SOC2'],
    remediation: 'Configure DeadLetterConfig with a target SNS topic or SQS queue',
    documentation: 'https://docs.aws.amazon.com/lambda/latest/dg/invocation-async.html',
    evaluate: (context) => {
      const { properties } = context;

      const dlqConfig = properties.DeadLetterConfig;
      if (!dlqConfig || !dlqConfig.TargetArn) {
        return {
          passed: false,
          message: 'Lambda function does not have a dead letter queue configured',
        };
      }

      return {
        passed: true,
        message: 'Lambda function has a dead letter queue configured',
      };
    },
  },

  {
    id: 'CFN_LAMBDA_005',
    name: 'Lambda Function Reserved Concurrency',
    description: 'Ensure Lambda functions have reserved concurrency configured',
    severity: 'LOW',
    category: 'availability',
    resourceTypes: ['AWS::Lambda::Function'],
    frameworks: ['SOC2'],
    remediation: 'Set ReservedConcurrentExecutions to limit concurrent executions',
    documentation: 'https://docs.aws.amazon.com/lambda/latest/dg/configuration-concurrency.html',
    evaluate: (context) => {
      const { properties } = context;

      if (properties.ReservedConcurrentExecutions === undefined) {
        return {
          passed: false,
          message: 'Lambda function does not have reserved concurrency configured',
        };
      }

      return {
        passed: true,
        message: `Lambda function has reserved concurrency: ${properties.ReservedConcurrentExecutions}`,
      };
    },
  },

  {
    id: 'CFN_LAMBDA_006',
    name: 'Lambda Function Code Signing',
    description: 'Ensure Lambda functions have code signing configured',
    severity: 'MEDIUM',
    category: 'access-control',
    resourceTypes: ['AWS::Lambda::Function'],
    frameworks: ['SOC2'],
    remediation: 'Configure CodeSigningConfigArn for code signing validation',
    documentation: 'https://docs.aws.amazon.com/lambda/latest/dg/configuration-codesigning.html',
    evaluate: (context) => {
      const { properties } = context;

      if (!properties.CodeSigningConfigArn) {
        return {
          passed: false,
          message: 'Lambda function does not have code signing configured',
        };
      }

      return {
        passed: true,
        message: 'Lambda function has code signing configured',
      };
    },
  },

  {
    id: 'CFN_LAMBDA_007',
    name: 'Lambda Function Timeout Configuration',
    description: 'Ensure Lambda functions have appropriate timeout configuration',
    severity: 'LOW',
    category: 'general',
    resourceTypes: ['AWS::Lambda::Function'],
    frameworks: ['SOC2'],
    remediation: 'Set an appropriate Timeout value (not default 3 seconds)',
    documentation: 'https://docs.aws.amazon.com/lambda/latest/dg/configuration-function-common.html',
    evaluate: (context) => {
      const { properties } = context;

      const timeout = properties.Timeout;
      if (!timeout || timeout === 3) {
        return {
          passed: false,
          message: 'Lambda function uses default timeout (3 seconds)',
        };
      }

      return {
        passed: true,
        message: `Lambda function has configured timeout: ${timeout} seconds`,
      };
    },
  },

  {
    id: 'CFN_LAMBDA_008',
    name: 'Lambda Permission Source Account',
    description: 'Ensure Lambda permissions specify source account for cross-account access',
    severity: 'HIGH',
    category: 'access-control',
    resourceTypes: ['AWS::Lambda::Permission'],
    frameworks: ['SOC2'],
    remediation: 'Add SourceAccount or SourceArn to Lambda permission',
    documentation: 'https://docs.aws.amazon.com/lambda/latest/dg/access-control-resource-based.html',
    evaluate: (context) => {
      const { properties } = context;

      const principal = properties.Principal;

      // If principal is a service, require SourceAccount or SourceArn
      if (principal && principal.includes('.amazonaws.com')) {
        if (!properties.SourceAccount && !properties.SourceArn) {
          return {
            passed: false,
            message: 'Lambda permission does not specify SourceAccount or SourceArn',
          };
        }
      }

      return {
        passed: true,
        message: 'Lambda permission has appropriate source restrictions',
      };
    },
  },

  {
    id: 'CFN_LAMBDA_009',
    name: 'Lambda Function Runtime Supported',
    description: 'Ensure Lambda functions use supported runtimes',
    severity: 'MEDIUM',
    category: 'general',
    resourceTypes: ['AWS::Lambda::Function'],
    frameworks: ['SOC2'],
    remediation: 'Update to a supported runtime version',
    documentation: 'https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html',
    evaluate: (context) => {
      const { properties } = context;

      const deprecatedRuntimes = [
        'python2.7',
        'python3.6',
        'nodejs10.x',
        'nodejs12.x',
        'dotnetcore2.1',
        'dotnetcore3.1',
        'ruby2.5',
        'java8',
      ];

      const runtime = properties.Runtime;
      if (runtime && deprecatedRuntimes.includes(runtime)) {
        return {
          passed: false,
          message: `Lambda function uses deprecated runtime: ${runtime}`,
          details: { runtime },
        };
      }

      return {
        passed: true,
        message: `Lambda function uses supported runtime: ${runtime || 'container'}`,
      };
    },
  },

  {
    id: 'CFN_LAMBDA_010',
    name: 'Lambda Function No Hardcoded Secrets',
    description: 'Ensure Lambda function environment variables do not contain hardcoded secrets',
    severity: 'CRITICAL',
    category: 'encryption',
    resourceTypes: ['AWS::Lambda::Function'],
    frameworks: ['SOC2', 'HIPAA', 'PCI-DSS'],
    remediation: 'Use AWS Secrets Manager or Parameter Store for sensitive values',
    documentation: 'https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html',
    evaluate: (context) => {
      const { properties } = context;

      const envVars = properties.Environment?.Variables;
      if (!envVars) {
        return null; // No environment variables
      }

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

      const suspiciousVars = [];

      for (const [key, value] of Object.entries(envVars)) {
        // Check if key matches sensitive pattern
        if (sensitivePatterns.some(pattern => pattern.test(key))) {
          // Check if value looks like it might be hardcoded
          if (typeof value === 'string' && !value.startsWith('{{') && !value.includes('!Ref') && !value.includes('!GetAtt')) {
            suspiciousVars.push(key);
          }
        }
      }

      if (suspiciousVars.length > 0) {
        return {
          passed: false,
          message: `Lambda function may have hardcoded secrets in environment variables: ${suspiciousVars.join(', ')}`,
          details: { suspiciousVars },
        };
      }

      return {
        passed: true,
        message: 'Lambda function environment variables do not appear to contain hardcoded secrets',
      };
    },
  },
];
