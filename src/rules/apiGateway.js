/**
 * API Gateway Security Rules
 * Rules for Amazon API Gateway security best practices
 */

module.exports = [
  {
    id: 'CFN_APIGW_001',
    name: 'API Gateway Access Logging Enabled',
    description: 'Ensure API Gateway stages have access logging enabled',
    severity: 'MEDIUM',
    category: 'logging',
    resourceTypes: ['AWS::ApiGateway::Stage', 'AWS::ApiGatewayV2::Stage'],
    frameworks: ['SOC2', 'HIPAA'],
    remediation: 'Configure AccessLogSetting with DestinationArn and Format',
    documentation: 'https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-logging.html',
    evaluate: (context) => {
      const { properties } = context;

      const accessLogSetting = properties.AccessLogSetting;
      if (!accessLogSetting || !accessLogSetting.DestinationArn) {
        return {
          passed: false,
          message: 'API Gateway stage does not have access logging enabled',
        };
      }

      return {
        passed: true,
        message: 'API Gateway stage has access logging enabled',
      };
    },
  },

  {
    id: 'CFN_APIGW_002',
    name: 'API Gateway X-Ray Tracing',
    description: 'Ensure API Gateway stages have X-Ray tracing enabled',
    severity: 'LOW',
    category: 'monitoring',
    resourceTypes: ['AWS::ApiGateway::Stage'],
    frameworks: ['SOC2'],
    remediation: 'Set TracingEnabled to true',
    documentation: 'https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-xray.html',
    evaluate: (context) => {
      const { properties } = context;

      if (properties.TracingEnabled !== true) {
        return {
          passed: false,
          message: 'API Gateway stage does not have X-Ray tracing enabled',
        };
      }

      return {
        passed: true,
        message: 'API Gateway stage has X-Ray tracing enabled',
      };
    },
  },

  {
    id: 'CFN_APIGW_003',
    name: 'API Gateway WAF Integration',
    description: 'Ensure API Gateway stages are protected by WAF',
    severity: 'HIGH',
    category: 'network',
    resourceTypes: ['AWS::ApiGateway::Stage'],
    frameworks: ['SOC2', 'PCI-DSS'],
    remediation: 'Associate a WAF WebACL with the API Gateway stage',
    documentation: 'https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-control-access-aws-waf.html',
    evaluate: (context) => {
      const { template, resourceName } = context;

      // Check if there's a WAF association
      const resources = template.Resources || {};
      const hasWafAssociation = Object.values(resources).some(resource => {
        return resource.Type === 'AWS::WAFv2::WebACLAssociation' ||
               resource.Type === 'AWS::WAFRegional::WebACLAssociation';
      });

      if (!hasWafAssociation) {
        return {
          passed: false,
          message: 'API Gateway stage is not protected by WAF',
        };
      }

      return {
        passed: true,
        message: 'API Gateway may be protected by WAF (WebACL association found)',
      };
    },
  },

  {
    id: 'CFN_APIGW_004',
    name: 'API Gateway SSL Certificate',
    description: 'Ensure API Gateway uses SSL certificates for client authentication',
    severity: 'MEDIUM',
    category: 'encryption',
    resourceTypes: ['AWS::ApiGateway::Stage'],
    frameworks: ['SOC2', 'PCI-DSS'],
    remediation: 'Configure ClientCertificateId for mutual TLS',
    documentation: 'https://docs.aws.amazon.com/apigateway/latest/developerguide/getting-started-client-side-ssl-authentication.html',
    evaluate: (context) => {
      const { properties } = context;

      if (!properties.ClientCertificateId) {
        return {
          passed: false,
          message: 'API Gateway stage does not have client certificate authentication',
        };
      }

      return {
        passed: true,
        message: 'API Gateway stage has client certificate authentication',
      };
    },
  },

  {
    id: 'CFN_APIGW_005',
    name: 'API Gateway Throttling Configured',
    description: 'Ensure API Gateway has throttling configured to prevent abuse',
    severity: 'MEDIUM',
    category: 'availability',
    resourceTypes: ['AWS::ApiGateway::Stage'],
    frameworks: ['SOC2'],
    remediation: 'Configure MethodSettings with ThrottlingBurstLimit and ThrottlingRateLimit',
    documentation: 'https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-request-throttling.html',
    evaluate: (context) => {
      const { properties } = context;

      const methodSettings = properties.MethodSettings;
      if (!methodSettings || methodSettings.length === 0) {
        return {
          passed: false,
          message: 'API Gateway stage does not have throttling configured',
        };
      }

      const hasThrottling = methodSettings.some(
        setting => setting.ThrottlingBurstLimit || setting.ThrottlingRateLimit
      );

      if (!hasThrottling) {
        return {
          passed: false,
          message: 'API Gateway stage method settings do not include throttling',
        };
      }

      return {
        passed: true,
        message: 'API Gateway stage has throttling configured',
      };
    },
  },

  {
    id: 'CFN_APIGW_006',
    name: 'API Gateway Cache Encryption',
    description: 'Ensure API Gateway caches are encrypted',
    severity: 'MEDIUM',
    category: 'encryption',
    resourceTypes: ['AWS::ApiGateway::Stage'],
    frameworks: ['SOC2', 'HIPAA'],
    remediation: 'Set CacheDataEncrypted to true in MethodSettings',
    documentation: 'https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-caching.html',
    evaluate: (context) => {
      const { properties } = context;

      const methodSettings = properties.MethodSettings;
      if (!methodSettings || methodSettings.length === 0) {
        return null; // No caching configured
      }

      const hasCachingEnabled = methodSettings.some(setting => setting.CachingEnabled);
      if (!hasCachingEnabled) {
        return null; // Caching not enabled
      }

      const cacheEncrypted = methodSettings.every(
        setting => !setting.CachingEnabled || setting.CacheDataEncrypted === true
      );

      if (!cacheEncrypted) {
        return {
          passed: false,
          message: 'API Gateway cache is not encrypted',
        };
      }

      return {
        passed: true,
        message: 'API Gateway cache is encrypted',
      };
    },
  },

  {
    id: 'CFN_APIGW_007',
    name: 'API Gateway Authorization',
    description: 'Ensure API Gateway methods have authorization configured',
    severity: 'HIGH',
    category: 'access-control',
    resourceTypes: ['AWS::ApiGateway::Method'],
    frameworks: ['SOC2', 'HIPAA', 'PCI-DSS'],
    remediation: 'Configure AuthorizationType (AWS_IAM, COGNITO_USER_POOLS, or CUSTOM)',
    documentation: 'https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-control-access-to-api.html',
    evaluate: (context) => {
      const { properties } = context;

      const authType = properties.AuthorizationType;
      if (!authType || authType === 'NONE') {
        return {
          passed: false,
          message: 'API Gateway method does not have authorization configured',
        };
      }

      return {
        passed: true,
        message: `API Gateway method has authorization: ${authType}`,
      };
    },
  },

  {
    id: 'CFN_APIGW_008',
    name: 'API Gateway REST API Endpoint Type',
    description: 'Ensure API Gateway REST APIs use private or regional endpoints',
    severity: 'MEDIUM',
    category: 'network',
    resourceTypes: ['AWS::ApiGateway::RestApi'],
    frameworks: ['SOC2'],
    remediation: 'Configure EndpointConfiguration with PRIVATE or REGIONAL type',
    documentation: 'https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-api-endpoint-types.html',
    evaluate: (context) => {
      const { properties } = context;

      const endpointConfig = properties.EndpointConfiguration;
      if (!endpointConfig || !endpointConfig.Types) {
        return {
          passed: false,
          message: 'API Gateway REST API does not have endpoint configuration',
        };
      }

      if (endpointConfig.Types.includes('EDGE')) {
        return {
          passed: false,
          message: 'API Gateway REST API uses EDGE endpoint (consider REGIONAL or PRIVATE)',
        };
      }

      return {
        passed: true,
        message: `API Gateway REST API uses ${endpointConfig.Types.join(', ')} endpoint`,
      };
    },
  },

  {
    id: 'CFN_APIGW_009',
    name: 'API Gateway Resource Policy',
    description: 'Ensure API Gateway REST APIs have a resource policy',
    severity: 'MEDIUM',
    category: 'access-control',
    resourceTypes: ['AWS::ApiGateway::RestApi'],
    frameworks: ['SOC2'],
    remediation: 'Add a resource policy to restrict access',
    documentation: 'https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-resource-policies.html',
    evaluate: (context) => {
      const { properties } = context;

      if (!properties.Policy) {
        return {
          passed: false,
          message: 'API Gateway REST API does not have a resource policy',
        };
      }

      return {
        passed: true,
        message: 'API Gateway REST API has a resource policy',
      };
    },
  },

  {
    id: 'CFN_APIGW_010',
    name: 'API Gateway Domain TLS Version',
    description: 'Ensure API Gateway custom domains use TLS 1.2',
    severity: 'HIGH',
    category: 'encryption',
    resourceTypes: ['AWS::ApiGateway::DomainName', 'AWS::ApiGatewayV2::DomainName'],
    frameworks: ['SOC2', 'PCI-DSS'],
    remediation: 'Set SecurityPolicy to TLS_1_2',
    documentation: 'https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-custom-domain-tls-version.html',
    evaluate: (context) => {
      const { properties } = context;

      const securityPolicy = properties.SecurityPolicy;
      if (!securityPolicy || securityPolicy === 'TLS_1_0') {
        return {
          passed: false,
          message: 'API Gateway custom domain does not enforce TLS 1.2',
        };
      }

      return {
        passed: true,
        message: 'API Gateway custom domain enforces TLS 1.2',
      };
    },
  },
];
