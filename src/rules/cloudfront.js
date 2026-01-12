/**
 * CloudFront Security Rules
 * Rules for Amazon CloudFront security best practices
 */

module.exports = [
  {
    id: 'CFN_CLOUDFRONT_001',
    name: 'CloudFront HTTPS Only',
    description: 'Ensure CloudFront distributions require HTTPS',
    severity: 'HIGH',
    category: 'encryption',
    resourceTypes: ['AWS::CloudFront::Distribution'],
    frameworks: ['SOC2', 'HIPAA', 'PCI-DSS'],
    remediation: 'Set ViewerProtocolPolicy to https-only or redirect-to-https',
    documentation: 'https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https.html',
    evaluate: (context) => {
      const { properties } = context;

      const config = properties.DistributionConfig;
      if (!config) {
        return null;
      }

      // Check default cache behavior
      const defaultBehavior = config.DefaultCacheBehavior;
      if (defaultBehavior?.ViewerProtocolPolicy === 'allow-all') {
        return {
          passed: false,
          message: 'CloudFront distribution allows HTTP traffic',
        };
      }

      // Check all cache behaviors
      const cacheBehaviors = config.CacheBehaviors || [];
      for (const behavior of cacheBehaviors) {
        if (behavior.ViewerProtocolPolicy === 'allow-all') {
          return {
            passed: false,
            message: 'CloudFront distribution cache behavior allows HTTP traffic',
            details: { pathPattern: behavior.PathPattern },
          };
        }
      }

      return {
        passed: true,
        message: 'CloudFront distribution requires HTTPS',
      };
    },
  },

  {
    id: 'CFN_CLOUDFRONT_002',
    name: 'CloudFront Minimum TLS Version',
    description: 'Ensure CloudFront uses TLS 1.2 or higher',
    severity: 'HIGH',
    category: 'encryption',
    resourceTypes: ['AWS::CloudFront::Distribution'],
    frameworks: ['SOC2', 'HIPAA', 'PCI-DSS'],
    remediation: 'Set MinimumProtocolVersion to TLSv1.2_2021 or higher',
    documentation: 'https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/secure-connections-supported-viewer-protocols-ciphers.html',
    evaluate: (context) => {
      const { properties } = context;

      const config = properties.DistributionConfig;
      if (!config) {
        return null;
      }

      const viewerCert = config.ViewerCertificate;
      if (!viewerCert) {
        return {
          passed: false,
          message: 'CloudFront distribution does not have viewer certificate configured',
        };
      }

      // If using CloudFront default certificate, check minimum protocol version
      if (viewerCert.CloudFrontDefaultCertificate === true) {
        return {
          passed: true,
          message: 'CloudFront distribution uses default certificate with TLS 1.2',
        };
      }

      const minProtocol = viewerCert.MinimumProtocolVersion;
      const insecureProtocols = ['SSLv3', 'TLSv1', 'TLSv1_2016', 'TLSv1.1_2016'];

      if (!minProtocol || insecureProtocols.includes(minProtocol)) {
        return {
          passed: false,
          message: `CloudFront uses insecure TLS version: ${minProtocol || 'not specified'}`,
        };
      }

      return {
        passed: true,
        message: `CloudFront uses secure TLS version: ${minProtocol}`,
      };
    },
  },

  {
    id: 'CFN_CLOUDFRONT_003',
    name: 'CloudFront Logging Enabled',
    description: 'Ensure CloudFront distributions have logging enabled',
    severity: 'MEDIUM',
    category: 'logging',
    resourceTypes: ['AWS::CloudFront::Distribution'],
    frameworks: ['SOC2', 'HIPAA'],
    remediation: 'Configure Logging with S3 bucket destination',
    documentation: 'https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/AccessLogs.html',
    evaluate: (context) => {
      const { properties } = context;

      const config = properties.DistributionConfig;
      if (!config) {
        return null;
      }

      const logging = config.Logging;
      if (!logging || !logging.Bucket) {
        return {
          passed: false,
          message: 'CloudFront distribution does not have logging enabled',
        };
      }

      return {
        passed: true,
        message: 'CloudFront distribution has logging enabled',
      };
    },
  },

  {
    id: 'CFN_CLOUDFRONT_004',
    name: 'CloudFront WAF Integration',
    description: 'Ensure CloudFront distributions are protected by WAF',
    severity: 'HIGH',
    category: 'network',
    resourceTypes: ['AWS::CloudFront::Distribution'],
    frameworks: ['SOC2', 'PCI-DSS'],
    remediation: 'Configure WebACLId to associate a WAF WebACL',
    documentation: 'https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-awswaf.html',
    evaluate: (context) => {
      const { properties } = context;

      const config = properties.DistributionConfig;
      if (!config) {
        return null;
      }

      if (!config.WebACLId) {
        return {
          passed: false,
          message: 'CloudFront distribution is not protected by WAF',
        };
      }

      return {
        passed: true,
        message: 'CloudFront distribution is protected by WAF',
      };
    },
  },

  {
    id: 'CFN_CLOUDFRONT_005',
    name: 'CloudFront Origin Access Identity',
    description: 'Ensure CloudFront uses OAI/OAC for S3 origins',
    severity: 'HIGH',
    category: 'access-control',
    resourceTypes: ['AWS::CloudFront::Distribution'],
    frameworks: ['SOC2', 'HIPAA'],
    remediation: 'Configure Origin Access Identity or Origin Access Control for S3 origins',
    documentation: 'https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-restricting-access-to-s3.html',
    evaluate: (context) => {
      const { properties } = context;

      const config = properties.DistributionConfig;
      if (!config || !config.Origins) {
        return null;
      }

      for (const origin of config.Origins) {
        if (origin.S3OriginConfig) {
          const oai = origin.S3OriginConfig.OriginAccessIdentity;
          const oac = origin.OriginAccessControlId;

          if (!oai && !oac) {
            return {
              passed: false,
              message: 'CloudFront S3 origin does not use OAI or OAC',
              details: { originId: origin.Id },
            };
          }
        }
      }

      return {
        passed: true,
        message: 'CloudFront S3 origins use OAI or OAC',
      };
    },
  },

  {
    id: 'CFN_CLOUDFRONT_006',
    name: 'CloudFront Geo Restriction',
    description: 'Check if CloudFront has geo restriction configured',
    severity: 'LOW',
    category: 'access-control',
    resourceTypes: ['AWS::CloudFront::Distribution'],
    frameworks: ['SOC2'],
    remediation: 'Consider configuring GeoRestriction to limit access by geography',
    documentation: 'https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/georestrictions.html',
    evaluate: (context) => {
      const { properties } = context;

      const config = properties.DistributionConfig;
      if (!config) {
        return null;
      }

      const geoRestriction = config.Restrictions?.GeoRestriction;
      if (!geoRestriction || geoRestriction.RestrictionType === 'none') {
        return {
          passed: false,
          message: 'CloudFront distribution does not have geo restriction configured',
        };
      }

      return {
        passed: true,
        message: `CloudFront has geo restriction: ${geoRestriction.RestrictionType}`,
      };
    },
  },

  {
    id: 'CFN_CLOUDFRONT_007',
    name: 'CloudFront Origin Protocol Policy',
    description: 'Ensure CloudFront uses HTTPS for origin connections',
    severity: 'HIGH',
    category: 'encryption',
    resourceTypes: ['AWS::CloudFront::Distribution'],
    frameworks: ['SOC2', 'HIPAA', 'PCI-DSS'],
    remediation: 'Set OriginProtocolPolicy to https-only',
    documentation: 'https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-values-specify.html',
    evaluate: (context) => {
      const { properties } = context;

      const config = properties.DistributionConfig;
      if (!config || !config.Origins) {
        return null;
      }

      for (const origin of config.Origins) {
        if (origin.CustomOriginConfig) {
          const protocol = origin.CustomOriginConfig.OriginProtocolPolicy;
          if (protocol === 'http-only') {
            return {
              passed: false,
              message: 'CloudFront custom origin uses HTTP-only protocol',
              details: { originId: origin.Id },
            };
          }
        }
      }

      return {
        passed: true,
        message: 'CloudFront uses HTTPS for origin connections',
      };
    },
  },

  {
    id: 'CFN_CLOUDFRONT_008',
    name: 'CloudFront Default Root Object',
    description: 'Ensure CloudFront has a default root object configured',
    severity: 'LOW',
    category: 'general',
    resourceTypes: ['AWS::CloudFront::Distribution'],
    frameworks: ['SOC2'],
    remediation: 'Configure DefaultRootObject (e.g., index.html)',
    documentation: 'https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/DefaultRootObject.html',
    evaluate: (context) => {
      const { properties } = context;

      const config = properties.DistributionConfig;
      if (!config) {
        return null;
      }

      if (!config.DefaultRootObject) {
        return {
          passed: false,
          message: 'CloudFront distribution does not have a default root object',
        };
      }

      return {
        passed: true,
        message: `CloudFront has default root object: ${config.DefaultRootObject}`,
      };
    },
  },

  {
    id: 'CFN_CLOUDFRONT_009',
    name: 'CloudFront Field-Level Encryption',
    description: 'Check if CloudFront uses field-level encryption for sensitive data',
    severity: 'MEDIUM',
    category: 'encryption',
    resourceTypes: ['AWS::CloudFront::Distribution'],
    frameworks: ['SOC2', 'HIPAA', 'PCI-DSS'],
    remediation: 'Configure FieldLevelEncryptionId for sensitive form data',
    documentation: 'https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/field-level-encryption.html',
    evaluate: (context) => {
      const { properties } = context;

      const config = properties.DistributionConfig;
      if (!config) {
        return null;
      }

      const defaultBehavior = config.DefaultCacheBehavior;
      if (!defaultBehavior?.FieldLevelEncryptionId) {
        return {
          passed: false,
          message: 'CloudFront does not use field-level encryption (consider if handling sensitive form data)',
        };
      }

      return {
        passed: true,
        message: 'CloudFront uses field-level encryption',
      };
    },
  },
];
