/**
 * ELB/ALB/NLB Security Rules
 * Rules for Elastic Load Balancer security best practices
 */

module.exports = [
  {
    id: 'CFN_ELB_001',
    name: 'ALB Access Logging Enabled',
    description: 'Ensure Application Load Balancers have access logging enabled',
    severity: 'MEDIUM',
    category: 'logging',
    resourceTypes: ['AWS::ElasticLoadBalancingV2::LoadBalancer'],
    frameworks: ['SOC2', 'HIPAA', 'PCI-DSS'],
    remediation: 'Enable access logging in LoadBalancerAttributes',
    documentation: 'https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html',
    evaluate: (context) => {
      const { properties } = context;

      const attributes = properties.LoadBalancerAttributes || [];
      const accessLogging = attributes.find(attr => attr.Key === 'access_logs.s3.enabled');

      if (!accessLogging || accessLogging.Value !== 'true') {
        return {
          passed: false,
          message: 'Load balancer does not have access logging enabled',
        };
      }

      return {
        passed: true,
        message: 'Load balancer has access logging enabled',
      };
    },
  },

  {
    id: 'CFN_ELB_002',
    name: 'ALB Deletion Protection',
    description: 'Ensure Application Load Balancers have deletion protection enabled',
    severity: 'MEDIUM',
    category: 'data-protection',
    resourceTypes: ['AWS::ElasticLoadBalancingV2::LoadBalancer'],
    frameworks: ['SOC2'],
    remediation: 'Enable deletion_protection.enabled in LoadBalancerAttributes',
    documentation: 'https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html',
    evaluate: (context) => {
      const { properties } = context;

      const attributes = properties.LoadBalancerAttributes || [];
      const deletionProtection = attributes.find(attr => attr.Key === 'deletion_protection.enabled');

      if (!deletionProtection || deletionProtection.Value !== 'true') {
        return {
          passed: false,
          message: 'Load balancer does not have deletion protection enabled',
        };
      }

      return {
        passed: true,
        message: 'Load balancer has deletion protection enabled',
      };
    },
  },

  {
    id: 'CFN_ELB_003',
    name: 'ALB Drop Invalid Headers',
    description: 'Ensure ALB drops invalid HTTP headers',
    severity: 'MEDIUM',
    category: 'network',
    resourceTypes: ['AWS::ElasticLoadBalancingV2::LoadBalancer'],
    frameworks: ['SOC2'],
    remediation: 'Enable routing.http.drop_invalid_header_fields.enabled',
    documentation: 'https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html',
    evaluate: (context) => {
      const { properties } = context;

      if (properties.Type !== 'application') {
        return null; // Only applies to ALB
      }

      const attributes = properties.LoadBalancerAttributes || [];
      const dropHeaders = attributes.find(
        attr => attr.Key === 'routing.http.drop_invalid_header_fields.enabled'
      );

      if (!dropHeaders || dropHeaders.Value !== 'true') {
        return {
          passed: false,
          message: 'ALB does not drop invalid HTTP headers',
        };
      }

      return {
        passed: true,
        message: 'ALB drops invalid HTTP headers',
      };
    },
  },

  {
    id: 'CFN_ELB_004',
    name: 'ALB HTTPS Listener',
    description: 'Ensure ALB listeners use HTTPS protocol',
    severity: 'HIGH',
    category: 'encryption',
    resourceTypes: ['AWS::ElasticLoadBalancingV2::Listener'],
    frameworks: ['SOC2', 'HIPAA', 'PCI-DSS'],
    remediation: 'Use HTTPS protocol for listeners',
    documentation: 'https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html',
    evaluate: (context) => {
      const { properties } = context;

      const protocol = properties.Protocol;
      if (protocol === 'HTTP') {
        // Check if this is a redirect to HTTPS
        const defaultActions = properties.DefaultActions || [];
        const isRedirect = defaultActions.some(
          action => action.Type === 'redirect' && action.RedirectConfig?.Protocol === 'HTTPS'
        );

        if (!isRedirect) {
          return {
            passed: false,
            message: 'ALB listener uses HTTP without redirect to HTTPS',
          };
        }
      }

      return {
        passed: true,
        message: 'ALB listener uses HTTPS or redirects to HTTPS',
      };
    },
  },

  {
    id: 'CFN_ELB_005',
    name: 'ALB SSL Policy',
    description: 'Ensure ALB uses secure SSL/TLS policy',
    severity: 'HIGH',
    category: 'encryption',
    resourceTypes: ['AWS::ElasticLoadBalancingV2::Listener'],
    frameworks: ['SOC2', 'HIPAA', 'PCI-DSS'],
    remediation: 'Use a secure SSL policy (ELBSecurityPolicy-TLS13-1-2-2021-06 or newer)',
    documentation: 'https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html',
    evaluate: (context) => {
      const { properties } = context;

      const protocol = properties.Protocol;
      if (protocol !== 'HTTPS' && protocol !== 'TLS') {
        return null; // Only applies to HTTPS/TLS listeners
      }

      const sslPolicy = properties.SslPolicy;
      const insecurePolicies = [
        'ELBSecurityPolicy-2015-05',
        'ELBSecurityPolicy-2016-08',
        'ELBSecurityPolicy-TLS-1-0-2015-04',
        'ELBSecurityPolicy-TLS-1-1-2017-01',
      ];

      if (!sslPolicy || insecurePolicies.includes(sslPolicy)) {
        return {
          passed: false,
          message: `ALB uses insecure SSL policy: ${sslPolicy || 'default'}`,
        };
      }

      return {
        passed: true,
        message: `ALB uses secure SSL policy: ${sslPolicy}`,
      };
    },
  },

  {
    id: 'CFN_ELB_006',
    name: 'ALB WAF Integration',
    description: 'Ensure Application Load Balancers are protected by WAF',
    severity: 'HIGH',
    category: 'network',
    resourceTypes: ['AWS::ElasticLoadBalancingV2::LoadBalancer'],
    frameworks: ['SOC2', 'PCI-DSS'],
    remediation: 'Associate a WAF WebACL with the ALB',
    documentation: 'https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-associating-aws-resource.html',
    evaluate: (context) => {
      const { properties, template, resourceName } = context;

      if (properties.Type !== 'application') {
        return null; // Only applies to ALB
      }

      // Check if there's a WAF association in the template
      const resources = template.Resources || {};
      const hasWafAssociation = Object.values(resources).some(resource => {
        if (resource.Type === 'AWS::WAFv2::WebACLAssociation') {
          const resourceArn = resource.Properties?.ResourceArn;
          if (typeof resourceArn === 'object' && resourceArn.Ref === resourceName) {
            return true;
          }
        }
        return false;
      });

      if (!hasWafAssociation) {
        return {
          passed: false,
          message: 'ALB is not protected by WAF',
        };
      }

      return {
        passed: true,
        message: 'ALB is protected by WAF',
      };
    },
  },

  {
    id: 'CFN_ELB_007',
    name: 'NLB Cross-Zone Load Balancing',
    description: 'Ensure NLB has cross-zone load balancing enabled',
    severity: 'MEDIUM',
    category: 'availability',
    resourceTypes: ['AWS::ElasticLoadBalancingV2::LoadBalancer'],
    frameworks: ['SOC2'],
    remediation: 'Enable load_balancing.cross_zone.enabled',
    documentation: 'https://docs.aws.amazon.com/elasticloadbalancing/latest/network/network-load-balancers.html',
    evaluate: (context) => {
      const { properties } = context;

      if (properties.Type !== 'network') {
        return null; // Only applies to NLB
      }

      const attributes = properties.LoadBalancerAttributes || [];
      const crossZone = attributes.find(attr => attr.Key === 'load_balancing.cross_zone.enabled');

      if (!crossZone || crossZone.Value !== 'true') {
        return {
          passed: false,
          message: 'NLB does not have cross-zone load balancing enabled',
        };
      }

      return {
        passed: true,
        message: 'NLB has cross-zone load balancing enabled',
      };
    },
  },

  {
    id: 'CFN_ELB_008',
    name: 'ALB Internal Load Balancer',
    description: 'Check if ALB is internet-facing (informational)',
    severity: 'LOW',
    category: 'network',
    resourceTypes: ['AWS::ElasticLoadBalancingV2::LoadBalancer'],
    frameworks: ['SOC2'],
    remediation: 'Consider using internal load balancer if public access is not required',
    documentation: 'https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html',
    evaluate: (context) => {
      const { properties } = context;

      if (properties.Scheme === 'internet-facing') {
        return {
          passed: false,
          message: 'Load balancer is internet-facing (ensure this is intentional)',
        };
      }

      return {
        passed: true,
        message: 'Load balancer is internal',
      };
    },
  },

  {
    id: 'CFN_ELB_009',
    name: 'Classic ELB SSL Policy',
    description: 'Ensure Classic ELB uses secure SSL policy',
    severity: 'HIGH',
    category: 'encryption',
    resourceTypes: ['AWS::ElasticLoadBalancing::LoadBalancer'],
    frameworks: ['SOC2', 'HIPAA', 'PCI-DSS'],
    remediation: 'Migrate to ALB/NLB or use a secure SSL policy',
    documentation: 'https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-ssl-security-policy.html',
    evaluate: (context) => {
      const { properties } = context;

      // Check for HTTPS listeners
      const listeners = properties.Listeners || [];
      const httpsListeners = listeners.filter(l => l.Protocol === 'HTTPS' || l.Protocol === 'SSL');

      if (httpsListeners.length === 0) {
        return {
          passed: false,
          message: 'Classic ELB has no HTTPS listeners configured',
        };
      }

      return {
        passed: true,
        message: 'Classic ELB has HTTPS listeners (consider migrating to ALB/NLB)',
      };
    },
  },
];
