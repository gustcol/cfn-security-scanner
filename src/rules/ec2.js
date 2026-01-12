/**
 * EC2 Security Rules
 * Rules for Amazon EC2 security best practices
 */

module.exports = [
  {
    id: 'CFN_EC2_001',
    name: 'Security Group Unrestricted SSH',
    description: 'Ensure no security group allows unrestricted SSH access (0.0.0.0/0)',
    severity: 'CRITICAL',
    category: 'network',
    resourceTypes: ['AWS::EC2::SecurityGroup'],
    frameworks: ['CIS', 'SOC2', 'HIPAA', 'PCI-DSS'],
    remediation: 'Restrict SSH access to specific IP ranges or use bastion hosts',
    documentation: 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security-groups.html',
    evaluate: (context) => {
      const { properties } = context;

      const ingress = properties.SecurityGroupIngress || [];

      for (const rule of ingress) {
        const fromPort = rule.FromPort;
        const toPort = rule.ToPort;
        const cidr = rule.CidrIp || '';
        const cidrv6 = rule.CidrIpv6 || '';

        // Check for SSH port (22)
        if (fromPort <= 22 && toPort >= 22) {
          if (cidr === '0.0.0.0/0' || cidrv6 === '::/0') {
            return {
              passed: false,
              message: 'Security group allows unrestricted SSH access from 0.0.0.0/0',
              details: { port: 22, cidr: cidr || cidrv6 },
            };
          }
        }
      }

      return {
        passed: true,
        message: 'Security group does not allow unrestricted SSH access',
      };
    },
  },

  {
    id: 'CFN_EC2_002',
    name: 'Security Group Unrestricted RDP',
    description: 'Ensure no security group allows unrestricted RDP access (0.0.0.0/0)',
    severity: 'CRITICAL',
    category: 'network',
    resourceTypes: ['AWS::EC2::SecurityGroup'],
    frameworks: ['CIS', 'SOC2', 'HIPAA', 'PCI-DSS'],
    remediation: 'Restrict RDP access to specific IP ranges or use bastion hosts',
    documentation: 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security-groups.html',
    evaluate: (context) => {
      const { properties } = context;

      const ingress = properties.SecurityGroupIngress || [];

      for (const rule of ingress) {
        const fromPort = rule.FromPort;
        const toPort = rule.ToPort;
        const cidr = rule.CidrIp || '';
        const cidrv6 = rule.CidrIpv6 || '';

        // Check for RDP port (3389)
        if (fromPort <= 3389 && toPort >= 3389) {
          if (cidr === '0.0.0.0/0' || cidrv6 === '::/0') {
            return {
              passed: false,
              message: 'Security group allows unrestricted RDP access from 0.0.0.0/0',
              details: { port: 3389, cidr: cidr || cidrv6 },
            };
          }
        }
      }

      return {
        passed: true,
        message: 'Security group does not allow unrestricted RDP access',
      };
    },
  },

  {
    id: 'CFN_EC2_003',
    name: 'Security Group Unrestricted All Traffic',
    description: 'Ensure no security group allows unrestricted inbound traffic',
    severity: 'CRITICAL',
    category: 'network',
    resourceTypes: ['AWS::EC2::SecurityGroup'],
    frameworks: ['CIS', 'SOC2', 'HIPAA', 'PCI-DSS'],
    remediation: 'Restrict inbound traffic to required ports and IP ranges only',
    documentation: 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security-groups.html',
    evaluate: (context) => {
      const { properties } = context;

      const ingress = properties.SecurityGroupIngress || [];

      for (const rule of ingress) {
        const protocol = rule.IpProtocol;
        const cidr = rule.CidrIp || '';
        const cidrv6 = rule.CidrIpv6 || '';

        // Check for all traffic (-1 protocol) from anywhere
        if (protocol === '-1' || protocol === -1) {
          if (cidr === '0.0.0.0/0' || cidrv6 === '::/0') {
            return {
              passed: false,
              message: 'Security group allows unrestricted inbound traffic (all ports) from 0.0.0.0/0',
              details: { protocol, cidr: cidr || cidrv6 },
            };
          }
        }
      }

      return {
        passed: true,
        message: 'Security group does not allow unrestricted all traffic',
      };
    },
  },

  {
    id: 'CFN_EC2_004',
    name: 'EC2 Instance IMDSv2 Required',
    description: 'Ensure EC2 instances require IMDSv2 (Instance Metadata Service v2)',
    severity: 'HIGH',
    category: 'access-control',
    resourceTypes: ['AWS::EC2::Instance', 'AWS::EC2::LaunchTemplate'],
    frameworks: ['CIS', 'SOC2'],
    remediation: 'Configure MetadataOptions with HttpTokens set to required',
    documentation: 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html',
    evaluate: (context) => {
      const { properties, resourceType } = context;

      let metadataOptions;

      if (resourceType === 'AWS::EC2::LaunchTemplate') {
        metadataOptions = properties.LaunchTemplateData?.MetadataOptions;
      } else {
        metadataOptions = properties.MetadataOptions;
      }

      if (!metadataOptions || metadataOptions.HttpTokens !== 'required') {
        return {
          passed: false,
          message: 'EC2 instance does not require IMDSv2',
        };
      }

      return {
        passed: true,
        message: 'EC2 instance requires IMDSv2',
      };
    },
  },

  {
    id: 'CFN_EC2_005',
    name: 'EC2 Instance EBS Encryption',
    description: 'Ensure EC2 instance EBS volumes are encrypted',
    severity: 'HIGH',
    category: 'encryption',
    resourceTypes: ['AWS::EC2::Instance'],
    frameworks: ['CIS', 'SOC2', 'HIPAA', 'PCI-DSS'],
    remediation: 'Enable encryption for all EBS volumes attached to the instance',
    documentation: 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html',
    evaluate: (context) => {
      const { properties } = context;

      const blockDevices = properties.BlockDeviceMappings || [];

      for (const device of blockDevices) {
        const ebs = device.Ebs;
        if (ebs && ebs.Encrypted !== true) {
          return {
            passed: false,
            message: `EBS volume ${device.DeviceName || 'unknown'} is not encrypted`,
            details: { deviceName: device.DeviceName },
          };
        }
      }

      return {
        passed: true,
        message: 'All EBS volumes are encrypted',
      };
    },
  },

  {
    id: 'CFN_EC2_006',
    name: 'EC2 Instance Detailed Monitoring',
    description: 'Ensure EC2 instances have detailed monitoring enabled',
    severity: 'LOW',
    category: 'monitoring',
    resourceTypes: ['AWS::EC2::Instance'],
    frameworks: ['SOC2'],
    remediation: 'Enable detailed monitoring for the EC2 instance',
    documentation: 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-cloudwatch-new.html',
    evaluate: (context) => {
      const { properties } = context;

      if (properties.Monitoring !== true) {
        return {
          passed: false,
          message: 'EC2 instance does not have detailed monitoring enabled',
        };
      }

      return {
        passed: true,
        message: 'EC2 instance has detailed monitoring enabled',
      };
    },
  },

  {
    id: 'CFN_EC2_007',
    name: 'EC2 Instance Public IP',
    description: 'Ensure EC2 instances do not have public IP addresses unless required',
    severity: 'MEDIUM',
    category: 'network',
    resourceTypes: ['AWS::EC2::Instance'],
    frameworks: ['CIS', 'SOC2'],
    remediation: 'Place instances in private subnets and use NAT gateways for outbound access',
    documentation: 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-instance-addressing.html',
    evaluate: (context) => {
      const { properties } = context;

      const networkInterfaces = properties.NetworkInterfaces || [];

      for (const ni of networkInterfaces) {
        if (ni.AssociatePublicIpAddress === true) {
          return {
            passed: false,
            message: 'EC2 instance has a public IP address assigned',
          };
        }
      }

      return {
        passed: true,
        message: 'EC2 instance does not have automatic public IP assignment',
      };
    },
  },

  {
    id: 'CFN_EC2_008',
    name: 'EBS Volume Encryption',
    description: 'Ensure EBS volumes are encrypted',
    severity: 'HIGH',
    category: 'encryption',
    resourceTypes: ['AWS::EC2::Volume'],
    frameworks: ['CIS', 'SOC2', 'HIPAA', 'PCI-DSS'],
    remediation: 'Enable encryption when creating EBS volumes',
    documentation: 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html',
    evaluate: (context) => {
      const { properties } = context;

      if (properties.Encrypted !== true) {
        return {
          passed: false,
          message: 'EBS volume is not encrypted',
        };
      }

      return {
        passed: true,
        message: 'EBS volume is encrypted',
      };
    },
  },

  {
    id: 'CFN_EC2_009',
    name: 'Security Group Description',
    description: 'Ensure security groups have descriptions',
    severity: 'LOW',
    category: 'general',
    resourceTypes: ['AWS::EC2::SecurityGroup'],
    frameworks: ['SOC2'],
    remediation: 'Add a meaningful description to the security group',
    documentation: 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security-groups.html',
    evaluate: (context) => {
      const { properties } = context;

      if (!properties.GroupDescription || properties.GroupDescription.trim() === '') {
        return {
          passed: false,
          message: 'Security group does not have a description',
        };
      }

      return {
        passed: true,
        message: 'Security group has a description',
      };
    },
  },

  {
    id: 'CFN_EC2_010',
    name: 'VPC Flow Logs Enabled',
    description: 'Ensure VPC Flow Logs are enabled',
    severity: 'MEDIUM',
    category: 'logging',
    resourceTypes: ['AWS::EC2::VPC'],
    frameworks: ['CIS', 'SOC2', 'HIPAA'],
    remediation: 'Enable VPC Flow Logs for the VPC',
    documentation: 'https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html',
    evaluate: (context) => {
      const { template, resourceName } = context;

      // Check if there's a FlowLog resource referencing this VPC
      const resources = template.Resources || {};
      const hasFlowLog = Object.values(resources).some(resource => {
        if (resource.Type === 'AWS::EC2::FlowLog') {
          const resourceId = resource.Properties?.ResourceId;
          if (typeof resourceId === 'object' && resourceId.Ref === resourceName) {
            return true;
          }
        }
        return false;
      });

      if (!hasFlowLog) {
        return {
          passed: false,
          message: 'VPC does not have Flow Logs enabled',
        };
      }

      return {
        passed: true,
        message: 'VPC has Flow Logs enabled',
      };
    },
  },

  {
    id: 'CFN_EC2_011',
    name: 'Security Group Unrestricted Database Ports',
    description: 'Ensure no security group allows unrestricted access to database ports',
    severity: 'CRITICAL',
    category: 'network',
    resourceTypes: ['AWS::EC2::SecurityGroup'],
    frameworks: ['CIS', 'SOC2', 'HIPAA', 'PCI-DSS'],
    remediation: 'Restrict database port access to application security groups only',
    documentation: 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security-groups.html',
    evaluate: (context) => {
      const { properties } = context;

      const databasePorts = [
        { port: 3306, name: 'MySQL' },
        { port: 5432, name: 'PostgreSQL' },
        { port: 1433, name: 'MSSQL' },
        { port: 1521, name: 'Oracle' },
        { port: 27017, name: 'MongoDB' },
        { port: 6379, name: 'Redis' },
        { port: 11211, name: 'Memcached' },
      ];

      const ingress = properties.SecurityGroupIngress || [];

      for (const rule of ingress) {
        const fromPort = rule.FromPort;
        const toPort = rule.ToPort;
        const cidr = rule.CidrIp || '';
        const cidrv6 = rule.CidrIpv6 || '';

        for (const db of databasePorts) {
          if (fromPort <= db.port && toPort >= db.port) {
            if (cidr === '0.0.0.0/0' || cidrv6 === '::/0') {
              return {
                passed: false,
                message: `Security group allows unrestricted access to ${db.name} port (${db.port})`,
                details: { port: db.port, database: db.name, cidr: cidr || cidrv6 },
              };
            }
          }
        }
      }

      return {
        passed: true,
        message: 'Security group does not allow unrestricted database access',
      };
    },
  },

  {
    id: 'CFN_EC2_012',
    name: 'EC2 Instance IAM Profile',
    description: 'Ensure EC2 instances use IAM instance profiles instead of hardcoded credentials',
    severity: 'HIGH',
    category: 'access-control',
    resourceTypes: ['AWS::EC2::Instance'],
    frameworks: ['CIS', 'SOC2'],
    remediation: 'Attach an IAM instance profile to the EC2 instance',
    documentation: 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html',
    evaluate: (context) => {
      const { properties } = context;

      if (!properties.IamInstanceProfile) {
        return {
          passed: false,
          message: 'EC2 instance does not have an IAM instance profile attached',
        };
      }

      return {
        passed: true,
        message: 'EC2 instance has an IAM instance profile attached',
      };
    },
  },
];
