/**
 * ElastiCache Security Rules
 * Rules for Amazon ElastiCache security best practices
 */

module.exports = [
  {
    id: 'CFN_ELASTICACHE_001',
    name: 'ElastiCache Encryption at Rest',
    description: 'Ensure ElastiCache replication groups have encryption at rest enabled',
    severity: 'HIGH',
    category: 'encryption',
    resourceTypes: ['AWS::ElastiCache::ReplicationGroup'],
    frameworks: ['SOC2', 'HIPAA', 'PCI-DSS'],
    remediation: 'Set AtRestEncryptionEnabled to true',
    documentation: 'https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/at-rest-encryption.html',
    evaluate: (context) => {
      const { properties } = context;

      if (properties.AtRestEncryptionEnabled !== true) {
        return {
          passed: false,
          message: 'ElastiCache replication group does not have encryption at rest enabled',
        };
      }

      return {
        passed: true,
        message: 'ElastiCache replication group has encryption at rest enabled',
      };
    },
  },

  {
    id: 'CFN_ELASTICACHE_002',
    name: 'ElastiCache Encryption in Transit',
    description: 'Ensure ElastiCache replication groups have encryption in transit enabled',
    severity: 'HIGH',
    category: 'encryption',
    resourceTypes: ['AWS::ElastiCache::ReplicationGroup'],
    frameworks: ['SOC2', 'HIPAA', 'PCI-DSS'],
    remediation: 'Set TransitEncryptionEnabled to true',
    documentation: 'https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/in-transit-encryption.html',
    evaluate: (context) => {
      const { properties } = context;

      if (properties.TransitEncryptionEnabled !== true) {
        return {
          passed: false,
          message: 'ElastiCache replication group does not have encryption in transit enabled',
        };
      }

      return {
        passed: true,
        message: 'ElastiCache replication group has encryption in transit enabled',
      };
    },
  },

  {
    id: 'CFN_ELASTICACHE_003',
    name: 'ElastiCache Auth Token',
    description: 'Ensure ElastiCache Redis clusters have AUTH token enabled',
    severity: 'HIGH',
    category: 'access-control',
    resourceTypes: ['AWS::ElastiCache::ReplicationGroup'],
    frameworks: ['SOC2', 'HIPAA', 'PCI-DSS'],
    remediation: 'Configure AuthToken for Redis authentication',
    documentation: 'https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/auth.html',
    evaluate: (context) => {
      const { properties } = context;

      if (!properties.AuthToken) {
        return {
          passed: false,
          message: 'ElastiCache Redis cluster does not have AUTH token enabled',
        };
      }

      return {
        passed: true,
        message: 'ElastiCache Redis cluster has AUTH token enabled',
      };
    },
  },

  {
    id: 'CFN_ELASTICACHE_004',
    name: 'ElastiCache Auto Minor Version Upgrade',
    description: 'Ensure ElastiCache clusters have automatic minor version upgrades enabled',
    severity: 'LOW',
    category: 'general',
    resourceTypes: ['AWS::ElastiCache::CacheCluster', 'AWS::ElastiCache::ReplicationGroup'],
    frameworks: ['SOC2'],
    remediation: 'Set AutoMinorVersionUpgrade to true',
    documentation: 'https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/VersionManagement.html',
    evaluate: (context) => {
      const { properties } = context;

      if (properties.AutoMinorVersionUpgrade === false) {
        return {
          passed: false,
          message: 'ElastiCache cluster does not have automatic minor version upgrades enabled',
        };
      }

      return {
        passed: true,
        message: 'ElastiCache cluster has automatic minor version upgrades enabled',
      };
    },
  },

  {
    id: 'CFN_ELASTICACHE_005',
    name: 'ElastiCache Multi-AZ',
    description: 'Ensure ElastiCache replication groups have Multi-AZ enabled',
    severity: 'MEDIUM',
    category: 'availability',
    resourceTypes: ['AWS::ElastiCache::ReplicationGroup'],
    frameworks: ['SOC2'],
    remediation: 'Set MultiAZEnabled to true',
    documentation: 'https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/AutoFailover.html',
    evaluate: (context) => {
      const { properties } = context;

      if (properties.MultiAZEnabled !== true) {
        return {
          passed: false,
          message: 'ElastiCache replication group does not have Multi-AZ enabled',
        };
      }

      return {
        passed: true,
        message: 'ElastiCache replication group has Multi-AZ enabled',
      };
    },
  },

  {
    id: 'CFN_ELASTICACHE_006',
    name: 'ElastiCache Automatic Failover',
    description: 'Ensure ElastiCache replication groups have automatic failover enabled',
    severity: 'MEDIUM',
    category: 'availability',
    resourceTypes: ['AWS::ElastiCache::ReplicationGroup'],
    frameworks: ['SOC2'],
    remediation: 'Set AutomaticFailoverEnabled to true',
    documentation: 'https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/AutoFailover.html',
    evaluate: (context) => {
      const { properties } = context;

      if (properties.AutomaticFailoverEnabled !== true) {
        return {
          passed: false,
          message: 'ElastiCache replication group does not have automatic failover enabled',
        };
      }

      return {
        passed: true,
        message: 'ElastiCache replication group has automatic failover enabled',
      };
    },
  },

  {
    id: 'CFN_ELASTICACHE_007',
    name: 'ElastiCache Snapshot Retention',
    description: 'Ensure ElastiCache has snapshot retention enabled',
    severity: 'MEDIUM',
    category: 'data-protection',
    resourceTypes: ['AWS::ElastiCache::ReplicationGroup'],
    frameworks: ['SOC2'],
    remediation: 'Set SnapshotRetentionLimit to at least 7 days',
    documentation: 'https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/backups-automatic.html',
    evaluate: (context) => {
      const { properties } = context;

      const retention = properties.SnapshotRetentionLimit;
      if (!retention || retention < 7) {
        return {
          passed: false,
          message: `ElastiCache snapshot retention is ${retention || 0} days (should be at least 7)`,
        };
      }

      return {
        passed: true,
        message: `ElastiCache has ${retention} days snapshot retention`,
      };
    },
  },
];
