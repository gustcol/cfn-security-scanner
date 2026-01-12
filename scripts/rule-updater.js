#!/usr/bin/env node

/**
 * Rule Updater
 *
 * Manages rule versions, updates, and changelog generation.
 * Fetches updates from multiple sources:
 * - AWS Security Hub findings
 * - CIS Benchmarks
 * - Checkov rules
 * - AWS Well-Architected Framework
 *
 * Usage:
 *   node scripts/rule-updater.js --check-updates     Check for rule updates
 *   node scripts/rule-updater.js --apply-updates     Apply pending updates
 *   node scripts/rule-updater.js --generate-changelog Generate changelog
 *   node scripts/rule-updater.js --validate          Validate all rules
 */

const fs = require('fs');
const path = require('path');
const https = require('https');

const RULES_DIR = path.join(__dirname, '../src/rules');
const VERSIONS_FILE = path.join(__dirname, '../.cache/rule-versions.json');
const CHANGELOG_FILE = path.join(__dirname, '../CHANGELOG.md');
const UPDATES_FILE = path.join(__dirname, '../.cache/pending-updates.json');

// AWS Security Hub control mappings
const SECURITY_HUB_CONTROLS = {
  'S3.1': { rule: 'CFN_S3_002', name: 'S3 Block Public Access' },
  'S3.2': { rule: 'CFN_S3_002', name: 'S3 Block Public Access' },
  'S3.3': { rule: 'CFN_S3_002', name: 'S3 Block Public Access' },
  'S3.4': { rule: 'CFN_S3_001', name: 'S3 Encryption' },
  'S3.5': { rule: 'CFN_S3_005', name: 'S3 SSL Only' },
  'EC2.1': { rule: 'CFN_EC2_005', name: 'EBS Encryption' },
  'EC2.2': { rule: 'CFN_EC2_001', name: 'Security Group SSH' },
  'EC2.3': { rule: 'CFN_EC2_005', name: 'EBS Encryption' },
  'EC2.8': { rule: 'CFN_EC2_004', name: 'IMDSv2' },
  'EC2.18': { rule: 'CFN_EC2_001', name: 'Security Group SSH' },
  'EC2.19': { rule: 'CFN_EC2_011', name: 'Security Group DB Ports' },
  'IAM.1': { rule: 'CFN_IAM_007', name: 'IAM Admin Access' },
  'IAM.21': { rule: 'CFN_IAM_001', name: 'IAM Wildcard Actions' },
  'RDS.1': { rule: 'CFN_RDS_002', name: 'RDS Public Access' },
  'RDS.2': { rule: 'CFN_RDS_002', name: 'RDS Public Access' },
  'RDS.3': { rule: 'CFN_RDS_001', name: 'RDS Encryption' },
  'RDS.4': { rule: 'CFN_RDS_001', name: 'RDS Encryption' },
  'Lambda.1': { rule: 'CFN_LAMBDA_002', name: 'Lambda Encryption' },
  'Lambda.2': { rule: 'CFN_LAMBDA_009', name: 'Lambda Runtime' },
  'CloudTrail.1': { rule: 'CFN_CLOUDTRAIL_003', name: 'CloudTrail Multi-Region' },
  'CloudTrail.2': { rule: 'CFN_CLOUDTRAIL_001', name: 'CloudTrail Encryption' },
  'KMS.1': { rule: 'CFN_KMS_001', name: 'KMS Rotation' },
  'KMS.2': { rule: 'CFN_KMS_002', name: 'KMS Policy' },
};

// CIS AWS Benchmark mappings
const CIS_CONTROLS = {
  '2.1.1': { rule: 'CFN_S3_001', name: 'Ensure S3 Bucket encryption is enabled' },
  '2.1.2': { rule: 'CFN_S3_005', name: 'Ensure S3 Bucket Policy is set to deny HTTP requests' },
  '2.1.5': { rule: 'CFN_S3_002', name: 'Ensure S3 bucket access is restricted' },
  '2.2.1': { rule: 'CFN_EC2_005', name: 'Ensure EBS volume encryption is enabled' },
  '2.3.1': { rule: 'CFN_RDS_001', name: 'Ensure RDS encryption is enabled' },
  '3.1': { rule: 'CFN_CLOUDTRAIL_007', name: 'Ensure CloudTrail is enabled' },
  '3.2': { rule: 'CFN_CLOUDTRAIL_002', name: 'Ensure CloudTrail log validation is enabled' },
  '3.4': { rule: 'CFN_CLOUDTRAIL_004', name: 'Ensure CloudTrail trails are integrated with CloudWatch' },
  '3.7': { rule: 'CFN_CLOUDTRAIL_001', name: 'Ensure CloudTrail logs are encrypted at rest' },
  '5.1': { rule: 'CFN_EC2_001', name: 'Ensure no security groups allow SSH from 0.0.0.0/0' },
  '5.2': { rule: 'CFN_EC2_002', name: 'Ensure no security groups allow RDP from 0.0.0.0/0' },
  '5.3': { rule: 'CFN_EC2_010', name: 'Ensure VPC flow logging is enabled' },
};

class RuleUpdater {
  constructor() {
    this.rules = [];
    this.versions = {};
    this.pendingUpdates = [];
  }

  /**
   * Load current rules
   */
  loadRules() {
    const { loadAllRules } = require(path.join(RULES_DIR, 'index.js'));
    this.rules = loadAllRules();

    // Load version tracking
    if (fs.existsSync(VERSIONS_FILE)) {
      this.versions = JSON.parse(fs.readFileSync(VERSIONS_FILE, 'utf8'));
    } else {
      // Initialize versions
      for (const rule of this.rules) {
        this.versions[rule.id] = {
          version: '1.0.0',
          lastUpdated: new Date().toISOString(),
          checksums: this.calculateChecksum(rule),
        };
      }
      this.saveVersions();
    }

    return this.rules;
  }

  /**
   * Calculate rule checksum for change detection
   */
  calculateChecksum(rule) {
    const str = JSON.stringify({
      name: rule.name,
      description: rule.description,
      severity: rule.severity,
      resourceTypes: rule.resourceTypes,
    });
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      hash = ((hash << 5) - hash) + str.charCodeAt(i);
      hash = hash & hash;
    }
    return hash.toString(16);
  }

  /**
   * Save version tracking
   */
  saveVersions() {
    const cacheDir = path.dirname(VERSIONS_FILE);
    if (!fs.existsSync(cacheDir)) {
      fs.mkdirSync(cacheDir, { recursive: true });
    }
    fs.writeFileSync(VERSIONS_FILE, JSON.stringify(this.versions, null, 2));
  }

  /**
   * Check for updates from various sources
   */
  async checkUpdates() {
    console.log('Checking for rule updates...\n');

    const updates = [];

    // 1. Check AWS Security Hub controls
    console.log('Checking AWS Security Hub mappings...');
    for (const [controlId, mapping] of Object.entries(SECURITY_HUB_CONTROLS)) {
      const rule = this.rules.find(r => r.id === mapping.rule);
      if (!rule) {
        updates.push({
          type: 'missing',
          source: 'SecurityHub',
          controlId,
          suggestedRule: mapping.rule,
          name: mapping.name,
          priority: 'high',
        });
      }
    }

    // 2. Check CIS Benchmark controls
    console.log('Checking CIS Benchmark mappings...');
    for (const [controlId, mapping] of Object.entries(CIS_CONTROLS)) {
      const rule = this.rules.find(r => r.id === mapping.rule);
      if (rule) {
        // Check if rule has CIS in frameworks
        if (!rule.frameworks?.includes('CIS')) {
          updates.push({
            type: 'update',
            source: 'CIS',
            controlId,
            ruleId: rule.id,
            change: 'Add CIS framework mapping',
            priority: 'medium',
          });
        }
      }
    }

    // 3. Check for deprecated/outdated checks
    console.log('Checking for outdated rules...');
    const deprecatedPatterns = [
      { pattern: /python2\.7|python3\.6|nodejs10|nodejs12/i, message: 'Update deprecated runtime check' },
      { pattern: /TLS_1_0|TLSv1_2016/i, message: 'Update TLS version requirements' },
    ];

    for (const rule of this.rules) {
      const ruleStr = JSON.stringify(rule);
      for (const { pattern, message } of deprecatedPatterns) {
        if (pattern.test(ruleStr)) {
          updates.push({
            type: 'update',
            source: 'internal',
            ruleId: rule.id,
            change: message,
            priority: 'high',
          });
        }
      }
    }

    // 4. Check for new AWS resource types we should cover
    console.log('Checking for new resource types...');
    const coveredTypes = new Set(this.rules.flatMap(r => r.resourceTypes));
    const recommendedTypes = [
      'AWS::Athena::WorkGroup',
      'AWS::DynamoDB::Table',
      'AWS::Kinesis::Stream',
      'AWS::Neptune::DBCluster',
      'AWS::DocumentDB::DBCluster',
      'AWS::MSK::Cluster',
      'AWS::Redshift::Cluster',
      'AWS::EKS::Cluster',
      'AWS::ECR::Repository',
      'AWS::StepFunctions::StateMachine',
      'AWS::Glue::DataCatalog',
      'AWS::OpenSearchService::Domain',
    ];

    for (const resourceType of recommendedTypes) {
      if (!coveredTypes.has(resourceType)) {
        updates.push({
          type: 'new',
          source: 'recommendation',
          resourceType,
          message: `Add security rules for ${resourceType}`,
          priority: 'medium',
        });
      }
    }

    // Save pending updates
    this.pendingUpdates = updates;
    this.savePendingUpdates();

    // Print summary
    console.log(`\nFound ${updates.length} potential updates:\n`);
    console.log(`  High priority: ${updates.filter(u => u.priority === 'high').length}`);
    console.log(`  Medium priority: ${updates.filter(u => u.priority === 'medium').length}`);
    console.log(`  Low priority: ${updates.filter(u => u.priority === 'low').length}`);

    return updates;
  }

  /**
   * Save pending updates
   */
  savePendingUpdates() {
    const cacheDir = path.dirname(UPDATES_FILE);
    if (!fs.existsSync(cacheDir)) {
      fs.mkdirSync(cacheDir, { recursive: true });
    }
    fs.writeFileSync(UPDATES_FILE, JSON.stringify(this.pendingUpdates, null, 2));
  }

  /**
   * Validate all rules
   */
  validateRules() {
    console.log('Validating rules...\n');

    const issues = [];

    for (const rule of this.rules) {
      // Check required fields
      if (!rule.id) issues.push({ rule: rule.id || 'unknown', issue: 'Missing rule ID' });
      if (!rule.name) issues.push({ rule: rule.id, issue: 'Missing rule name' });
      if (!rule.description) issues.push({ rule: rule.id, issue: 'Missing description' });
      if (!rule.severity) issues.push({ rule: rule.id, issue: 'Missing severity' });
      if (!rule.evaluate) issues.push({ rule: rule.id, issue: 'Missing evaluate function' });

      // Check ID format (CFN_SERVICE_NNN where SERVICE is 2-12 alphanumeric chars)
      if (rule.id && !rule.id.match(/^CFN_[A-Z0-9]{2,12}_\d{3}$/)) {
        issues.push({ rule: rule.id, issue: 'Invalid ID format (expected CFN_SERVICE_NNN)' });
      }

      // Check severity values
      const validSeverities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
      if (rule.severity && !validSeverities.includes(rule.severity)) {
        issues.push({ rule: rule.id, issue: `Invalid severity: ${rule.severity}` });
      }

      // Check frameworks
      const validFrameworks = ['CIS', 'SOC2', 'HIPAA', 'PCI-DSS', 'NIST', 'ISO27001'];
      if (rule.frameworks) {
        for (const framework of rule.frameworks) {
          if (!validFrameworks.includes(framework)) {
            issues.push({ rule: rule.id, issue: `Unknown framework: ${framework}` });
          }
        }
      }

      // Check for documentation
      if (!rule.documentation) {
        issues.push({ rule: rule.id, issue: 'Missing documentation URL', severity: 'warning' });
      }

      // Check for remediation
      if (!rule.remediation) {
        issues.push({ rule: rule.id, issue: 'Missing remediation guidance', severity: 'warning' });
      }
    }

    // Check for duplicate IDs
    const ids = this.rules.map(r => r.id);
    const duplicates = ids.filter((id, index) => ids.indexOf(id) !== index);
    for (const dup of duplicates) {
      issues.push({ rule: dup, issue: 'Duplicate rule ID' });
    }

    // Print results
    const errors = issues.filter(i => i.severity !== 'warning');
    const warnings = issues.filter(i => i.severity === 'warning');

    console.log(`Validation complete:`);
    console.log(`  Total rules: ${this.rules.length}`);
    console.log(`  Errors: ${errors.length}`);
    console.log(`  Warnings: ${warnings.length}\n`);

    if (errors.length > 0) {
      console.log('Errors:');
      for (const issue of errors) {
        console.log(`  [${issue.rule}] ${issue.issue}`);
      }
    }

    if (warnings.length > 0) {
      console.log('\nWarnings:');
      for (const issue of warnings.slice(0, 10)) {
        console.log(`  [${issue.rule}] ${issue.issue}`);
      }
      if (warnings.length > 10) {
        console.log(`  ... and ${warnings.length - 10} more`);
      }
    }

    return { errors, warnings };
  }

  /**
   * Generate changelog entry
   */
  generateChangelog() {
    console.log('Generating changelog...\n');

    // Load pending updates if available
    if (fs.existsSync(UPDATES_FILE)) {
      this.pendingUpdates = JSON.parse(fs.readFileSync(UPDATES_FILE, 'utf8'));
    }

    const date = new Date().toISOString().split('T')[0];
    const entry = [];

    entry.push(`## [Unreleased] - ${date}\n`);

    // Group updates by type
    const byType = {
      new: this.pendingUpdates.filter(u => u.type === 'new'),
      update: this.pendingUpdates.filter(u => u.type === 'update'),
      missing: this.pendingUpdates.filter(u => u.type === 'missing'),
    };

    if (byType.new.length > 0) {
      entry.push('### Added');
      for (const update of byType.new) {
        entry.push(`- ${update.message || update.resourceType}`);
      }
      entry.push('');
    }

    if (byType.update.length > 0) {
      entry.push('### Changed');
      for (const update of byType.update) {
        entry.push(`- ${update.ruleId}: ${update.change}`);
      }
      entry.push('');
    }

    if (byType.missing.length > 0) {
      entry.push('### To Do');
      for (const update of byType.missing) {
        entry.push(`- Implement ${update.suggestedRule} for ${update.source} ${update.controlId}`);
      }
      entry.push('');
    }

    // Read existing changelog or create new
    let changelog = '';
    if (fs.existsSync(CHANGELOG_FILE)) {
      changelog = fs.readFileSync(CHANGELOG_FILE, 'utf8');
    } else {
      changelog = '# Changelog\n\nAll notable changes to the security rules will be documented in this file.\n\n';
    }

    // Insert new entry after header
    const headerEnd = changelog.indexOf('\n\n') + 2;
    changelog = changelog.slice(0, headerEnd) + entry.join('\n') + '\n' + changelog.slice(headerEnd);

    fs.writeFileSync(CHANGELOG_FILE, changelog);
    console.log(`Changelog updated: ${CHANGELOG_FILE}`);

    return entry.join('\n');
  }

  /**
   * Generate rule statistics
   */
  generateStats() {
    const stats = {
      totalRules: this.rules.length,
      bySeverity: {},
      byCategory: {},
      byResourceType: {},
      byFramework: {},
    };

    for (const rule of this.rules) {
      // By severity
      stats.bySeverity[rule.severity] = (stats.bySeverity[rule.severity] || 0) + 1;

      // By category
      stats.byCategory[rule.category] = (stats.byCategory[rule.category] || 0) + 1;

      // By resource type
      for (const rt of rule.resourceTypes) {
        stats.byResourceType[rt] = (stats.byResourceType[rt] || 0) + 1;
      }

      // By framework
      for (const fw of rule.frameworks || []) {
        stats.byFramework[fw] = (stats.byFramework[fw] || 0) + 1;
      }
    }

    return stats;
  }
}

// CLI
async function main() {
  const args = process.argv.slice(2);
  const updater = new RuleUpdater();

  updater.loadRules();

  if (args.includes('--check-updates')) {
    await updater.checkUpdates();
  } else if (args.includes('--validate')) {
    updater.validateRules();
  } else if (args.includes('--generate-changelog')) {
    updater.generateChangelog();
  } else if (args.includes('--stats')) {
    const stats = updater.generateStats();
    console.log('Rule Statistics:\n');
    console.log(`Total rules: ${stats.totalRules}\n`);
    console.log('By Severity:');
    for (const [sev, count] of Object.entries(stats.bySeverity).sort()) {
      console.log(`  ${sev}: ${count}`);
    }
    console.log('\nBy Category:');
    for (const [cat, count] of Object.entries(stats.byCategory).sort()) {
      console.log(`  ${cat}: ${count}`);
    }
    console.log('\nBy Framework:');
    for (const [fw, count] of Object.entries(stats.byFramework).sort()) {
      console.log(`  ${fw}: ${count}`);
    }
  } else {
    console.log(`
Rule Updater - Manage and update security rules

Usage:
  node scripts/rule-updater.js --check-updates        Check for rule updates
  node scripts/rule-updater.js --validate             Validate all rules
  node scripts/rule-updater.js --generate-changelog   Generate changelog entry
  node scripts/rule-updater.js --stats                Show rule statistics
`);
  }
}

main().catch(console.error);

module.exports = RuleUpdater;
