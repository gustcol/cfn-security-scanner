#!/usr/bin/env node

/**
 * Checkov Rule Mapper
 *
 * This script fetches Checkov CloudFormation rules and maps them to our rule format.
 * It helps identify:
 * - Rules we're missing that Checkov has
 * - Rules that need updating based on Checkov changes
 * - New AWS resources/checks to implement
 *
 * Usage:
 *   node scripts/checkov-mapper.js --fetch      # Fetch latest Checkov rules
 *   node scripts/checkov-mapper.js --compare    # Compare with our rules
 *   node scripts/checkov-mapper.js --report     # Generate gap analysis report
 */

const https = require('https');
const fs = require('fs');
const path = require('path');

const CHECKOV_REPO = 'bridgecrewio/checkov';
const CHECKOV_CFN_PATH = 'checkov/cloudformation/checks/resource';
const CACHE_DIR = path.join(__dirname, '../.cache');
const CACHE_FILE = path.join(CACHE_DIR, 'checkov-rules.json');

// Our rule categories mapped to Checkov categories
const CATEGORY_MAP = {
  'encryption': ['Encryption', 'Logging'],
  'access-control': ['IAM', 'Networking'],
  'network': ['Networking'],
  'logging': ['Logging'],
  'data-protection': ['Backup', 'General'],
  'monitoring': ['Logging'],
  'availability': ['General'],
  'general': ['General'],
};

// Resource type mapping
const RESOURCE_MAP = {
  'AWS::S3::Bucket': 'S3',
  'AWS::EC2::SecurityGroup': 'EC2',
  'AWS::EC2::Instance': 'EC2',
  'AWS::RDS::DBInstance': 'RDS',
  'AWS::IAM::Role': 'IAM',
  'AWS::IAM::Policy': 'IAM',
  'AWS::Lambda::Function': 'Lambda',
  'AWS::ECS::TaskDefinition': 'ECS',
  'AWS::ElastiCache::ReplicationGroup': 'ElastiCache',
  'AWS::CloudTrail::Trail': 'CloudTrail',
  'AWS::KMS::Key': 'KMS',
  'AWS::SNS::Topic': 'SNS',
  'AWS::SQS::Queue': 'SQS',
  'AWS::ApiGateway::Stage': 'APIGateway',
  'AWS::CloudFront::Distribution': 'CloudFront',
  'AWS::ElasticLoadBalancingV2::LoadBalancer': 'ELB',
  'AWS::SecretsManager::Secret': 'SecretsManager',
};

class CheckovMapper {
  constructor() {
    this.checkovRules = [];
    this.ourRules = [];
  }

  /**
   * Fetch Checkov rules from GitHub API
   */
  async fetchCheckovRules() {
    console.log('Fetching Checkov CloudFormation rules from GitHub...\n');

    // Ensure cache directory exists
    if (!fs.existsSync(CACHE_DIR)) {
      fs.mkdirSync(CACHE_DIR, { recursive: true });
    }

    try {
      // Fetch directory listing from GitHub API
      const contents = await this.githubApiRequest(
        `/repos/${CHECKOV_REPO}/contents/${CHECKOV_CFN_PATH}`
      );

      const rules = [];

      for (const item of contents) {
        if (item.type === 'file' && item.name.endsWith('.py') && !item.name.startsWith('__')) {
          // Fetch individual file content
          const fileContent = await this.githubApiRequest(item.url.replace('https://api.github.com', ''));
          const content = Buffer.from(fileContent.content, 'base64').toString('utf8');

          // Parse the Python file to extract rule info
          const ruleInfo = this.parseCheckovRule(content, item.name);
          if (ruleInfo) {
            rules.push(ruleInfo);
          }
        }
      }

      // Cache the results
      fs.writeFileSync(CACHE_FILE, JSON.stringify(rules, null, 2));
      console.log(`Fetched and cached ${rules.length} Checkov rules.\n`);

      this.checkovRules = rules;
      return rules;

    } catch (error) {
      console.error('Error fetching Checkov rules:', error.message);

      // Try to load from cache
      if (fs.existsSync(CACHE_FILE)) {
        console.log('Loading rules from cache...');
        this.checkovRules = JSON.parse(fs.readFileSync(CACHE_FILE, 'utf8'));
        return this.checkovRules;
      }

      throw error;
    }
  }

  /**
   * Make GitHub API request
   */
  githubApiRequest(path) {
    return new Promise((resolve, reject) => {
      const options = {
        hostname: 'api.github.com',
        path: path,
        headers: {
          'User-Agent': 'cfn-security-scanner',
          'Accept': 'application/vnd.github.v3+json',
        },
      };

      // Add auth token if available
      if (process.env.GITHUB_TOKEN) {
        options.headers['Authorization'] = `token ${process.env.GITHUB_TOKEN}`;
      }

      https.get(options, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          if (res.statusCode === 200) {
            resolve(JSON.parse(data));
          } else {
            reject(new Error(`GitHub API error: ${res.statusCode} - ${data}`));
          }
        });
      }).on('error', reject);
    });
  }

  /**
   * Parse Checkov Python rule file to extract metadata
   */
  parseCheckovRule(content, filename) {
    try {
      const rule = {
        id: null,
        name: null,
        category: null,
        resourceTypes: [],
        severity: 'MEDIUM',
        source: 'checkov',
        filename: filename,
      };

      // Extract check ID (e.g., CKV_AWS_1)
      const idMatch = content.match(/id\s*=\s*["']([^"']+)["']/);
      if (idMatch) {
        rule.id = idMatch[1];
      }

      // Extract check name
      const nameMatch = content.match(/name\s*=\s*["']([^"']+)["']/);
      if (nameMatch) {
        rule.name = nameMatch[1];
      }

      // Extract supported resources
      const resourceMatch = content.match(/supported_resources\s*=\s*\[([^\]]+)\]/);
      if (resourceMatch) {
        const resources = resourceMatch[1].match(/["']([^"']+)["']/g);
        if (resources) {
          rule.resourceTypes = resources.map(r => r.replace(/["']/g, ''));
        }
      }

      // Extract category from class inheritance or guideline
      const categoryMatch = content.match(/category\s*=\s*["']([^"']+)["']/);
      if (categoryMatch) {
        rule.category = categoryMatch[1];
      }

      // Extract guideline/documentation
      const guidelineMatch = content.match(/guideline\s*=\s*["']([^"']+)["']/);
      if (guidelineMatch) {
        rule.documentation = guidelineMatch[1];
      }

      // Only return if we have at least ID and name
      if (rule.id && rule.name) {
        return rule;
      }

      return null;
    } catch (error) {
      console.error(`Error parsing ${filename}:`, error.message);
      return null;
    }
  }

  /**
   * Load our rules
   */
  loadOurRules() {
    const rulesDir = path.join(__dirname, '../src/rules');
    const { loadAllRules } = require(path.join(rulesDir, 'index.js'));
    this.ourRules = loadAllRules();
    return this.ourRules;
  }

  /**
   * Compare our rules with Checkov rules
   */
  compareRules() {
    console.log('Comparing rules...\n');

    const comparison = {
      matchedRules: [],
      missingFromUs: [],
      uniqueToUs: [],
      resourceCoverage: {},
    };

    // Build lookup maps
    const ourRulesByName = new Map();
    const ourRulesByResource = new Map();

    for (const rule of this.ourRules) {
      ourRulesByName.set(rule.name.toLowerCase(), rule);
      for (const resourceType of rule.resourceTypes) {
        if (!ourRulesByResource.has(resourceType)) {
          ourRulesByResource.set(resourceType, []);
        }
        ourRulesByResource.get(resourceType).push(rule);
      }
    }

    // Compare each Checkov rule
    for (const checkovRule of this.checkovRules) {
      const nameKey = checkovRule.name.toLowerCase();

      // Try to find matching rule by name similarity
      let matched = false;
      for (const [ourName, ourRule] of ourRulesByName) {
        if (this.isSimilarRule(checkovRule, ourRule)) {
          comparison.matchedRules.push({
            checkov: checkovRule,
            ours: ourRule,
            similarity: this.calculateSimilarity(checkovRule.name, ourRule.name),
          });
          matched = true;
          break;
        }
      }

      if (!matched) {
        comparison.missingFromUs.push(checkovRule);
      }

      // Track resource coverage
      for (const resourceType of checkovRule.resourceTypes) {
        if (!comparison.resourceCoverage[resourceType]) {
          comparison.resourceCoverage[resourceType] = {
            checkovCount: 0,
            ourCount: 0,
            checkovRules: [],
            ourRules: [],
          };
        }
        comparison.resourceCoverage[resourceType].checkovCount++;
        comparison.resourceCoverage[resourceType].checkovRules.push(checkovRule.id);
      }
    }

    // Add our rules to resource coverage
    for (const rule of this.ourRules) {
      for (const resourceType of rule.resourceTypes) {
        if (!comparison.resourceCoverage[resourceType]) {
          comparison.resourceCoverage[resourceType] = {
            checkovCount: 0,
            ourCount: 0,
            checkovRules: [],
            ourRules: [],
          };
        }
        comparison.resourceCoverage[resourceType].ourCount++;
        comparison.resourceCoverage[resourceType].ourRules.push(rule.id);
      }
    }

    return comparison;
  }

  /**
   * Check if two rules are similar
   */
  isSimilarRule(checkovRule, ourRule) {
    // Check resource type overlap
    const resourceOverlap = checkovRule.resourceTypes.some(r => ourRule.resourceTypes.includes(r));
    if (!resourceOverlap && checkovRule.resourceTypes.length > 0) {
      return false;
    }

    // Check name similarity
    const similarity = this.calculateSimilarity(
      checkovRule.name.toLowerCase(),
      ourRule.name.toLowerCase()
    );

    return similarity > 0.6;
  }

  /**
   * Calculate string similarity (Jaccard index on words)
   */
  calculateSimilarity(str1, str2) {
    const words1 = new Set(str1.split(/\s+/));
    const words2 = new Set(str2.split(/\s+/));

    const intersection = new Set([...words1].filter(x => words2.has(x)));
    const union = new Set([...words1, ...words2]);

    return intersection.size / union.size;
  }

  /**
   * Generate gap analysis report
   */
  generateReport(comparison) {
    const report = [];

    report.push('# CFN Security Scanner - Rule Gap Analysis Report');
    report.push(`Generated: ${new Date().toISOString()}\n`);

    // Summary
    report.push('## Summary\n');
    report.push(`| Metric | Count |`);
    report.push(`|--------|-------|`);
    report.push(`| Our Rules | ${this.ourRules.length} |`);
    report.push(`| Checkov CFN Rules | ${this.checkovRules.length} |`);
    report.push(`| Matched Rules | ${comparison.matchedRules.length} |`);
    report.push(`| Missing from Us | ${comparison.missingFromUs.length} |`);
    report.push('');

    // Missing rules (priority to implement)
    report.push('## Missing Rules (Priority Implementation)\n');
    report.push('These are Checkov rules we should consider implementing:\n');

    const priorityMissing = comparison.missingFromUs
      .filter(r => r.resourceTypes.some(rt => Object.keys(RESOURCE_MAP).includes(rt)))
      .slice(0, 30);

    report.push('| Checkov ID | Name | Resource Types |');
    report.push('|------------|------|----------------|');
    for (const rule of priorityMissing) {
      report.push(`| ${rule.id} | ${rule.name} | ${rule.resourceTypes.join(', ')} |`);
    }
    report.push('');

    // Resource coverage comparison
    report.push('## Resource Coverage Comparison\n');
    report.push('| Resource Type | Checkov Rules | Our Rules | Gap |');
    report.push('|---------------|---------------|-----------|-----|');

    const sortedResources = Object.entries(comparison.resourceCoverage)
      .sort((a, b) => (b[1].checkovCount - b[1].ourCount) - (a[1].checkovCount - a[1].ourCount));

    for (const [resourceType, coverage] of sortedResources.slice(0, 20)) {
      const gap = coverage.checkovCount - coverage.ourCount;
      const gapStr = gap > 0 ? `+${gap}` : gap.toString();
      report.push(`| ${resourceType} | ${coverage.checkovCount} | ${coverage.ourCount} | ${gapStr} |`);
    }
    report.push('');

    // Matched rules (for reference)
    report.push('## Matched Rules\n');
    report.push('Rules we have that correspond to Checkov rules:\n');
    report.push('| Our ID | Our Name | Checkov ID | Similarity |');
    report.push('|--------|----------|------------|------------|');

    for (const match of comparison.matchedRules.slice(0, 20)) {
      const sim = (match.similarity * 100).toFixed(0) + '%';
      report.push(`| ${match.ours.id} | ${match.ours.name} | ${match.checkov.id} | ${sim} |`);
    }
    report.push('');

    // Recommendations
    report.push('## Recommendations\n');
    report.push('### High Priority');
    report.push('1. Implement missing CRITICAL severity rules from Checkov');
    report.push('2. Add rules for new AWS resource types');
    report.push('3. Update existing rules based on Checkov improvements\n');

    report.push('### Medium Priority');
    report.push('1. Improve rule matching with Checkov IDs');
    report.push('2. Add compliance framework mappings from Checkov');
    report.push('3. Implement automated rule synchronization\n');

    return report.join('\n');
  }
}

// CLI
async function main() {
  const args = process.argv.slice(2);
  const mapper = new CheckovMapper();

  if (args.includes('--fetch')) {
    await mapper.fetchCheckovRules();
    console.log('Rules fetched and cached successfully.');
  } else if (args.includes('--compare')) {
    // Load cached Checkov rules or fetch
    if (fs.existsSync(CACHE_FILE)) {
      mapper.checkovRules = JSON.parse(fs.readFileSync(CACHE_FILE, 'utf8'));
    } else {
      await mapper.fetchCheckovRules();
    }

    mapper.loadOurRules();
    const comparison = mapper.compareRules();

    console.log('Comparison Results:');
    console.log(`  Matched rules: ${comparison.matchedRules.length}`);
    console.log(`  Missing from us: ${comparison.missingFromUs.length}`);
    console.log(`  Resource types covered: ${Object.keys(comparison.resourceCoverage).length}`);
  } else if (args.includes('--report')) {
    // Load cached Checkov rules or fetch
    if (fs.existsSync(CACHE_FILE)) {
      mapper.checkovRules = JSON.parse(fs.readFileSync(CACHE_FILE, 'utf8'));
    } else {
      await mapper.fetchCheckovRules();
    }

    mapper.loadOurRules();
    const comparison = mapper.compareRules();
    const report = mapper.generateReport(comparison);

    const reportPath = path.join(__dirname, '../docs/GAP_ANALYSIS.md');
    fs.writeFileSync(reportPath, report);
    console.log(`Report generated: ${reportPath}`);
  } else {
    console.log(`
Checkov Rule Mapper - Compare and sync rules with Checkov

Usage:
  node scripts/checkov-mapper.js --fetch      Fetch latest Checkov rules from GitHub
  node scripts/checkov-mapper.js --compare    Compare rules and show summary
  node scripts/checkov-mapper.js --report     Generate detailed gap analysis report

Environment:
  GITHUB_TOKEN    Optional GitHub token for higher API rate limits
`);
  }
}

main().catch(console.error);

module.exports = CheckovMapper;
