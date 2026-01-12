/**
 * Scanner - Core scanning engine for CloudFormation templates
 */

const fs = require('fs');
const path = require('path');
const cfnYaml = require('./utils/cfnYaml');
const RuleEngine = require('./ruleEngine');
const { loadAllRules } = require('./rules');

class Scanner {
  constructor(options = {}) {
    this.options = {
      failOnSeverity: options.failOnSeverity || 'HIGH',
      skipRules: options.skipRules || [],
      includeRules: options.includeRules || [],
      framework: options.framework || 'all',
      ...options,
    };

    this.ruleEngine = new RuleEngine();
    this.results = [];
    this.stats = {
      filesScanned: 0,
      passed: 0,
      failed: 0,
      skipped: 0,
      errors: 0,
    };
  }

  /**
   * Initialize the scanner with all security rules
   */
  async initialize() {
    const rules = loadAllRules();

    for (const rule of rules) {
      if (this.shouldIncludeRule(rule)) {
        this.ruleEngine.registerRule(rule);
      }
    }

    return this;
  }

  /**
   * Check if a rule should be included based on options
   */
  shouldIncludeRule(rule) {
    if (this.options.skipRules.includes(rule.id)) {
      return false;
    }

    if (this.options.includeRules.length > 0) {
      return this.options.includeRules.includes(rule.id);
    }

    if (this.options.framework !== 'all') {
      return rule.frameworks?.includes(this.options.framework);
    }

    return true;
  }

  /**
   * Scan a single file
   */
  async scanFile(filePath) {
    const absolutePath = path.resolve(filePath);

    if (!fs.existsSync(absolutePath)) {
      throw new Error(`File not found: ${absolutePath}`);
    }

    const content = fs.readFileSync(absolutePath, 'utf8');
    const template = this.parseTemplate(content, absolutePath);

    if (!template) {
      this.stats.errors++;
      return {
        file: absolutePath,
        error: 'Failed to parse template',
        results: [],
      };
    }

    this.stats.filesScanned++;
    const fileResults = await this.ruleEngine.evaluate(template, absolutePath);

    this.processResults(fileResults);

    return {
      file: absolutePath,
      results: fileResults,
    };
  }

  /**
   * Scan a directory recursively
   */
  async scanDirectory(dirPath, patterns = ['**/*.yaml', '**/*.yml', '**/*.json', '**/*.template']) {
    const { glob } = require('glob');
    const results = [];

    for (const pattern of patterns) {
      const files = await glob(pattern, {
        cwd: dirPath,
        absolute: true,
        nodir: true,
      });

      for (const file of files) {
        if (this.isCloudFormationTemplate(file)) {
          try {
            const result = await this.scanFile(file);
            results.push(result);
          } catch (error) {
            results.push({
              file,
              error: error.message,
              results: [],
            });
            this.stats.errors++;
          }
        }
      }
    }

    return results;
  }

  /**
   * Parse CloudFormation template (YAML or JSON)
   */
  parseTemplate(content, filePath) {
    try {
      const ext = path.extname(filePath).toLowerCase();

      if (ext === '.json' || ext === '.template') {
        try {
          return JSON.parse(content);
        } catch {
          // Try YAML if JSON fails
          return cfnYaml.parse(content);
        }
      }

      return cfnYaml.parse(content);
    } catch (error) {
      console.error(`Error parsing ${filePath}: ${error.message}`);
      return null;
    }
  }

  /**
   * Check if file is a CloudFormation template
   */
  isCloudFormationTemplate(filePath) {
    try {
      const content = fs.readFileSync(filePath, 'utf8');
      const template = this.parseTemplate(content, filePath);

      if (!template || typeof template !== 'object') {
        return false;
      }

      // Check for CloudFormation indicators
      return !!(
        template.AWSTemplateFormatVersion ||
        template.Resources ||
        template.Transform === 'AWS::Serverless-2016-10-31'
      );
    } catch {
      return false;
    }
  }

  /**
   * Process and aggregate results
   */
  processResults(results) {
    for (const result of results) {
      this.results.push(result);

      if (result.status === 'PASSED') {
        this.stats.passed++;
      } else if (result.status === 'FAILED') {
        this.stats.failed++;
      } else if (result.status === 'SKIPPED') {
        this.stats.skipped++;
      }
    }
  }

  /**
   * Get scan summary
   */
  getSummary() {
    const severityCounts = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFO: 0,
    };

    for (const result of this.results) {
      if (result.status === 'FAILED') {
        severityCounts[result.severity] = (severityCounts[result.severity] || 0) + 1;
      }
    }

    return {
      ...this.stats,
      severityCounts,
      totalChecks: this.stats.passed + this.stats.failed + this.stats.skipped,
    };
  }

  /**
   * Determine if scan should fail based on severity threshold
   */
  shouldFail() {
    const severityOrder = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
    const threshold = severityOrder.indexOf(this.options.failOnSeverity);

    for (const result of this.results) {
      if (result.status === 'FAILED') {
        const resultSeverity = severityOrder.indexOf(result.severity);
        if (resultSeverity >= threshold) {
          return true;
        }
      }
    }

    return false;
  }

  /**
   * Get all results
   */
  getResults() {
    return this.results;
  }

  /**
   * Get failed results only
   */
  getFailedResults() {
    return this.results.filter(r => r.status === 'FAILED');
  }
}

module.exports = Scanner;
