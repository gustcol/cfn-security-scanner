/**
 * RuleEngine - Evaluates security rules against CloudFormation templates
 */

class RuleEngine {
  constructor() {
    this.rules = new Map();
  }

  /**
   * Register a security rule
   */
  registerRule(rule) {
    if (!rule.id || !rule.evaluate) {
      throw new Error('Rule must have an id and evaluate function');
    }

    this.rules.set(rule.id, {
      id: rule.id,
      name: rule.name || rule.id,
      description: rule.description || '',
      severity: rule.severity || 'MEDIUM',
      category: rule.category || 'general',
      resourceTypes: rule.resourceTypes || [],
      frameworks: rule.frameworks || [],
      remediation: rule.remediation || '',
      documentation: rule.documentation || '',
      evaluate: rule.evaluate,
    });
  }

  /**
   * Get all registered rules
   */
  getRules() {
    return Array.from(this.rules.values());
  }

  /**
   * Get rule by ID
   */
  getRule(id) {
    return this.rules.get(id);
  }

  /**
   * Evaluate all rules against a template
   */
  async evaluate(template, filePath) {
    const results = [];
    const resources = template.Resources || {};

    for (const [ruleId, rule] of this.rules) {
      try {
        // Check each resource
        for (const [resourceName, resource] of Object.entries(resources)) {
          const resourceType = resource.Type;

          // Skip if rule doesn't apply to this resource type
          if (rule.resourceTypes.length > 0 && !rule.resourceTypes.includes(resourceType)) {
            continue;
          }

          const context = {
            template,
            resourceName,
            resource,
            resourceType,
            properties: resource.Properties || {},
            filePath,
          };

          const evaluation = await rule.evaluate(context);

          if (evaluation !== null) {
            results.push({
              ruleId: rule.id,
              ruleName: rule.name,
              description: rule.description,
              severity: rule.severity,
              category: rule.category,
              status: evaluation.passed ? 'PASSED' : 'FAILED',
              resourceName,
              resourceType,
              filePath,
              message: evaluation.message || (evaluation.passed ? 'Check passed' : 'Check failed'),
              remediation: rule.remediation,
              documentation: rule.documentation,
              details: evaluation.details || {},
            });
          }
        }

        // Also run template-level checks (for rules that don't target specific resources)
        if (rule.resourceTypes.length === 0 || rule.resourceTypes.includes('AWS::CloudFormation::Template')) {
          const context = {
            template,
            resourceName: null,
            resource: null,
            resourceType: 'AWS::CloudFormation::Template',
            properties: {},
            filePath,
          };

          const evaluation = await rule.evaluate(context);

          if (evaluation !== null && !results.some(r => r.ruleId === rule.id && r.resourceName === null)) {
            results.push({
              ruleId: rule.id,
              ruleName: rule.name,
              description: rule.description,
              severity: rule.severity,
              category: rule.category,
              status: evaluation.passed ? 'PASSED' : 'FAILED',
              resourceName: 'Template',
              resourceType: 'AWS::CloudFormation::Template',
              filePath,
              message: evaluation.message || (evaluation.passed ? 'Check passed' : 'Check failed'),
              remediation: rule.remediation,
              documentation: rule.documentation,
              details: evaluation.details || {},
            });
          }
        }
      } catch (error) {
        results.push({
          ruleId: rule.id,
          ruleName: rule.name,
          severity: rule.severity,
          status: 'ERROR',
          message: `Error evaluating rule: ${error.message}`,
          filePath,
        });
      }
    }

    return results;
  }
}

module.exports = RuleEngine;
