/**
 * SARIF Formatter - Static Analysis Results Interchange Format
 * Standard format for IDE integration and security tools
 */

class SarifFormatter {
  constructor(options = {}) {
    this.options = options;
  }

  format(results, summary, fileResults) {
    const sarif = {
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: 'cfn-security-scanner',
              version: '1.0.0',
              informationUri: 'https://github.com/example/cfn-security-scanner',
              rules: this.getRules(results),
            },
          },
          results: this.getResults(results),
          invocations: [
            {
              executionSuccessful: true,
              endTimeUtc: new Date().toISOString(),
            },
          ],
        },
      ],
    };

    return JSON.stringify(sarif, null, 2);
  }

  getRules(results) {
    const rulesMap = new Map();

    for (const result of results) {
      if (!rulesMap.has(result.ruleId)) {
        rulesMap.set(result.ruleId, {
          id: result.ruleId,
          name: result.ruleName,
          shortDescription: {
            text: result.ruleName,
          },
          fullDescription: {
            text: result.description || result.ruleName,
          },
          helpUri: result.documentation || '',
          help: {
            text: result.remediation || 'No remediation guidance available',
            markdown: result.remediation
              ? `**Remediation:** ${result.remediation}`
              : 'No remediation guidance available',
          },
          defaultConfiguration: {
            level: this.severityToLevel(result.severity),
          },
          properties: {
            category: result.category,
            severity: result.severity,
            tags: [result.category, result.severity.toLowerCase()],
          },
        });
      }
    }

    return Array.from(rulesMap.values());
  }

  getResults(results) {
    return results
      .filter(r => r.status === 'FAILED')
      .map((result, index) => ({
        ruleId: result.ruleId,
        ruleIndex: this.getRuleIndex(results, result.ruleId),
        level: this.severityToLevel(result.severity),
        message: {
          text: result.message,
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: {
                uri: result.filePath,
                uriBaseId: '%SRCROOT%',
              },
            },
            logicalLocations: [
              {
                name: result.resourceName,
                kind: 'resource',
                fullyQualifiedName: `${result.resourceType}/${result.resourceName}`,
              },
            ],
          },
        ],
        fingerprints: {
          primaryLocationLineHash: this.generateFingerprint(result),
        },
        properties: {
          resourceName: result.resourceName,
          resourceType: result.resourceType,
          category: result.category,
          remediation: result.remediation,
        },
      }));
  }

  getRuleIndex(results, ruleId) {
    const uniqueRules = [...new Set(results.map(r => r.ruleId))];
    return uniqueRules.indexOf(ruleId);
  }

  severityToLevel(severity) {
    switch (severity) {
      case 'CRITICAL':
      case 'HIGH':
        return 'error';
      case 'MEDIUM':
        return 'warning';
      case 'LOW':
      case 'INFO':
        return 'note';
      default:
        return 'none';
    }
  }

  generateFingerprint(result) {
    const data = `${result.ruleId}:${result.resourceName}:${result.filePath}`;
    let hash = 0;
    for (let i = 0; i < data.length; i++) {
      const char = data.charCodeAt(i);
      hash = (hash << 5) - hash + char;
      hash = hash & hash;
    }
    return Math.abs(hash).toString(16);
  }
}

module.exports = SarifFormatter;
