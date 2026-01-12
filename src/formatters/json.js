/**
 * JSON Formatter - Machine-readable JSON output
 */

class JsonFormatter {
  constructor(options = {}) {
    this.options = {
      pretty: true,
      ...options,
    };
  }

  format(results, summary, fileResults) {
    const output = {
      version: '1.0.0',
      scanDate: new Date().toISOString(),
      summary: {
        filesScanned: summary.filesScanned,
        totalChecks: summary.totalChecks,
        passed: summary.passed,
        failed: summary.failed,
        skipped: summary.skipped,
        errors: summary.errors,
        severityCounts: summary.severityCounts,
      },
      results: results.map(r => ({
        ruleId: r.ruleId,
        ruleName: r.ruleName,
        description: r.description,
        severity: r.severity,
        category: r.category,
        status: r.status,
        resourceName: r.resourceName,
        resourceType: r.resourceType,
        filePath: r.filePath,
        message: r.message,
        remediation: r.remediation,
        documentation: r.documentation,
        details: r.details || {},
      })),
      files: fileResults.map(f => ({
        path: f.file,
        error: f.error || null,
        findingsCount: f.results?.filter(r => r.status === 'FAILED').length || 0,
      })),
    };

    if (this.options.pretty) {
      return JSON.stringify(output, null, 2);
    }

    return JSON.stringify(output);
  }
}

module.exports = JsonFormatter;
