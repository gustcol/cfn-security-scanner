/**
 * Console Formatter - Human-readable console output
 */

const chalk = require('chalk');

class ConsoleFormatter {
  constructor(options = {}) {
    this.options = {
      color: true,
      ...options,
    };

    // Disable chalk if color is disabled
    if (!this.options.color) {
      chalk.level = 0;
    }
  }

  format(results, summary, fileResults) {
    const lines = [];
    const failedResults = results.filter(r => r.status === 'FAILED');

    if (failedResults.length === 0) {
      lines.push(chalk.green('✓ No security issues found!\n'));
      return lines.join('\n');
    }

    // Group by file
    const byFile = {};
    for (const result of failedResults) {
      const file = result.filePath || 'Unknown';
      if (!byFile[file]) {
        byFile[file] = [];
      }
      byFile[file].push(result);
    }

    for (const [file, fileFindings] of Object.entries(byFile)) {
      lines.push(chalk.bold.underline(`\n${file}`));
      lines.push('');

      // Sort by severity
      const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
      fileFindings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

      for (const finding of fileFindings) {
        const severityColor = this.getSeverityColor(finding.severity);
        const severityBadge = chalk[severityColor](`[${finding.severity}]`);
        const status = chalk.red('✗ FAILED');

        lines.push(`  ${status} ${severityBadge} ${chalk.cyan(finding.ruleId)}`);
        lines.push(`     ${chalk.bold(finding.ruleName)}`);
        lines.push(`     Resource: ${finding.resourceName} (${finding.resourceType})`);
        lines.push(`     ${finding.message}`);

        if (finding.remediation) {
          lines.push(chalk.yellow(`     Remediation: ${finding.remediation}`));
        }

        if (finding.documentation) {
          lines.push(chalk.dim(`     Docs: ${finding.documentation}`));
        }

        lines.push('');
      }
    }

    return lines.join('\n');
  }

  getSeverityColor(severity) {
    switch (severity) {
      case 'CRITICAL':
        return 'magenta';
      case 'HIGH':
        return 'red';
      case 'MEDIUM':
        return 'yellow';
      case 'LOW':
        return 'blue';
      case 'INFO':
        return 'gray';
      default:
        return 'white';
    }
  }
}

module.exports = ConsoleFormatter;
