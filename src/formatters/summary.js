/**
 * Summary Formatter - Compact summary view of scan results
 */

const chalk = require('chalk');

class SummaryFormatter {
  constructor(options = {}) {
    this.options = {
      color: true,
      ...options,
    };

    if (!this.options.color) {
      chalk.level = 0;
    }
  }

  format(results, summary, fileResults) {
    const lines = [];
    const failedResults = results.filter(r => r.status === 'FAILED');

    // Header
    lines.push(chalk.bold('\n📊 SCAN RESULTS SUMMARY\n'));
    lines.push('═'.repeat(60));

    // Stats
    lines.push('');
    lines.push(chalk.bold('📁 Files'));
    lines.push(`   Scanned: ${summary.filesScanned}`);
    lines.push(`   Errors:  ${summary.errors}`);
    lines.push('');

    lines.push(chalk.bold('🔍 Checks'));
    lines.push(`   Total:   ${summary.totalChecks}`);
    lines.push(`   ${chalk.green('Passed:')}  ${summary.passed}`);
    lines.push(`   ${chalk.red('Failed:')}  ${summary.failed}`);
    lines.push(`   ${chalk.gray('Skipped:')} ${summary.skipped}`);
    lines.push('');

    // Severity breakdown
    lines.push(chalk.bold('⚠️  Findings by Severity'));
    lines.push(`   ${chalk.magenta('CRITICAL:')} ${summary.severityCounts.CRITICAL || 0}`);
    lines.push(`   ${chalk.red('HIGH:')}     ${summary.severityCounts.HIGH || 0}`);
    lines.push(`   ${chalk.yellow('MEDIUM:')}   ${summary.severityCounts.MEDIUM || 0}`);
    lines.push(`   ${chalk.blue('LOW:')}      ${summary.severityCounts.LOW || 0}`);
    lines.push(`   ${chalk.gray('INFO:')}     ${summary.severityCounts.INFO || 0}`);
    lines.push('');

    // Top issues by rule
    if (failedResults.length > 0) {
      lines.push(chalk.bold('🔝 Top Issues by Rule'));

      const ruleCount = {};
      for (const result of failedResults) {
        if (!ruleCount[result.ruleId]) {
          ruleCount[result.ruleId] = { count: 0, name: result.ruleName, severity: result.severity };
        }
        ruleCount[result.ruleId].count++;
      }

      const sortedRules = Object.entries(ruleCount)
        .sort((a, b) => b[1].count - a[1].count)
        .slice(0, 10);

      for (const [ruleId, info] of sortedRules) {
        const severityColor = this.getSeverityColor(info.severity);
        lines.push(`   ${chalk[severityColor](`[${info.severity}]`)} ${ruleId}: ${info.name} (${info.count})`);
      }
      lines.push('');
    }

    // Files with most issues
    if (fileResults.length > 0) {
      const filesWithIssues = fileResults
        .map(f => ({
          path: f.file,
          count: f.results?.filter(r => r.status === 'FAILED').length || 0,
        }))
        .filter(f => f.count > 0)
        .sort((a, b) => b.count - a.count)
        .slice(0, 5);

      if (filesWithIssues.length > 0) {
        lines.push(chalk.bold('📄 Files with Most Issues'));
        for (const file of filesWithIssues) {
          const shortPath = file.path.length > 50
            ? '...' + file.path.slice(-47)
            : file.path;
          lines.push(`   ${shortPath}: ${chalk.red(file.count + ' issues')}`);
        }
        lines.push('');
      }
    }

    // Category breakdown
    if (failedResults.length > 0) {
      lines.push(chalk.bold('📂 Issues by Category'));

      const categoryCount = {};
      for (const result of failedResults) {
        categoryCount[result.category] = (categoryCount[result.category] || 0) + 1;
      }

      const sortedCategories = Object.entries(categoryCount)
        .sort((a, b) => b[1] - a[1]);

      for (const [category, count] of sortedCategories) {
        const bar = '█'.repeat(Math.min(20, Math.round(count / failedResults.length * 20)));
        lines.push(`   ${category.padEnd(18)} ${bar} ${count}`);
      }
      lines.push('');
    }

    lines.push('═'.repeat(60));

    // Final status
    if (summary.failed === 0) {
      lines.push(chalk.green.bold('\n✅ ALL CHECKS PASSED\n'));
    } else {
      const criticalOrHigh = (summary.severityCounts.CRITICAL || 0) + (summary.severityCounts.HIGH || 0);
      if (criticalOrHigh > 0) {
        lines.push(chalk.red.bold(`\n❌ ${criticalOrHigh} CRITICAL/HIGH SEVERITY ISSUES FOUND\n`));
      } else {
        lines.push(chalk.yellow.bold(`\n⚠️  ${summary.failed} ISSUES FOUND (no critical/high severity)\n`));
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

module.exports = SummaryFormatter;
