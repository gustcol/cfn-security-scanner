#!/usr/bin/env node

/**
 * CFN Security Scanner CLI
 * Command-line interface for scanning CloudFormation templates
 */

const { Command } = require('commander');
const path = require('path');
const fs = require('fs');
const Scanner = require('../src/scanner');
const { ConsoleFormatter, JsonFormatter, SarifFormatter, SummaryFormatter } = require('../src/formatters');

const program = new Command();

program
  .name('cfn-scan')
  .description('Security scanner for AWS CloudFormation templates')
  .version('1.0.0');

program
  .argument('[path]', 'File or directory to scan', '.')
  .option('-o, --output <format>', 'Output format (console, json, sarif, summary)', 'console')
  .option('-s, --severity <level>', 'Minimum severity to report (INFO, LOW, MEDIUM, HIGH, CRITICAL)', 'INFO')
  .option('-f, --fail-on <level>', 'Exit with error code if findings at this severity or higher (INFO, LOW, MEDIUM, HIGH, CRITICAL)', 'HIGH')
  .option('--skip <rules>', 'Comma-separated list of rule IDs to skip', '')
  .option('--include <rules>', 'Comma-separated list of rule IDs to include (all others excluded)', '')
  .option('--framework <framework>', 'Filter rules by compliance framework (CIS, SOC2, HIPAA, PCI-DSS)', 'all')
  .option('--list-rules', 'List all available rules and exit')
  .option('--output-file <file>', 'Write output to file instead of stdout')
  .option('-q, --quiet', 'Suppress banner and summary output')
  .option('--no-color', 'Disable colored output')
  .action(async (scanPath, options) => {
    try {
      await runScanner(scanPath, options);
    } catch (error) {
      console.error(`Error: ${error.message}`);
      process.exit(1);
    }
  });

async function runScanner(scanPath, options) {
  // Show banner unless quiet mode
  if (!options.quiet) {
    printBanner();
  }

  // List rules if requested
  if (options.listRules) {
    await listRules(options);
    return;
  }

  // Resolve path
  const absolutePath = path.resolve(scanPath);

  if (!fs.existsSync(absolutePath)) {
    throw new Error(`Path not found: ${absolutePath}`);
  }

  // Parse skip and include rules
  const skipRules = options.skip ? options.skip.split(',').map(r => r.trim()) : [];
  const includeRules = options.include ? options.include.split(',').map(r => r.trim()) : [];

  // Initialize scanner
  const scanner = new Scanner({
    failOnSeverity: options.failOn,
    skipRules,
    includeRules,
    framework: options.framework,
  });

  await scanner.initialize();

  if (!options.quiet) {
    console.log(`Scanning: ${absolutePath}\n`);
  }

  // Run scan
  const stats = fs.statSync(absolutePath);
  let fileResults = [];

  if (stats.isDirectory()) {
    fileResults = await scanner.scanDirectory(absolutePath);
  } else {
    const result = await scanner.scanFile(absolutePath);
    fileResults = [result];
  }

  // Get all results
  const allResults = scanner.getResults();

  // Filter by minimum severity
  const severityOrder = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
  const minSeverityIndex = severityOrder.indexOf(options.severity);
  const filteredResults = allResults.filter(r => {
    const resultSeverityIndex = severityOrder.indexOf(r.severity);
    return resultSeverityIndex >= minSeverityIndex;
  });

  // Format output
  const formatter = getFormatter(options.output, { color: options.color !== false });
  const output = formatter.format(filteredResults, scanner.getSummary(), fileResults);

  // Write output
  if (options.outputFile) {
    fs.writeFileSync(options.outputFile, output);
    if (!options.quiet) {
      console.log(`Output written to: ${options.outputFile}`);
    }
  } else {
    console.log(output);
  }

  // Summary
  if (!options.quiet && options.output === 'console') {
    printSummary(scanner.getSummary());
  }

  // Exit with error code if findings exceed threshold
  if (scanner.shouldFail()) {
    process.exit(1);
  }
}

function getFormatter(format, options) {
  switch (format.toLowerCase()) {
    case 'json':
      return new JsonFormatter(options);
    case 'sarif':
      return new SarifFormatter(options);
    case 'summary':
      return new SummaryFormatter(options);
    case 'console':
    default:
      return new ConsoleFormatter(options);
  }
}

function printBanner() {
  const banner = `
╔═══════════════════════════════════════════════════════════╗
║         CFN Security Scanner v1.0.0                       ║
║   CloudFormation Security Best Practices Scanner          ║
╚═══════════════════════════════════════════════════════════╝
`;
  console.log(banner);
}

function printSummary(summary) {
  console.log('\n' + '═'.repeat(60));
  console.log('SCAN SUMMARY');
  console.log('═'.repeat(60));
  console.log(`Files scanned:    ${summary.filesScanned}`);
  console.log(`Total checks:     ${summary.totalChecks}`);
  console.log(`Passed:           ${summary.passed}`);
  console.log(`Failed:           ${summary.failed}`);
  console.log(`Skipped:          ${summary.skipped}`);
  console.log(`Errors:           ${summary.errors}`);
  console.log('');
  console.log('Findings by severity:');
  console.log(`  CRITICAL: ${summary.severityCounts.CRITICAL || 0}`);
  console.log(`  HIGH:     ${summary.severityCounts.HIGH || 0}`);
  console.log(`  MEDIUM:   ${summary.severityCounts.MEDIUM || 0}`);
  console.log(`  LOW:      ${summary.severityCounts.LOW || 0}`);
  console.log(`  INFO:     ${summary.severityCounts.INFO || 0}`);
  console.log('═'.repeat(60));
}

async function listRules(options) {
  const { loadAllRules } = require('../src/rules');
  const rules = loadAllRules();

  // Filter by framework if specified
  let filteredRules = rules;
  if (options.framework && options.framework !== 'all') {
    filteredRules = rules.filter(r => r.frameworks?.includes(options.framework));
  }

  console.log(`\nAvailable Rules (${filteredRules.length} total):\n`);
  console.log('─'.repeat(100));
  console.log(
    padRight('ID', 20) +
    padRight('Severity', 12) +
    padRight('Category', 18) +
    'Name'
  );
  console.log('─'.repeat(100));

  // Group by category
  const byCategory = {};
  for (const rule of filteredRules) {
    if (!byCategory[rule.category]) {
      byCategory[rule.category] = [];
    }
    byCategory[rule.category].push(rule);
  }

  for (const [category, categoryRules] of Object.entries(byCategory).sort()) {
    for (const rule of categoryRules.sort((a, b) => a.id.localeCompare(b.id))) {
      console.log(
        padRight(rule.id, 20) +
        padRight(rule.severity, 12) +
        padRight(rule.category, 18) +
        rule.name
      );
    }
  }

  console.log('─'.repeat(100));
  console.log(`\nFrameworks: CIS, SOC2, HIPAA, PCI-DSS`);
  console.log(`Use --framework <name> to filter rules by compliance framework`);
}

function padRight(str, len) {
  return str.padEnd(len);
}

program.parse();
