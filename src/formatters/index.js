/**
 * Formatters Index - Export all output formatters
 */

const ConsoleFormatter = require('./console');
const JsonFormatter = require('./json');
const SarifFormatter = require('./sarif');
const SummaryFormatter = require('./summary');

module.exports = {
  ConsoleFormatter,
  JsonFormatter,
  SarifFormatter,
  SummaryFormatter,
};
