/**
 * Rules Index - Loads and exports all security rules
 */

const s3Rules = require('./s3');
const ec2Rules = require('./ec2');
const iamRules = require('./iam');
const rdsRules = require('./rds');
const lambdaRules = require('./lambda');
const apiGatewayRules = require('./apiGateway');
const cloudTrailRules = require('./cloudtrail');
const kmsRules = require('./kms');
const snsRules = require('./sns');
const sqsRules = require('./sqs');
const ecsRules = require('./ecs');
const elasticacheRules = require('./elasticache');
const elbRules = require('./elb');
const cloudFrontRules = require('./cloudfront');
const secretsManagerRules = require('./secretsmanager');
const generalRules = require('./general');

/**
 * Load all security rules
 */
function loadAllRules() {
  return [
    ...s3Rules,
    ...ec2Rules,
    ...iamRules,
    ...rdsRules,
    ...lambdaRules,
    ...apiGatewayRules,
    ...cloudTrailRules,
    ...kmsRules,
    ...snsRules,
    ...sqsRules,
    ...ecsRules,
    ...elasticacheRules,
    ...elbRules,
    ...cloudFrontRules,
    ...secretsManagerRules,
    ...generalRules,
  ];
}

/**
 * Get rules by category
 */
function getRulesByCategory(category) {
  return loadAllRules().filter(rule => rule.category === category);
}

/**
 * Get rules by severity
 */
function getRulesBySeverity(severity) {
  return loadAllRules().filter(rule => rule.severity === severity);
}

/**
 * Get rules by resource type
 */
function getRulesByResourceType(resourceType) {
  return loadAllRules().filter(rule => rule.resourceTypes.includes(resourceType));
}

module.exports = {
  loadAllRules,
  getRulesByCategory,
  getRulesBySeverity,
  getRulesByResourceType,
};
