/**
 * CloudFormation YAML Parser
 * Custom YAML parser that handles CloudFormation intrinsic functions
 */

const yaml = require('js-yaml');

// CloudFormation intrinsic function tags
const cfnTags = [
  'Ref',
  'GetAtt',
  'Sub',
  'Join',
  'Select',
  'Split',
  'If',
  'Condition',
  'Equals',
  'And',
  'Or',
  'Not',
  'FindInMap',
  'GetAZs',
  'ImportValue',
  'Base64',
  'Cidr',
  'Transform',
];

/**
 * Create custom YAML type for CloudFormation function
 */
function createCfnType(name) {
  return new yaml.Type(`!${name}`, {
    kind: 'scalar',
    construct: function (data) {
      return { [name]: data };
    },
  });
}

/**
 * Create sequence type for CloudFormation functions that take arrays
 */
function createCfnSequenceType(name) {
  return new yaml.Type(`!${name}`, {
    kind: 'sequence',
    construct: function (data) {
      return { [name]: data };
    },
  });
}

/**
 * Create mapping type for CloudFormation functions that take objects
 */
function createCfnMappingType(name) {
  return new yaml.Type(`!${name}`, {
    kind: 'mapping',
    construct: function (data) {
      return { [name]: data };
    },
  });
}

// Create schema with all CloudFormation types
const cfnTypes = [];

for (const tag of cfnTags) {
  cfnTypes.push(createCfnType(tag));
  cfnTypes.push(createCfnSequenceType(tag));
  cfnTypes.push(createCfnMappingType(tag));
}

// Special handling for GetAtt with dot notation
cfnTypes.push(
  new yaml.Type('!GetAtt', {
    kind: 'scalar',
    construct: function (data) {
      if (typeof data === 'string' && data.includes('.')) {
        return { 'Fn::GetAtt': data.split('.') };
      }
      return { 'Fn::GetAtt': data };
    },
  })
);

const CFN_SCHEMA = yaml.DEFAULT_SCHEMA.extend(cfnTypes);

/**
 * Parse CloudFormation YAML template
 */
function parse(content) {
  return yaml.load(content, { schema: CFN_SCHEMA });
}

/**
 * Dump object to CloudFormation YAML
 */
function dump(obj) {
  return yaml.dump(obj, { schema: CFN_SCHEMA });
}

module.exports = {
  parse,
  dump,
  CFN_SCHEMA,
};
