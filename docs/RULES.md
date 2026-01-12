# Security Rules Reference

This document provides a comprehensive reference for all security rules implemented in CFN Security Scanner.

## Table of Contents

- [S3 Rules](#s3-rules)
- [EC2 Rules](#ec2-rules)
- [IAM Rules](#iam-rules)
- [RDS Rules](#rds-rules)
- [Lambda Rules](#lambda-rules)
- [API Gateway Rules](#api-gateway-rules)
- [CloudTrail Rules](#cloudtrail-rules)
- [KMS Rules](#kms-rules)
- [SNS Rules](#sns-rules)
- [SQS Rules](#sqs-rules)
- [ECS Rules](#ecs-rules)
- [ElastiCache Rules](#elasticache-rules)
- [ELB Rules](#elb-rules)
- [CloudFront Rules](#cloudfront-rules)
- [Secrets Manager Rules](#secrets-manager-rules)
- [General Rules](#general-rules)

---

## S3 Rules

### CFN_S3_001 - S3 Bucket Encryption Enabled

**Severity:** HIGH | **Category:** encryption

Ensure S3 bucket has server-side encryption enabled to protect data at rest.

**Remediation:** Enable server-side encryption using SSE-S3, SSE-KMS, or SSE-C.

```yaml
BucketEncryption:
  ServerSideEncryptionConfiguration:
    - ServerSideEncryptionByDefault:
        SSEAlgorithm: aws:kms
        KMSMasterKeyID: !Ref KMSKey
```

### CFN_S3_002 - S3 Bucket Public Access Block

**Severity:** CRITICAL | **Category:** access-control

Ensure S3 bucket has public access block configuration to prevent accidental public exposure.

**Remediation:** Enable all public access block settings.

```yaml
PublicAccessBlockConfiguration:
  BlockPublicAcls: true
  BlockPublicPolicy: true
  IgnorePublicAcls: true
  RestrictPublicBuckets: true
```

### CFN_S3_003 - S3 Bucket Versioning Enabled

**Severity:** MEDIUM | **Category:** data-protection

Enable versioning for data protection and recovery capabilities.

### CFN_S3_004 - S3 Bucket Logging Enabled

**Severity:** MEDIUM | **Category:** logging

Enable access logging to track requests to your bucket.

### CFN_S3_005 - S3 Bucket SSL Requests Only

**Severity:** HIGH | **Category:** encryption

Require SSL/TLS for all requests through bucket policy.

### CFN_S3_006 - S3 Bucket KMS Encryption

**Severity:** MEDIUM | **Category:** encryption

Use KMS for server-side encryption instead of SSE-S3.

---

## EC2 Rules

### CFN_EC2_001 - Security Group Unrestricted SSH

**Severity:** CRITICAL | **Category:** network

Detect security groups that allow SSH (port 22) from 0.0.0.0/0.

**Remediation:** Restrict SSH access to specific IP ranges or use AWS Systems Manager Session Manager.

### CFN_EC2_002 - Security Group Unrestricted RDP

**Severity:** CRITICAL | **Category:** network

Detect security groups that allow RDP (port 3389) from 0.0.0.0/0.

### CFN_EC2_003 - Security Group Unrestricted All Traffic

**Severity:** CRITICAL | **Category:** network

Detect security groups that allow all traffic from 0.0.0.0/0.

### CFN_EC2_004 - EC2 Instance IMDSv2 Required

**Severity:** HIGH | **Category:** access-control

Ensure EC2 instances require IMDSv2 to prevent SSRF attacks.

**Remediation:**

```yaml
MetadataOptions:
  HttpTokens: required
  HttpEndpoint: enabled
  HttpPutResponseHopLimit: 1
```

### CFN_EC2_005 - EC2 Instance EBS Encryption

**Severity:** HIGH | **Category:** encryption

Ensure all EBS volumes attached to EC2 instances are encrypted.

### CFN_EC2_010 - VPC Flow Logs Enabled

**Severity:** MEDIUM | **Category:** logging

Ensure VPCs have flow logs enabled for network monitoring.

### CFN_EC2_011 - Security Group Unrestricted Database Ports

**Severity:** CRITICAL | **Category:** network

Detect security groups that allow database ports (3306, 5432, 1433, etc.) from 0.0.0.0/0.

---

## IAM Rules

### CFN_IAM_001 - IAM Policy No Wildcard Actions

**Severity:** HIGH | **Category:** access-control

Ensure IAM policies do not use wildcard (*) actions.

### CFN_IAM_002 - IAM Policy No Wildcard Resources

**Severity:** HIGH | **Category:** access-control

Ensure IAM policies do not use wildcard resources with sensitive actions.

### CFN_IAM_003 - IAM Role Trust Policy Restricted

**Severity:** CRITICAL | **Category:** access-control

Ensure IAM role trust policies do not allow all principals (*).

### CFN_IAM_007 - IAM Policy No Admin Access

**Severity:** CRITICAL | **Category:** access-control

Ensure IAM policies do not grant full administrative access (Action: *, Resource: *).

### CFN_IAM_008 - IAM Role Permissions Boundary

**Severity:** MEDIUM | **Category:** access-control

Recommend setting permissions boundaries on IAM roles.

---

## RDS Rules

### CFN_RDS_001 - RDS Storage Encryption

**Severity:** HIGH | **Category:** encryption

Ensure RDS instances have storage encryption enabled.

**Remediation:**

```yaml
StorageEncrypted: true
KmsKeyId: !Ref KMSKey
```

### CFN_RDS_002 - RDS Public Access Disabled

**Severity:** CRITICAL | **Category:** network

Ensure RDS instances are not publicly accessible.

**Remediation:**

```yaml
PubliclyAccessible: false
```

### CFN_RDS_003 - RDS Multi-AZ Deployment

**Severity:** MEDIUM | **Category:** availability

Enable Multi-AZ for high availability.

### CFN_RDS_004 - RDS Backup Retention

**Severity:** MEDIUM | **Category:** data-protection

Ensure backup retention is at least 7 days.

### CFN_RDS_008 - RDS IAM Authentication

**Severity:** MEDIUM | **Category:** access-control

Enable IAM database authentication.

---

## Lambda Rules

### CFN_LAMBDA_001 - Lambda Function VPC Configuration

**Severity:** MEDIUM | **Category:** network

Deploy Lambda functions within a VPC for network isolation.

### CFN_LAMBDA_002 - Lambda Function Environment Variables Encryption

**Severity:** HIGH | **Category:** encryption

Encrypt environment variables with a custom KMS key.

### CFN_LAMBDA_003 - Lambda Function Tracing Enabled

**Severity:** LOW | **Category:** monitoring

Enable X-Ray tracing for debugging and performance analysis.

### CFN_LAMBDA_009 - Lambda Function Runtime Supported

**Severity:** MEDIUM | **Category:** general

Ensure Lambda functions use supported (non-deprecated) runtimes.

### CFN_LAMBDA_010 - Lambda Function No Hardcoded Secrets

**Severity:** CRITICAL | **Category:** encryption

Detect potentially hardcoded secrets in environment variables.

---

## API Gateway Rules

### CFN_APIGW_001 - API Gateway Access Logging Enabled

**Severity:** MEDIUM | **Category:** logging

Enable access logging on API Gateway stages.

### CFN_APIGW_003 - API Gateway WAF Integration

**Severity:** HIGH | **Category:** network

Protect API Gateway with AWS WAF.

### CFN_APIGW_007 - API Gateway Authorization

**Severity:** HIGH | **Category:** access-control

Ensure API Gateway methods have authorization configured.

### CFN_APIGW_010 - API Gateway Domain TLS Version

**Severity:** HIGH | **Category:** encryption

Ensure custom domains use TLS 1.2 or higher.

---

## CloudTrail Rules

### CFN_CLOUDTRAIL_001 - CloudTrail Encryption Enabled

**Severity:** HIGH | **Category:** encryption

Encrypt CloudTrail logs with KMS.

### CFN_CLOUDTRAIL_002 - CloudTrail Log Validation Enabled

**Severity:** MEDIUM | **Category:** data-protection

Enable log file validation to detect tampering.

### CFN_CLOUDTRAIL_003 - CloudTrail Multi-Region Enabled

**Severity:** HIGH | **Category:** logging

Enable CloudTrail in all regions.

### CFN_CLOUDTRAIL_004 - CloudTrail CloudWatch Integration

**Severity:** MEDIUM | **Category:** logging

Send CloudTrail logs to CloudWatch for real-time monitoring.

---

## KMS Rules

### CFN_KMS_001 - KMS Key Rotation Enabled

**Severity:** MEDIUM | **Category:** encryption

Enable automatic key rotation for symmetric KMS keys.

### CFN_KMS_002 - KMS Key Policy Restricted

**Severity:** CRITICAL | **Category:** access-control

Ensure KMS key policies do not allow public access.

---

## SNS/SQS Rules

### CFN_SNS_001 - SNS Topic Encryption

**Severity:** HIGH | **Category:** encryption

Encrypt SNS topics with KMS.

### CFN_SQS_001 - SQS Queue Encryption

**Severity:** HIGH | **Category:** encryption

Encrypt SQS queues with KMS.

### CFN_SQS_003 - SQS Dead Letter Queue

**Severity:** MEDIUM | **Category:** availability

Configure dead letter queues for message handling.

---

## ECS Rules

### CFN_ECS_003 - ECS Task Definition No Privileged

**Severity:** CRITICAL | **Category:** access-control

Ensure containers do not run in privileged mode.

### CFN_ECS_004 - ECS Task Definition Logging

**Severity:** MEDIUM | **Category:** logging

Configure logging for all containers.

### CFN_ECS_008 - ECS Task Definition User Not Root

**Severity:** HIGH | **Category:** access-control

Ensure containers run as non-root users.

---

## ElastiCache Rules

### CFN_ELASTICACHE_001 - ElastiCache Encryption at Rest

**Severity:** HIGH | **Category:** encryption

Enable encryption at rest for ElastiCache.

### CFN_ELASTICACHE_002 - ElastiCache Encryption in Transit

**Severity:** HIGH | **Category:** encryption

Enable encryption in transit for ElastiCache.

### CFN_ELASTICACHE_003 - ElastiCache Auth Token

**Severity:** HIGH | **Category:** access-control

Enable AUTH token for Redis clusters.

---

## ELB Rules

### CFN_ELB_001 - ALB Access Logging Enabled

**Severity:** MEDIUM | **Category:** logging

Enable access logging for load balancers.

### CFN_ELB_004 - ALB HTTPS Listener

**Severity:** HIGH | **Category:** encryption

Ensure listeners use HTTPS.

### CFN_ELB_005 - ALB SSL Policy

**Severity:** HIGH | **Category:** encryption

Use secure SSL/TLS policies.

### CFN_ELB_006 - ALB WAF Integration

**Severity:** HIGH | **Category:** network

Protect ALB with AWS WAF.

---

## CloudFront Rules

### CFN_CLOUDFRONT_001 - CloudFront HTTPS Only

**Severity:** HIGH | **Category:** encryption

Require HTTPS for all CloudFront distributions.

### CFN_CLOUDFRONT_002 - CloudFront Minimum TLS Version

**Severity:** HIGH | **Category:** encryption

Use TLS 1.2 or higher.

### CFN_CLOUDFRONT_004 - CloudFront WAF Integration

**Severity:** HIGH | **Category:** network

Protect CloudFront with AWS WAF.

### CFN_CLOUDFRONT_005 - CloudFront Origin Access Identity

**Severity:** HIGH | **Category:** access-control

Use OAI/OAC for S3 origins.

---

## Secrets Manager Rules

### CFN_SECRETS_001 - Secret KMS Encryption

**Severity:** MEDIUM | **Category:** encryption

Use customer-managed KMS keys for secrets.

### CFN_SECRETS_002 - Secret Rotation Enabled

**Severity:** HIGH | **Category:** access-control

Enable automatic secret rotation.

### CFN_SECRETS_003 - Secret No Hardcoded Values

**Severity:** CRITICAL | **Category:** encryption

Detect hardcoded secret values.

---

## General Rules

### CFN_GEN_001 - No Hardcoded Credentials

**Severity:** CRITICAL | **Category:** encryption

Detect hardcoded credentials in templates.

### CFN_GEN_003 - DeletionPolicy Configured

**Severity:** MEDIUM | **Category:** data-protection

Ensure critical resources have DeletionPolicy.

### CFN_GEN_005 - Parameters NoEcho

**Severity:** HIGH | **Category:** encryption

Use NoEcho for sensitive parameters.

---

## Compliance Framework Mapping

| Framework | Description |
|-----------|-------------|
| CIS | CIS AWS Foundations Benchmark |
| SOC2 | SOC 2 Type II Controls |
| HIPAA | HIPAA Security Rule |
| PCI-DSS | Payment Card Industry Data Security Standard |

To filter by framework:

```bash
cfn-scan template.yaml --framework HIPAA
```
