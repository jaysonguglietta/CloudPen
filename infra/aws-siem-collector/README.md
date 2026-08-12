# AWS immutable SIEM collector

This stack is the separately deployed receiving boundary for CloudPen's minimized `cloudpen.security-event.v1` stream. It exposes only `POST /v1/events`, verifies a generated bearer credential and body digest, rejects unknown schema fields, deduplicates event IDs, and returns success only after S3 accepts the event. Events are stored in a private, versioned S3 bucket with a 90-day Object Lock `COMPLIANCE` default. Selected security categories and any `localMode: true` event publish a metadata-only alert to the operator SNS topic.

The collector receives no request bodies from the CloudPen application, cloud credentials, evidence, signing material, External IDs, or raw user email addresses. API access logs also exclude bodies and authorization headers.

## Deploy

Use a security-operations AWS account and region selected by the owner. Package and deploy the SAM template with CloudFormation, passing an SNS topic with a confirmed operator subscription. Record the `CollectorUrl`, `CollectorTokenSecretArn`, and `EventArchiveBucket` outputs. Retrieve the generated token through an approved secret workflow and configure it as the Sites secret `CLOUDPEN_SIEM_TOKEN`; configure the URL as `CLOUDPEN_SIEM_URL`.

Rotate the token by writing a new 32-character-or-longer random value to the Secrets Manager secret, updating the Sites secret, deploying the current Sites version to apply the environment revision, and allowing five minutes for any warm collector instance to expire its credential cache. Test old-token rejection after the cache window.

Object Lock `COMPLIANCE` retention cannot be shortened or bypassed, including by the root user. Treat deployment as a retention and cost commitment. The bucket and secret are retained if the stack is deleted.
