# SAML2OAuth

A lightweight Identity Provider (IdP) shim that bridges OAuth/OIDC authentication to SAML 2.0 Service Providers. Deploy as an AWS Lambda function to enable SAML SSO for applications that don't support modern OAuth/OIDC protocols.

## Overview

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  SAML Service   │     │   SAML2OAuth     │     │  OAuth/OIDC     │     │     User        │
│    Provider     │────>│   IdP Shim       │────>│    Provider     │────>│   (Browser)     │
│  (Your App)     │<────│   (Lambda)       │<────│   (SSO)         │<────│                 │
└─────────────────┘     └──────────────────┘     └─────────────────┘     └─────────────────┘
     SAML 2.0              Translates               OAuth 2.0
     Response              protocols                + OIDC
```

### How It Works

1. **SP Initiates Login**: Your SAML Service Provider redirects users to this IdP with a `SAMLRequest`
2. **OAuth Redirect**: The shim redirects users to your OAuth/OIDC provider (e.g., GOV.UK SSO)
3. **User Authenticates**: User logs in via the OAuth provider
4. **Token Exchange**: OAuth callback returns user info (email, name, groups)
5. **SAML Response**: The shim generates a signed SAML 2.0 Response and POSTs it to the SP's ACS URL
6. **Optional SCIM**: User attributes can be provisioned to the SP via SCIM 2.0

## Features

- **SAML 2.0 IdP**: Full SP-initiated SSO flow with signed assertions
- **OAuth/OIDC Bridge**: Authenticate users via any OIDC-compliant provider
- **SCIM 2.0 Provisioning**: Optional just-in-time user provisioning
- **Auto-Generated Keypair**: SAML signing keys auto-generated and stored in AWS Secrets Manager
- **Serverless**: Runs as AWS Lambda with Lambda Function URL
- **Terraform Module**: Infrastructure-as-code deployment

## Quick Start

### Prerequisites

- Python 3.13+
- AWS account with appropriate permissions
- Terraform 1.0+
- OAuth/OIDC client credentials from your identity provider

### Local Development

```bash
# Clone the repository
git clone https://github.com/your-org/saml2oauth.git
cd saml2oauth

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate   # Windows

# Install dependencies
pip install -r src/requirements.txt
pip install -r requirements-dev.txt

# Set environment variables
export OAUTH_CLIENT_ID="your-client-id"
export OAUTH_CLIENT_SECRET="your-client-secret"
export SP_ACS_URL="https://your-app.com/saml/acs"
export SP_ENTITY_ID="https://your-app.com"
export FLASK_SECRET_KEY="local-dev-secret-key"
export ENVIRONMENT="dev"

# Run locally (requires AWS credentials for Secrets Manager)
flask --app src/app run --debug
```

### Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=src --cov-report=term-missing

# Run linting
ruff check src/ tests/
ruff format --check src/ tests/
```

### Building for Lambda

```bash
./build.sh
# Output: dist/lambda.zip
```

## Deployment

### Using Terraform

```hcl
module "saml2oauth" {
  source = "github.com/govuk-digital-backbone/saml2oauth"

  OAUTH_CLIENT_ID     = "your-oauth-client-id"
  OAUTH_CLIENT_SECRET = "your-oauth-client-secret"
  SP_ACS_URL          = "https://your-saml-app.com/saml/acs"
  SP_ENTITY_ID        = "https://your-saml-app.com"

  # Optional: SCIM provisioning
  SCIM_URL          = "https://your-saml-app.com/scim/v2"
  SCIM_ACCESS_TOKEN = "your-scim-bearer-token"

  # Optional: Log retention
  LOG_RETENTION_DAYS = 365
}

output "idp_url" {
  value = module.saml2oauth.lambda_function_url
}
```

### Terraform Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `OAUTH_CLIENT_ID` | Yes | - | OAuth/OIDC client identifier |
| `OAUTH_CLIENT_SECRET` | Yes | - | OAuth/OIDC client secret |
| `SP_ACS_URL` | Yes | - | Service Provider's Assertion Consumer Service URL |
| `SP_ENTITY_ID` | No | `""` | Service Provider Entity ID |
| `SCIM_URL` | No | `""` | SCIM 2.0 endpoint for user provisioning |
| `SCIM_ACCESS_TOKEN` | No | `""` | Bearer token for SCIM API |
| `LOG_RETENTION_DAYS` | No | `365` | CloudWatch log retention in days |

## Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `OAUTH_CLIENT_ID` | Yes | OAuth client ID |
| `OAUTH_CLIENT_SECRET` | Yes | OAuth client secret |
| `SP_ACS_URL` | Yes | SAML Assertion Consumer Service URL |
| `SP_ENTITY_ID` | Yes | SAML Service Provider Entity ID |
| `FLASK_SECRET_KEY` | Yes* | Session encryption key (*auto-generated in Lambda) |
| `SAML_KEYPAIR_SECRET_NAME` | No | Secrets Manager secret name for SAML signing keys |
| `OPENID_CONFIG_URL` | No | OIDC discovery URL (defaults to GOV.UK SSO) |
| `SIGNOUT_URL` | No | Post-logout redirect URL |
| `NAMEID_FORMAT` | No | SAML NameID format (default: `emailAddress`) |
| `SCIM_URL` | No | SCIM 2.0 base URL for user provisioning |
| `SCIM_ACCESS_TOKEN` | No | SCIM API bearer token |
| `ENVIRONMENT` | No | Environment name (`prod`, `dev`, `test`) |
| `IS_HTTPS` | No | Set to `true` for secure cookies |
| `IDP_COMMON_NAME` | No | Certificate Common Name |

### OAuth Provider Configuration

By default, configured for GOV.UK SSO. To use another provider, set:

```bash
export OPENID_CONFIG_URL="https://your-idp.com/.well-known/openid-configuration"
export SIGNOUT_URL="https://your-idp.com/logout"
```

The OAuth provider must return these claims:
- `email` (required)
- `email_verified` (required, must be `true`)
- `sub` (user identifier)
- `display_name` or `name` (optional)
- `given_name` (optional)
- `family_name` (optional)
- `groups` (optional, array)

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Home page with IdP information |
| `/login` | GET, POST | SP-initiated SSO entry point (accepts `SAMLRequest`, `RelayState`) |
| `/callback` | GET | OAuth callback handler |
| `/logout` | GET, POST | Logout and redirect to OAuth provider logout |
| `/saml/response` | GET | Generate and POST SAML response to SP |
| `/saml/metadata` | GET | SAML IdP metadata XML |
| `/saml/cert` | GET | Download SAML signing certificate |
| `/health` | GET | Health check endpoint |
| `/health/cert` | GET | Certificate health check |

## SAML Configuration

### Configuring Your Service Provider

1. **Get IdP Metadata**: Access `/saml/metadata` to download the IdP metadata XML
2. **Or Configure Manually**:
   - **IdP Entity ID**: `https://your-lambda-url.lambda-url.region.on.aws/`
   - **SSO URL**: `https://your-lambda-url.lambda-url.region.on.aws/login`
   - **SLO URL**: `https://your-lambda-url.lambda-url.region.on.aws/logout`
   - **Certificate**: Download from `/saml/cert`

### SAML Attributes

The following attributes are included in SAML assertions:

| Attribute Name | Source |
|----------------|--------|
| `email` | OAuth email claim |
| `mail` | OAuth email claim (alias) |
| `name` | OAuth display_name claim |
| `displayName` | OAuth display_name claim (alias) |
| `givenName` | OAuth given_name claim |
| `surname` | OAuth family_name claim |
| `groups` | OAuth groups claim (multi-valued) |
| `https://aws.amazon.com/SAML/Attributes/RoleSessionName` | OAuth email claim |

## SCIM Provisioning

When `SCIM_URL` and `SCIM_ACCESS_TOKEN` are configured, the shim will:

1. **Search for existing user** by email
2. **Create or update user** with attributes from OAuth
3. **Sync group memberships** (creates groups if they don't exist)

### SCIM User Payload

```json
{
  "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
  "userName": "user@example.com",
  "externalId": "oauth-sub-id",
  "active": true,
  "displayName": "User Name",
  "name": {
    "givenName": "User",
    "familyName": "Name"
  },
  "emails": [{"value": "user@example.com", "type": "work"}]
}
```

## Security

### Security Features

- **Signed SAML Assertions**: RSA-SHA256 signatures on all assertions
- **Cryptographic IDs**: Response and assertion IDs use `secrets.token_urlsafe()`
- **XSS Prevention**: HTML escaping on all user-controlled values
- **SCIM Filter Injection Prevention**: Escaped filter values
- **Secure Cookies**: HttpOnly, Secure (in HTTPS mode), SameSite=Lax
- **No Caching**: All responses include `Cache-Control: no-store`
- **Input Validation**: Email verification required from OAuth provider

### Key Storage

SAML signing keys are automatically generated and stored in AWS Secrets Manager:
- **Algorithm**: RSA 2048-bit
- **Certificate Validity**: 10 years
- **Secret Name**: Configured via `SAML_KEYPAIR_SECRET_NAME`

### IAM Permissions

The Lambda function requires these IAM permissions:

```json
{
  "Effect": "Allow",
  "Action": [
    "secretsmanager:GetSecretValue",
    "secretsmanager:CreateSecret",
    "secretsmanager:PutSecretValue"
  ],
  "Resource": "arn:aws:secretsmanager:*:*:secret:saml-idp-keypair-*"
}
```

## Architecture

```
src/
├── app.py              # Flask application and routes
├── lambda_function.py  # AWS Lambda handler
├── shim_saml.py        # SAML response generation and signing
├── shim_scim.py        # SCIM user provisioning
├── shim_utils.py       # Logging utilities
└── requirements.txt    # Production dependencies

tests/
├── conftest.py         # Shared pytest fixtures
├── test_app.py         # Flask route tests
├── test_shim_saml.py   # SAML generation tests
├── test_shim_scim.py   # SCIM provisioning tests
├── test_shim_utils.py  # Utility tests
└── test_lambda_handler.py  # Lambda handler tests
```

### Dependencies

**Runtime:**
- `flask` - Web framework
- `authlib` - OAuth/OIDC client
- `lxml` - XML processing
- `signxml` - XML signature generation
- `apig-wsgi` - Lambda/Flask bridge
- `requests` - HTTP client (for SCIM)
- `boto3` - AWS SDK (bundled in Lambda)

**Development:**
- `pytest` - Testing framework
- `pytest-cov` - Coverage reporting
- `moto` - AWS mocking
- `responses` - HTTP mocking
- `freezegun` - Time mocking
- `ruff` - Linting and formatting

## CI/CD

GitHub Actions workflow runs on push/PR to main:

1. **Lint**: Ruff linter and formatter checks
2. **Test**: pytest with 70% coverage requirement
3. **Build**: Lambda package (main branch only)

```yaml
# .github/workflows/ci.yml triggers:
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
```

## Troubleshooting

### Common Issues

**"SAML signature validation failed"**
- Ensure your SP has the correct certificate from `/saml/cert`
- Check that the IdP Entity ID matches (the Lambda URL)

**"OAuth callback failed"**
- Verify `OAUTH_CLIENT_ID` and `OAUTH_CLIENT_SECRET` are correct
- Check that your OAuth callback URL is registered: `https://your-lambda-url/callback`

**"SCIM provisioning failed"**
- Verify `SCIM_URL` is accessible from Lambda
- Check `SCIM_ACCESS_TOKEN` has appropriate permissions

**"Session not persisting"**
- In Lambda, ensure `FLASK_SECRET_KEY` is set (Terraform does this automatically)
- Check that cookies are being sent (browser developer tools)

### Logging

All requests are logged to CloudWatch with JSON format:

```json
{
  "_datetime": "2024-01-01T12:00:00.000000Z",
  "Request": {...},
  "Response": {
    "statusCode": 200,
    "headers": {...},
    "body_length": 1234
  }
}
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes with tests
4. Ensure `pytest` and `ruff check` pass
5. Submit a pull request

## License

MIT
