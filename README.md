# SAML2OAuth

...

``` terraform
module "saml2oauth" {
  source = "github.com/govuk-digital-backbone/saml2oauth"

  OAUTH_CLIENT_ID     = "123"
  OAUTH_CLIENT_SECRET = "abc"
  SCIM_URL            = "https://example.com/scim"   # Optional
  SCIM_ACCESS_TOKEN   = "def"                        # Optional
  SP_ACS_URL          = "https://example.com/acs"
  SP_ENTITY_ID        = "https://example.com/entity"
  LOG_RETENTION_DAYS  = 30                           # Default is 365
}
```
