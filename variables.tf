variable "OAUTH_CLIENT_ID" {
  description = "OAuth client ID"
  type        = string
}

variable "OAUTH_CLIENT_SECRET" {
  description = "OAuth client secret"
  type        = string
}

variable "SCIM_URL" {
  description = "SCIM API URL"
  type        = string
  default     = ""
}

variable "SCIM_ACCESS_TOKEN" {
  description = "SCIM API access token"
  type        = string
  default     = ""
}

variable "SP_ACS_URL" {
  description = "Service Provider Assertion Consumer Service URL"
  type        = string
}

variable "SP_ENTITY_ID" {
  description = "Service Provider Entity ID"
  type        = string
  default     = ""
}

variable "LOG_RETENTION_DAYS" {
  description = "Log retention days"
  type        = number
  default     = 365
}

variable "lambda_source" {
  description = "Source for Lambda package: 'local' builds from source, 'github' fetches from releases"
  type        = string
  default     = "local"
  validation {
    condition     = contains(["local", "github"], var.lambda_source)
    error_message = "lambda_source must be 'local' or 'github'"
  }
}

variable "github_repo" {
  description = "GitHub repository in format 'owner/repo' for fetching releases"
  type        = string
  default     = "govuk-digital-backbone/saml2oauth"
}

variable "github_release_tag" {
  description = "GitHub release tag to fetch artifact from (when lambda_source='github')"
  type        = string
  default     = "latest"
}

variable "IDP_COMMON_NAME" {
  description = "Common Name for the SAML signing certificate"
  type        = string
  default     = "saml2oauth.local"
}
