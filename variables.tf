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
