variable "region" {
  type    = string
  default = "eu-central-1"
}

variable "oidc_url" {
  description = "Issuer URL without a trailing slash. Example only; CI does not apply this."
  type        = string
  default     = "https://example.invalid/agents"
}

variable "thumbprint" {
  description = "Example SHA-1 thumbprint placeholder. Replace it before any real plan."
  type        = string
  default     = "0000000000000000000000000000000000000000"
}
