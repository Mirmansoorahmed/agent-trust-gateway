variable "tenant_id" {
  description = "Entra tenant id. Required for plan; this module is never applied by CI."
  type        = string
}

variable "display_name" {
  description = "App registration that stands in for an agent identity."
  type        = string
  default     = "agent-trust-gateway-lab"
}

variable "github_subject" {
  description = "Subject claim for workload identity federation."
  type        = string
  default     = "repo:Mirmansoorahmed/agent-trust-gateway:ref:refs/heads/main"
}
