# Optional Entra app registration and a federated credential.
# CI runs `terraform validate` only. Do not apply this from the lab.

provider "azuread" {
  tenant_id = var.tenant_id
}

resource "azuread_application" "gateway" {
  display_name = var.display_name
}

resource "azuread_service_principal" "gateway" {
  client_id = azuread_application.gateway.client_id
}

resource "azuread_application_federated_identity_credential" "github" {
  application_id = azuread_application.gateway.id
  display_name   = "github-main"
  description    = "Workload identity federation for the lab. Not a client secret."
  audiences      = ["api://AzureADTokenExchange"]
  issuer         = "https://token.actions.githubusercontent.com"
  subject        = var.github_subject
}
