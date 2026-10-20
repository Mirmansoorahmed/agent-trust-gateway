# Optional IAM OIDC provider and a role agents could assume.
# CI runs `terraform validate` only. Do not apply this from the lab.

provider "aws" {
  region = var.region
}

resource "aws_iam_openid_connect_provider" "agents" {
  url             = var.oidc_url
  client_id_list  = ["agent-trust-gateway"]
  thumbprint_list = [var.thumbprint]
}

data "aws_iam_policy_document" "assume" {
  statement {
    effect = "Allow"
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.agents.arn]
    }
    actions = ["sts:AssumeRoleWithWebIdentity"]
    condition {
      test     = "StringEquals"
      variable = "${replace(var.oidc_url, "https://", "")}:aud"
      values   = ["agent-trust-gateway"]
    }
  }
}

resource "aws_iam_role" "agent" {
  name               = "atg-agent-lab"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}
