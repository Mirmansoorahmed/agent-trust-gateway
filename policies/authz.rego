package atg.authz

import rego.v1

# Fail closed. A call is allowed only when no deny reason and no approval reason match.
default decision := "deny"
default reason := "denied by default"

base_reasons contains "manifest drift" if {
	input.server.drift == true
}

base_reasons contains "server is not allowlisted" if {
	input.server.allowlisted != true
}

base_reasons contains "tool description failed the linter" if {
	count(object.get(input.tool, "poison_flags", [])) > 0
}

base_reasons contains "tool is outside the agent allowlist" if {
	not input.tool.qualified_name in object.get(input.agent, "allowed_tools", [])
}

base_reasons contains "token scope does not allow this tool" if {
	scope := object.get(input.tool, "required_scope", "")
	scope != ""
	not scope in object.get(input.agent, "scopes", [])
}

base_reasons contains "blind-copy recipient is not permitted" if {
	bcc := object.get(input.args, "bcc", "")
	bcc != ""
}

base_reasons contains "outbound recipient is not allowlisted" if {
	"outbound" in object.get(input.tool, "labels", [])
	to := object.get(input.args, "to", "")
	to != ""
	not to in object.get(input.policy, "recipient_allowlist", [])
}

approval_reasons contains "outbound call after untrusted content" if {
	count(base_reasons) == 0
	"outbound" in object.get(input.tool, "labels", [])
	input.session.saw_untrusted == true
}

approval_reasons contains "outbound call would move sensitive data across servers" if {
	count(base_reasons) == 0
	"outbound" in object.get(input.tool, "labels", [])
	some other in object.get(input.session, "sensitive_servers", [])
	other != input.tool.server_id
}

rate_limited if {
	count(approval_reasons) > 0
	input.session.approvals_last_minute >= object.get(input.policy, "approval_rate_limit", 8)
}

reasons contains msg if base_reasons[msg]

reasons contains "approval rate limit exceeded" if rate_limited

decision := "deny" if count(reasons) > 0

decision := "needs_approval" if {
	count(reasons) == 0
	count(approval_reasons) > 0
}

decision := "allow" if {
	count(reasons) == 0
	count(approval_reasons) == 0
}

reason := concat("; ", sort(reasons)) if count(reasons) > 0

reason := concat("; ", sort(approval_reasons)) if {
	count(reasons) == 0
	count(approval_reasons) > 0
}

reason := "allow" if {
	count(reasons) == 0
	count(approval_reasons) == 0
}
