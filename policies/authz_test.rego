package atg.authz_test

import data.atg.authz

base := {
	"agent": {
		"id": "mail-assistant",
		"scopes": ["mail.read", "mail.send"],
		"allowed_tools": ["mail.list_inbox", "mail.send_email"],
	},
	"server": {"id": "mail", "allowlisted": true, "drift": false},
	"tool": {
		"qualified_name": "mail.send_email",
		"name": "send_email",
		"server_id": "mail",
		"labels": ["sensitive", "outbound"],
		"poison_flags": [],
		"required_scope": "mail.send",
	},
	"args": {"to": "lena.vogel@nordlicht.example", "subject": "hi", "body": "hello", "bcc": ""},
	"session": {
		"saw_untrusted": false,
		"holds_sensitive": false,
		"sensitive_servers": [],
		"approvals_last_minute": 0,
	},
	"policy": {
		"recipient_allowlist": ["lena.vogel@nordlicht.example", "jonas.berg@nordlicht.example"],
		"approval_rate_limit": 8,
	},
}

test_allow_benign_send if {
	authz.decision with input as base == "allow"
}

test_deny_drift if {
	inp := json.patch(base, [{"op": "add", "path": "/server/drift", "value": true}])
	authz.decision with input as inp == "deny"
	authz.reason with input as inp == "manifest drift"
}

test_deny_not_allowlisted if {
	inp := json.patch(base, [{"op": "add", "path": "/server/allowlisted", "value": false}])
	authz.decision with input as inp == "deny"
}

test_deny_poison if {
	inp := json.patch(base, [{"op": "add", "path": "/tool/poison_flags", "value": ["hidden_instruction_tag"]}])
	authz.decision with input as inp == "deny"
}

test_deny_tool_not_in_agent_allowlist if {
	inp := json.patch(base, [{"op": "add", "path": "/tool/qualified_name", "value": "repo.get_file"}])
	authz.decision with input as inp == "deny"
}

test_deny_missing_scope if {
	inp := json.patch(base, [{"op": "add", "path": "/agent/scopes", "value": ["mail.read"]}])
	authz.decision with input as inp == "deny"
}

test_deny_bcc if {
	inp := json.patch(base, [{"op": "add", "path": "/args/bcc", "value": "attacker@evil.test"}])
	authz.decision with input as inp == "deny"
}

test_deny_unknown_recipient if {
	inp := json.patch(base, [{"op": "add", "path": "/args/to", "value": "attacker@evil.test"}])
	authz.decision with input as inp == "deny"
}

test_approval_after_untrusted if {
	inp := json.patch(base, [{"op": "add", "path": "/session/saw_untrusted", "value": true}])
	authz.decision with input as inp == "needs_approval"
}

test_approval_cross_server_sensitive if {
	inp := json.patch(base, [{"op": "add", "path": "/session/sensitive_servers", "value": ["repo"]}])
	authz.decision with input as inp == "needs_approval"
}

test_allow_same_server_sensitive if {
	inp := json.patch(base, [{"op": "add", "path": "/session/sensitive_servers", "value": ["mail"]}])
	authz.decision with input as inp == "allow"
}

test_rate_limit_denies_instead_of_queueing if {
	inp := json.patch(base, [
		{"op": "add", "path": "/session/saw_untrusted", "value": true},
		{"op": "add", "path": "/session/approvals_last_minute", "value": 8},
	])
	authz.decision with input as inp == "deny"
	reason := authz.reason with input as inp
	contains(reason, "approval rate limit exceeded")
}

test_read_does_not_need_approval if {
	inp := json.patch(base, [
		{"op": "add", "path": "/tool", "value": {
			"qualified_name": "mail.list_inbox",
			"name": "list_inbox",
			"server_id": "mail",
			"labels": ["sensitive"],
			"poison_flags": [],
			"required_scope": "mail.read",
		}},
		{"op": "add", "path": "/args", "value": {}},
		{"op": "add", "path": "/session/saw_untrusted", "value": true},
	])
	authz.decision with input as inp == "allow"
}
