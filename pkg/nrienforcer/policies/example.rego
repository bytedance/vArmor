package nri.authz

import data.varmor.nri.builtin

# --- DENY 规则集 (仅拦截，不告警) ---
deny[msg] {
    input.pod.labels["security-tier"] == "production"
    not input.spec.linux.maskedPaths
    msg := "Privileged containers are denied in production"
}

deny[msg] {
    input.pod.labels["business-critical"] == "true"
    builtin.is_privileged_container
    msg := "Critical business: Privileged containers denied"
}

# --- AUDIT-DENY 规则集 (告警并拦截) ---
audit_deny[msg] {
    input.pod.labels["env"] == "production"
    contains(input.image, "latest")
    msg := "Using latest tag in production - audit-deny with alert"
}

audit_deny[msg] {
    input.pod.labels["environment"] == "production"
    builtin.has_dangerous_capabilities
    msg := "Production: Dangerous capabilities denied"
}

audit_deny[msg] {
    input.pod.labels["environment"] == "production"
    builtin.uses_latest_tag
    msg := "Production: Latest tag audit-denied"
}

# --- AUDIT-ALLOW 规则集 (仅告警，不拦截) ---
audit_allow[msg] {
    input.pod.labels["env"] == "development"
    not input.spec.linux.resources.cpu.quota
    msg := "Container without CPU limits (audit only)"
}

audit_allow[msg] {
    input.pod.labels["environment"] == "development"
    builtin.missing_cpu_limits
    msg := "Development: Missing CPU limits (audit)"
}

audit_allow[msg] {
    input.pod.labels["environment"] == "development"
    some env in input.spec.process.env
    startswith(env, "DEBUG=")
    msg := "Development: Debug environment variables (audit)"
}
