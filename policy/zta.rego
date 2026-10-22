# Note (R7): Full design authorization policy for OPA.
# OPA evaluates the full design; ablation experiments (-M20, -M21, etc.)
# use the JS policy engine in lib/policy.js.
package zta.authz

import rego.v1

sens := data.resources[input.resource].sensitivity          # "low" | "high"

default decision := "deny"

device_ok if {
  input.device.status == "active"
  input.device.attestation_age_s <= data.max_age_s[sens]  # T_max(r)
  input.device.owner == input.token.sub
}

acr_ok if sens == "low"
acr_ok if input.token.acr == "mfa"

risk_ok if input.risk < data.theta[sens]
risk_ok if {                                                # recent step-up covers elevated risk
  input.token.acr == "mfa"
  input.now_s - input.token.auth_time <= data.t_su_s
}

role_ok if {
  some p in data.permissions[input.token.role]
  p.resource == input.resource
  input.op in p.ops
}

decision := "deny"    if not device_ok
decision := "step_up" if { device_ok; not acr_ok }
decision := "step_up" if { device_ok; acr_ok; not risk_ok }
decision := "permit"  if { device_ok; acr_ok; risk_ok; role_ok }
decision := "deny"    if { device_ok; acr_ok; risk_ok; not role_ok }
