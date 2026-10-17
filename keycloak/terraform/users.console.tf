# Console personas: who uses the management console for what. Each persona
# holds ONE realm role; the console turns realm roles into team memberships
# (user:x member team:role_<name>) on every check, and the console store's
# seed grants per team (examples/models/console/seed.sql). alice/bob/carol/eva
# stay the APPLICATION users — the subjects the demo models decide about.
#
#   platform-admin  console_admin        IT/ops: creates and retires stores, owns shared types
#   auditor         console_auditor      audit: Activity and decisions everywhere, read-only
#   iam-dev         console_iam_dev      IAM developer: owns the models (author + publisher)
#   app-dev         console_app_dev      application developer: viewer + tester (own access only)
#   app-secarch     console_app_secarch  application security architect: author on the app's store
#   support         console_support      support: looks up anyone's access, never edits

locals {
  console_personas = {
    "platform-admin" = { first = "Pat", last = "Platform", role = "console_admin" }
    "auditor"        = { first = "Audrey", last = "Auditor", role = "console_auditor" }
    "iam-dev"        = { first = "Ian", last = "Identity", role = "console_iam_dev" }
    "app-dev"        = { first = "Dana", last = "Developer", role = "console_app_dev" }
    "app-secarch"    = { first = "Sam", last = "Secarch", role = "console_app_secarch" }
    "support"        = { first = "Sue", last = "Support", role = "console_support" }
  }
  console_persona_roles = toset([for p in local.console_personas : p.role if p.role != "console_admin"])
}

resource "keycloak_role" "console_persona" {
  for_each = local.console_persona_roles
  realm_id = keycloak_realm.pgauthz.id
  name     = each.key
}

resource "keycloak_user" "console_persona" {
  for_each   = local.console_personas
  realm_id   = keycloak_realm.pgauthz.id
  username   = each.key
  enabled    = true
  email      = "${each.key}@pgauthz.test"
  first_name = each.value.first
  last_name  = each.value.last
  attributes = { subject_type = "internal_user" }
  depends_on = [keycloak_realm_user_profile.pgauthz]
  initial_password {
    value     = var.demo_user_password
    temporary = false
  }
}

resource "keycloak_user_roles" "console_persona" {
  for_each = local.console_personas
  realm_id = keycloak_realm.pgauthz.id
  user_id  = keycloak_user.console_persona[each.key].id
  role_ids = [
    each.value.role == "console_admin" ? keycloak_role.console_admin_realm.id : keycloak_role.console_persona[each.value.role].id,
  ]
}
