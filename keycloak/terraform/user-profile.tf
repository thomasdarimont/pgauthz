# ─── Declarative User Profile ─────────────────────────────────────────────────
# Keycloak 24+ enables the declarative user profile by default and DROPS any user
# attribute not declared here (or allowed as "unmanaged"). Without this, the
# subject_type / db_role attributes set on the demo users are silently lost, their
# protocol mappers emit nothing, and e.g. carol (client_user) is treated as
# internal_user → wrong authorization decisions.
#
# Display names use Keycloak message-bundle keys ($${...} is an escaped ${...} so
# Terraform does not interpolate it); the bundles live in localization.tf.

resource "keycloak_realm_user_profile" "pgauthz" {
  realm_id = keycloak_realm.pgauthz.id

  unmanaged_attribute_policy = "ENABLED"

  attribute {
    name         = "username"
    display_name = "$${username}"
    multi_valued = false

    validator {
      name = "length"
      config = {
        min = "3"
        max = "255"
      }
    }
    validator {
      name = "username-prohibited-characters"
    }
    validator {
      name = "up-username-not-idn-homograph"
    }

    permissions {
      view = ["admin", "user"]
      edit = ["admin", "user"]
    }
  }

  attribute {
    name               = "email"
    display_name       = "$${email}"
    multi_valued       = false
    required_for_roles = ["user"]

    validator {
      name = "email"
    }
    validator {
      name = "length"
      config = {
        max = "255"
      }
    }

    permissions {
      view = ["admin", "user"]
      edit = ["admin"]
    }
  }

  attribute {
    name         = "firstName"
    display_name = "$${firstName}"
    multi_valued = false

    validator {
      name = "length"
      config = {
        max = "255"
      }
    }
    validator {
      name = "person-name-prohibited-characters"
    }

    permissions {
      view = ["admin", "user"]
      edit = ["admin"]
    }
  }

  attribute {
    name         = "lastName"
    display_name = "$${lastName}"
    multi_valued = false

    validator {
      name = "length"
      config = {
        max = "255"
      }
    }
    validator {
      name = "person-name-prohibited-characters"
    }

    permissions {
      view = ["admin", "user"]
      edit = ["admin"]
    }
  }

  # pgauthz reads this from the token (internal_user / client_user). authn.rego
  # defaults to internal_user when absent, so it is intentionally NOT required.
  attribute {
    name         = "subject_type"
    display_name = "$${profile.attributes.subject_type}"
    group        = "pgauthz-attributes"
    multi_valued = false

    validator {
      name = "options"
      config = {
        options = jsonencode(["internal_user", "client_user"])
      }
    }

    permissions {
      view = ["admin", "user"]
      edit = ["admin"]
    }
  }

  group {
    name           = "pgauthz-attributes"
    display_header = "$${profile.attribute-group.pgauthz-attributes}"
  }
}
