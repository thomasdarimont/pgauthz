# ─── Realm Localization (messageBundles) ──────────────────────────────────────
# Message bundle backing the user-profile display names / attribute group header
# (see user-profile.tf). $${...} in display_name resolves to these keys.

locals {
  # Keys with the same value in every locale.
  pgauthz_message_bundle_common = {
    "profile.attribute-group.pgauthz-attributes" = "pgauthz"
    "profile.attributes.subject_type"            = "Authz subject type"
  }

  # Locale-specific overrides, merged on top of the common bundle. Empty for now;
  # add translations here without touching the shared keys.
  pgauthz_message_bundle_locale = {
    en = {}
    de = {}
  }
}

resource "keycloak_realm_localization" "pgauthz" {
  for_each = local.pgauthz_message_bundle_locale

  realm_id = keycloak_realm.pgauthz.id
  locale   = each.key
  texts    = merge(local.pgauthz_message_bundle_common, each.value)
}
