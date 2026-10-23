// The shapes the BFF answers with (console/backend/internal/server/*.go and
// pgauthzadm), as JSDoc typedefs: no runtime, only what an editor needs to
// resolve fields and catch a misspelt one. One typedef per response or row;
// request bodies are documented at their api.js call. Keep in step with the
// Go structs' json tags.

/** @typedef {Object<string, boolean>} Capabilities console relations → decision */

/**
 * @typedef {Object} Status pgauthzadm.Status — what registry version a store runs
 * @property {string} store
 * @property {string|null} model_name
 * @property {number|null} model_version
 * @property {string|null} applied_at
 * @property {string|null} applied_by
 * @property {boolean|null} in_sync
 * @property {string} live_checksum
 * @property {string|null} expected_checksum
 */

/**
 * @typedef {Object} StoreRow one store as the home table and the store header see it
 * @property {string} name
 * @property {string} description
 * @property {string} docs_url
 * @property {Object<string, Capabilities>} [namespaces] namespace → what you may do there (store header)
 * @property {string|null} created_at
 * @property {string|null} last_change_at
 * @property {Capabilities} capabilities
 * @property {Status} [status]
 * @property {{types: number, relations: number, tuples: number, conditions: number}} [counts]
 * @property {boolean} claimed
 * @property {string} [retired_at]
 */

/** @typedef {{stores: StoreRow[], unclaimed: StoreRow[], can_create: boolean}} StoreList */

/**
 * @typedef {Object} Me who is logged in (api/me)
 * @property {boolean} authenticated
 * @property {string} username
 * @property {string} name
 * @property {string} email
 * @property {string} subject
 * @property {string[]} teams
 * @property {Capabilities} platform
 * @property {Capabilities} registry
 * @property {string} console_store
 * @property {boolean} [decision_url_configured]
 * @property {{oidc: boolean, local: boolean}} [login]
 */

// ── model ──────────────────────────────────────────────────────────────────

/**
 * @typedef {Object} ModelType
 * @property {string} name
 * @property {string|null} namespace
 * @property {string|null} description
 * @property {string[]} labels
 * @property {number} hash_modulus
 */
/**
 * @typedef {Object} ModelRelation
 * @property {string} name
 * @property {string|null} description
 * @property {*} [payload_schema]
 * @property {{kind?: string, ui_order?: number, label?: string, docs_url?: string}} [metadata]
 */
/**
 * @typedef {Object} ModelRule
 * @property {number} [id] present in the editor's rows (models_view), absent in the export
 * @property {string} object_type
 * @property {string} relation
 * @property {'direct'|'computed'|'ttu'} rule_type
 * @property {string|null} computed_relation
 * @property {string|null} tupleset_relation
 * @property {string|null} tupleset_computed
 * @property {number} group_id
 * @property {'or'|'intersection'|'exclusion'} group_op
 * @property {boolean} negated
 * @property {boolean} allow_object_wildcard
 */
/**
 * @typedef {Object} TypeRestriction
 * @property {number} [id]
 * @property {string} object_type
 * @property {string} relation
 * @property {string} allowed_user_type
 * @property {string|null} allowed_user_relation
 * @property {boolean} allow_wildcard
 * @property {string|null} [condition]
 */
/**
 * @typedef {Object} Condition
 * @property {string} name
 * @property {string} expression
 * @property {string} lang
 * @property {*} required_context
 * @property {string} [time_source]
 * @property {string} [description]
 */
/**
 * @typedef {Object} GateSpec
 * @property {Object[]} all_of
 * @property {string} [description]
 * @property {'enforce'|'shadow'|'off'} [mode]
 */
/** @typedef {{object_type: string, relation: string, name: string, spec: GateSpec}} Gate */
/** @typedef {{object_type: string, relation: string, requires: string, requires_revoke: string|null}} GrantRule */
/**
 * @typedef {Object} ModelExport pgauthzadm.Model — authz.export_model
 * @property {number} format
 * @property {ModelType[]} types
 * @property {ModelRelation[]} relations
 * @property {ModelRule[]} rules
 * @property {TypeRestriction[]} type_restrictions
 * @property {Condition[]} conditions
 * @property {Gate[]} gates
 * @property {GrantRule[]} grant_rules
 */
/**
 * @typedef {Object} ModelResponse api/stores/{store}/model
 * @property {string} dsl
 * @property {ModelExport} json
 * @property {string} sql
 * @property {ModelRule[]} rules with ids
 * @property {TypeRestriction[]} restrictions with ids
 * @property {Object<string, {created_at: string, updated_at: string}>} condition_times
 */
/**
 * @typedef {Object} DSLReport pgauthzadm.ImportReport
 * @property {string} store
 * @property {string[]} types
 * @property {string[]} relations
 * @property {number} rules_imported
 * @property {number} rules_replaced
 * @property {number} type_restrictions_imported
 * @property {string[]} placeholder_conditions
 * @property {string[]} warnings
 */

// ── data ───────────────────────────────────────────────────────────────────

/**
 * @typedef {Object} TupleRow
 * @property {string} user_type
 * @property {string} user_id
 * @property {string} user_relation
 * @property {string} relation
 * @property {string} object_type
 * @property {string} object_id
 * @property {string} [condition_name] the tuples listing
 * @property {string} [condition] the import preview and the export
 * @property {*} [condition_context]
 * @property {string|null} [expires_at]
 */
/** @typedef {{tuples: TupleRow[], limit: number, offset: number, total: number}} TupleList */
/**
 * @typedef {Object} TupleStats authz.tuple_stats
 * @property {number} total
 * @property {number} with_expiry
 * @property {number} expiring_24h
 * @property {number} [expired]
 * @property {number} wildcard_subject
 * @property {number} wildcard_object
 * @property {number} conditional
 * @property {number} usersets
 * @property {number} [subjects]
 * @property {number} [objects]
 * @property {Object<string, number>} [by_object_type]
 */
/** @typedef {{count: number, shape: string, object_types: string[], preview: TupleRow[], applied: false}} ImportPreview */
/** @typedef {{count: number, shape: string, written: number, applied: true}} ImportResult */
/** @typedef {{count: number, applied: boolean, removed?: number}} OffboardResult */
/** @typedef {{relation: string, can_grant: boolean, can_revoke: boolean, requires: string, requires_revoke: string, grantee_types: string[]}} GrantOption */
/** @typedef {{relation: string, user_type: string, user_id: string, user_relation: string, condition_name: string, expires_at: string|null}} HolderRow */
/** @typedef {{object_type: string, object_id: string, actor_type: string, actor_id: string}} ShareObject */
/** @typedef {{yaml: string, updated_at: string|null, updated_by: string, can_edit: boolean, cases: number}} Scenarios the store's saved tests.authz.yaml */
/** @typedef {{name: string, failed: boolean, detail?: string, test: number, note?: string, kind: 'check'|'list_objects'|'list_subjects'|'list_actions'|'explain', user: string, relation: string, object: string, expected: string[], actual?: string[]}} ScenarioResult test = index of the fixture's tests: entry; kind/user/relation/object = what was asserted (object = the type for list_objects) */
/** @typedef {{results: ScenarioResult[], passed: number, failed: number, duration_ms: number}} ScenariosRun */
/** @typedef {{store: string, yaml: string, model_fga?: string, command: string}} ScenariosExport the fixture for pgauthzctl, model_file filled in, the model as DSL */
/** @typedef {{object: ShareObject, options: GrantOption[], holders: HolderRow[], holder_totals: Record<string, number>, holders_limit: number}} ShareOptions the share dialog: what the actor may grant and revoke, who holds what (live tuples of the offered relations, at most holders_limit per relation; holder_totals has every relation's full count) */

// ── test ───────────────────────────────────────────────────────────────────

/** @typedef {{name: string, kind: 'relation'|'permission', direct: boolean, derived: boolean}} RelInfo */
/**
 * @typedef {Object} Meta api/stores/{store}/meta — what the Test tab offers
 * @property {Object<string, RelInfo[]>} relations_by_type
 * @property {string[]} types
 * @property {string[]} relations
 * @property {string[]} subjects type:id
 * @property {string[]} objects type:id
 */
/** @typedef {{subject: string, action: string, resource: string, allowed: boolean}} BatchCell */
/**
 * @typedef {Object} DecideDetail pgauthzd's decision envelope ("as me via pgauthzd")
 * @property {string} [via] engine | opa
 * @property {string} [policy]
 * @property {string} [reason]
 * @property {string[]} [hooks_loaded]
 * @property {Object[]} [hook_denials]
 * @property {string[]} [missing_context]
 * @property {string} [state] allow | deny | conditional
 */
/** @typedef {{decision: boolean, detail: DecideDetail, subject: {type: string, id: string}, url: string}} DecideResponse */
/** @typedef {{id: string, wildcard: boolean}} SearchHit */

// ── activity ───────────────────────────────────────────────────────────────

/**
 * @typedef {Object} AuditRow a relationship change (tuples_audit)
 * @property {string} action INSERT | DELETE
 * @property {string} performed_at
 * @property {string} performed_by
 * @property {string} user_type
 * @property {string} user_id
 * @property {string} user_relation
 * @property {string} relation
 * @property {string} object_type
 * @property {string} object_id
 * @property {*} condition_context
 */
/**
 * @typedef {Object} EventRow the action log (list_events)
 * @property {number} seq
 * @property {string} subject_type
 * @property {string} subject_id
 * @property {string} action
 * @property {string} object_type
 * @property {string} object_id
 * @property {string} kind
 * @property {Object<string, *>} payload
 * @property {string} occurred_at
 * @property {string} recorded_by
 */
/**
 * @typedef {Object} ModelChangeRow the model change history
 * @property {number} seq
 * @property {'rule'|'condition'|'gate'|'grant_rule'} kind
 * @property {string} action INSERT | DELETE
 * @property {string} performed_at
 * @property {string} performed_by
 * @property {string} object_type
 * @property {string} relation
 * @property {string} name
 * @property {Object<string, *>} detail
 */
/** @typedef {{audit: AuditRow[], model: ModelChangeRow[], events: EventRow[], console: EventRow[], retired: boolean}} ActivityResponse */

// ── access ─────────────────────────────────────────────────────────────────

/** @typedef {{subject_type: string, subject_id: string, subject_relation: string, role: string, subject: string}} AccessRow */
/** @typedef {{access: AccessRow[], roles: string[], can_manage: boolean, teams: string[]}} AccessResponse */
/** @typedef {{namespaces: {name: string, access: AccessRow[]}[], roles: string[], can_manage: boolean}} NamespacesResponse */

// ── registry and rollout ───────────────────────────────────────────────────

/** @typedef {{name: string, version: number, checksum: string, description: string, created_at: string, created_by: string}} Version */
/** @typedef {{store: string, model_version: number, latest_version: number, in_sync: boolean, applied_at: string|null}} RolloutRow */
/** @typedef {{name: string, versions: Version[], fleet: RolloutRow[]}} RegistryModel */
/** @typedef {{models: RegistryModel[], can_publish: boolean}} RegistryResponse */
/** @typedef {{status: Status, versions: Version[], fleet: RolloutRow[], can_rollout: boolean}} RolloutResponse */
/** @typedef {{plan: Object, changes: Object[], blockers: Object[], can_apply: boolean, since: Object|null, since_label: string}} PlanResponse */

// ── operations ─────────────────────────────────────────────────────────────

/**
 * @typedef {Object} Readiness authz.events_readiness row
 * @property {string} store
 * @property {number} gates
 * @property {number} gates_enforce
 * @property {number} gates_shadow
 * @property {number} gates_off
 * @property {string|null} max_gate_window
 * @property {string|null} history_since
 * @property {boolean} history_covers_gates
 * @property {string|null} history_deficit
 * @property {string|null} oldest_event_at
 * @property {string|null} newest_event_at
 * @property {string|null} last_recorded_at
 * @property {number} events_1h
 * @property {string|null} max_recording_delay_1h
 * @property {string[]} recorders_24h
 */
/** @typedef {{object_type: string, relation: string, gate: string, clause: string, window: string}} GateWindow */
/** @typedef {{db_role: string, actions: string[]}} RecorderRow */
/** @typedef {{parent: string, name: string, bound: string, bytes: number, default: boolean}} PartitionRow */
/**
 * @typedef {Object} DerivedStatus authz.materialized_relations_status row
 * @property {string} store
 * @property {string} as_of
 * @property {string} staleness
 * @property {boolean} feed_drained
 * @property {number} pending_due
 * @property {number} pending_deferred
 * @property {string|null} last_run_started_at
 * @property {string|null} last_run_finished_at
 * @property {number} last_run_changes
 * @property {number} last_run_pairs
 * @property {number} last_run_rows_written
 * @property {string|null} last_run_gate
 * @property {string|null} oldest_open_txn_age
 */
/**
 * @typedef {Object} OpsOverview api/stores/{store}/ops
 * @property {boolean} retired
 * @property {Readiness|null} readiness
 * @property {GateWindow[]} gate_windows
 * @property {RecorderRow[]} recorders
 * @property {TupleStats|null} tuple_stats
 * @property {{cursor_at: string|null, cursor_seq: number|null, safe_until: string}} changefeed
 * @property {{installed: boolean, status?: DerivedStatus, error?: string}} derived
 * @property {PartitionRow[]} partitions
 * @property {string[]} login_roles
 */
/** @typedef {{tuples: TupleRow[], more?: boolean, removed?: number, applied: boolean}} RedundantResult */
/**
 * @typedef {Object} OpsForm the Operations tab's inputs
 * @property {string} [rec_role]
 * @property {string} [rec_actions]
 * @property {string} [grace]
 * @property {string} [red_type]
 * @property {string} [red_rel]
 * @property {string} [purge_before]
 * @property {boolean} [purge_force]
 */
/**
 * @typedef {Object} OpsResults the last outcome per action
 * @property {{granted?: number, revoked?: number}} [recorder]
 * @property {{removed: number}} [expired]
 * @property {{purged: number}} [purge]
 * @property {RedundantResult} [redundant]
 */
/**
 * @typedef {Object} PlatformOps api/platform/ops
 * @property {PartitionRow[]} partitions
 * @property {Readiness[]} readiness
 * @property {string|null} max_gate_window
 * @property {{store: string, tuples: number, bytes: number}[]} store_sizes
 * @property {string} safe_until
 * @property {string} now
 */
/** @typedef {{audit_created?: number, events_created?: number, dropped?: number}} FleetResult */

// ── platform and policies ──────────────────────────────────────────────────

/**
 * @typedef {Object} PlatformInfo api/platform
 * @property {string} environment
 * @property {string} issuer
 * @property {string} client_id
 * @property {string} console_store
 * @property {string} platform_id
 * @property {string} registry_id
 * @property {string} subject_type
 * @property {{prefix: string, claim: string}[]} team_claims
 * @property {{ok: boolean, version?: string, role?: string, stores?: number, error?: string}} engine
 * @property {{url: string, ok: boolean, status?: number, error?: string}} [pgauthzd]
 */
/** @typedef {{id: string, package: string, name: string, raw: string}} PolicyInfo */
/** @typedef {{configured: boolean, error?: string, opa?: Object, global: PolicyInfo[], store: PolicyInfo[], libs: PolicyInfo[], platform: PolicyInfo[], contract: string}} PoliciesResponse */

export {};
