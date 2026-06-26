//! pg_cel — CEL (Common Expression Language) evaluation for PostgreSQL,
//! built with pgrx so a fault aborts the *transaction* (not the server).
//!
//! It exposes the minimal function contract pgauthz's condition dispatcher
//! (`authz._eval_condition_expr`) depends on:
//!
//!   cel_eval_bool(expression text, json_data text) -> boolean
//!   cel_compile_check(expression text)             -> boolean
//!
//! pgauthz calls `cel_eval_bool(expr, '{"request":{...},"stored":{...}}')`, so
//! CEL expressions reference the two context bags as `request.*` and `stored.*`,
//! e.g. `timestamp(request.current_time) < timestamp(stored.expires)`.
//!
//! The contract intentionally matches SPANDigital/pg-cel (cgo + cel-go), so the
//! two are interchangeable from pgauthz's point of view; this crate is the
//! Rust/pgrx implementation pgauthz ships for the safer failure mode.

use cel::{Context, Program, Value};
use pgrx::prelude::*;

::pgrx::pg_module_magic!();

/// Evaluate a CEL expression to a boolean.
///
/// `json_data` must be a JSON object; its top-level keys become CEL variables.
/// Returns NULL when the expression yields a non-boolean (pgauthz treats NULL
/// as deny — fail closed). Raises on a compile/evaluation error, which pgauthz's
/// callers catch and also turn into a deny.
#[pg_extern(immutable, strict, parallel_safe)]
fn cel_eval_bool(expression: &str, json_data: &str) -> Option<bool> {
    match eval_bool(expression, json_data) {
        Ok(result) => result,
        Err(e) => error!("pg_cel: {e}"),
    }
}

/// Compile-check a CEL expression without evaluating it. Returns true if it
/// parses; raises otherwise. pgauthz calls this at condition write time so a
/// malformed expression is rejected up front rather than denying at check time.
///
/// This is a PARSE check only — it verifies syntax, not variable bindings,
/// types, or value formats (CEL is dynamically typed and the context is
/// arbitrary JSON). Undeclared-variable references, type mismatches, and bad
/// value formats (e.g. a Postgres interval `"2 hours"` passed to CEL
/// `duration()`, which wants `"2h"`) surface at evaluation time and deny
/// (fail closed). Use authz.validate_condition with representative request /
/// stored context to exercise those before relying on the condition.
#[pg_extern(immutable, strict, parallel_safe)]
fn cel_compile_check(expression: &str) -> bool {
    match Program::compile(expression) {
        Ok(_) => true,
        Err(e) => error!("pg_cel: compile error: {e}"),
    }
}

// ---------------------------------------------------------------------------
// Pure logic (no Postgres symbols) — unit-testable with plain #[test].
// ---------------------------------------------------------------------------

/// Compile + evaluate, mapping a boolean result to Some/None and anything else
/// to None. Errors are returned as strings for the pg_extern wrappers to raise.
fn eval_bool(expression: &str, json_data: &str) -> Result<Option<bool>, String> {
    match evaluate(expression, json_data)? {
        Value::Bool(b) => Ok(Some(b)),
        _ => Ok(None),
    }
}

fn evaluate(expression: &str, json_data: &str) -> Result<Value, String> {
    let program = Program::compile(expression).map_err(|e| format!("compile error: {e}"))?;

    let parsed: serde_json::Value =
        serde_json::from_str(json_data).map_err(|e| format!("invalid json_data: {e}"))?;
    let map = match parsed {
        serde_json::Value::Object(map) => map,
        _ => return Err("json_data must be a JSON object".to_string()),
    };

    let mut ctx = Context::default();
    for (key, value) in map {
        // serde_json::Value binds via the blanket Serialize -> TryIntoValue impl.
        ctx.add_variable(key.as_str(), value)
            .map_err(|e| format!("binding variable '{key}': {e:?}"))?;
    }

    program
        .execute(&ctx)
        .map_err(|e| format!("evaluation error: {e}"))
}

#[cfg(any(test, feature = "pg_test"))]
#[pg_schema]
mod tests {
    use super::*;

    // Pure CEL logic — no Postgres symbols, so plain #[test] per the
    // cargo-pgrx boundary rules.
    #[test]
    fn bool_true() {
        assert_eq!(
            eval_bool("request.age >= 18", r#"{"request":{"age":21}}"#).unwrap(),
            Some(true)
        );
    }

    #[test]
    fn bool_false() {
        assert_eq!(
            eval_bool("request.age >= 18", r#"{"request":{"age":10}}"#).unwrap(),
            Some(false)
        );
    }

    #[test]
    fn two_bags_request_and_stored() {
        assert_eq!(
            eval_bool(
                "request.amount <= stored.limit",
                r#"{"request":{"amount":40},"stored":{"limit":100}}"#
            )
            .unwrap(),
            Some(true)
        );
    }

    #[test]
    fn non_boolean_is_none() {
        assert_eq!(eval_bool("1 + 1", "{}").unwrap(), None);
    }

    #[test]
    fn bad_expression_errors() {
        assert!(eval_bool("1 +", "{}").is_err());
    }

    // Postgres-level checks through SPI — need a live backend, so #[pg_test].
    #[pg_test]
    fn pg_eval_bool_true() {
        let v = Spi::get_one::<bool>(
            r#"SELECT cel_eval_bool('stored.x < 5', '{"stored":{"x":3}}')"#,
        )
        .unwrap();
        assert_eq!(v, Some(true));
    }

    #[pg_test]
    fn pg_eval_bool_non_boolean_is_null() {
        let v = Spi::get_one::<bool>(r#"SELECT cel_eval_bool('1 + 1', '{}')"#).unwrap();
        assert_eq!(v, None);
    }

    #[pg_test]
    fn pg_compile_check_ok() {
        let v = Spi::get_one::<bool>("SELECT cel_compile_check('1 == 1')").unwrap();
        assert_eq!(v, Some(true));
    }
}

/// Required boilerplate for `cargo pgrx test`.
#[cfg(test)]
pub mod pg_test {
    pub fn setup(_options: Vec<&str>) {}

    pub fn postgresql_conf_options() -> Vec<&'static str> {
        vec![]
    }
}
