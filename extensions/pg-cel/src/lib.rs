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
//!
//! Expressions compile against one environment: the CEL standard library, the
//! standard `strings`, `lists`, `math` and `encoders` extensions (as in
//! cel-go), and the IP/CIDR functions of the Kubernetes CEL library with its
//! input rules (`ip`, `cidr`, `isIP`, `isCIDR`, `containsIP`, `containsCIDR`,
//! `ip()`, `masked`, `prefixLength`, `family`, `isCanonical`, `isLoopback`,
//! `isUnspecified`, `isGlobalUnicast`, `isLinkLocalUnicast`,
//! `isLinkLocalMulticast`), so an expression here means what it means elsewhere.

use std::sync::{Arc, OnceLock};

use cel::{extensions, Context, DeclarationError, Env, Value};
use pgrx::prelude::*;

/// The environment every expression compiles and runs against; built once.
fn env() -> &'static Arc<Env> {
    static ENV: OnceLock<Arc<Env>> = OnceLock::new();
    ENV.get_or_init(|| Arc::new(build_env().expect("pg_cel: building the CEL environment")))
}

fn build_env() -> Result<Env, DeclarationError> {
    let mut env = Env::stdlib();
    env.add_extension(extensions::strings)?;
    env.add_extension(extensions::lists)?;
    env.add_extension(extensions::math)?;
    env.add_extension(extensions::encoders)?;
    env.add_extension(net::extension)?;
    Ok(env)
}

/// IP and CIDR functions, named and specified as the Kubernetes CEL library
/// has them, so a condition reads — and decides — the same as a Kubernetes
/// admission rule. Addresses and networks are strings (cel-rust has no IP
/// type): `ip()` and `cidr()` validate and return the value as written — as
/// Kubernetes keeps the original, so `isCanonical()` can tell — and the
/// member functions parse their receiver. Input rules follow Go's netip, which Kubernetes
/// uses: no surrounding whitespace, no zone, no leading zeros in an IPv4
/// octet, and no IPv4-mapped IPv6 address (`::ffff:192.0.2.1`).
mod net {
    use std::net::{IpAddr, Ipv4Addr};

    use cel::common::types::{CelBool, CelInt, CelString};
    use cel::{DeclarationError, Env, ExecutionError};
    use ipnet::IpNet;

    /// One validation for every entry point: what Kubernetes' `ip()` accepts.
    fn strict_ip(s: &str) -> Result<IpAddr, String> {
        if s != s.trim() {
            return Err(format!("{s:?} has surrounding whitespace"));
        }
        let addr = s.parse::<IpAddr>().map_err(|e| format!("{s:?} is not an IP address: {e}"))?;
        if let IpAddr::V6(v6) = addr {
            if v6.to_ipv4_mapped().is_some() {
                return Err(format!("{s:?} is an IPv4-mapped IPv6 address"));
            }
        }
        Ok(addr)
    }

    /// What Kubernetes' `cidr()` accepts: a strict address and a prefix; host
    /// bits may be set (`masked()` clears them).
    fn strict_cidr(s: &str) -> Result<IpNet, String> {
        if s != s.trim() {
            return Err(format!("{s:?} has surrounding whitespace"));
        }
        let (addr, _) = s.split_once('/').ok_or_else(|| format!("{s:?} is not a CIDR: no prefix length"))?;
        strict_ip(addr)?;
        s.parse::<IpNet>().map_err(|e| format!("{s:?} is not a CIDR: {e}"))
    }

    fn parse_ip(s: &str, fn_name: &str) -> Result<IpAddr, ExecutionError> {
        strict_ip(s).map_err(|e| ExecutionError::function_error(fn_name, e))
    }

    fn parse_cidr(s: &str, fn_name: &str) -> Result<IpNet, ExecutionError> {
        strict_cidr(s).map_err(|e| ExecutionError::function_error(fn_name, e))
    }

    fn is_ip(s: &CelString<'_>) -> CelBool {
        CelBool::from(strict_ip(s.inner()).is_ok())
    }

    fn is_cidr(s: &CelString<'_>) -> CelBool {
        CelBool::from(strict_cidr(s.inner()).is_ok())
    }

    fn ip(s: &CelString<'_>) -> Result<CelString<'static>, ExecutionError> {
        parse_ip(s.inner(), "ip")?;
        Ok(CelString::from(s.inner().to_owned()))
    }

    fn cidr(s: &CelString<'_>) -> Result<CelString<'static>, ExecutionError> {
        parse_cidr(s.inner(), "cidr")?;
        Ok(CelString::from(s.inner().to_owned()))
    }

    fn contains_ip(this: &CelString<'_>, addr: &CelString<'_>) -> Result<CelBool, ExecutionError> {
        let net = parse_cidr(this.inner(), "containsIP")?;
        let addr = parse_ip(addr.inner(), "containsIP")?;
        Ok(CelBool::from(net.contains(&addr)))
    }

    fn contains_cidr(this: &CelString<'_>, other: &CelString<'_>) -> Result<CelBool, ExecutionError> {
        let net = parse_cidr(this.inner(), "containsCIDR")?;
        let other = parse_cidr(other.inner(), "containsCIDR")?;
        Ok(CelBool::from(net.contains(&other)))
    }

    fn prefix_length(this: &CelString<'_>) -> Result<CelInt, ExecutionError> {
        Ok(CelInt::from(i64::from(parse_cidr(this.inner(), "prefixLength")?.prefix_len())))
    }

    fn masked(this: &CelString<'_>) -> Result<CelString<'static>, ExecutionError> {
        Ok(CelString::from(parse_cidr(this.inner(), "masked")?.trunc().to_string()))
    }

    fn family(this: &CelString<'_>) -> Result<CelInt, ExecutionError> {
        Ok(CelInt::from(match parse_ip(this.inner(), "family")? {
            IpAddr::V4(_) => 4,
            IpAddr::V6(_) => 6,
        }))
    }

    fn is_loopback(this: &CelString<'_>) -> Result<CelBool, ExecutionError> {
        Ok(CelBool::from(parse_ip(this.inner(), "isLoopback")?.is_loopback()))
    }

    fn is_unspecified(this: &CelString<'_>) -> Result<CelBool, ExecutionError> {
        Ok(CelBool::from(parse_ip(this.inner(), "isUnspecified")?.is_unspecified()))
    }

    /// `cidr(s).ip()`: the address part, host bits included.
    fn cidr_ip(this: &CelString<'_>) -> Result<CelString<'static>, ExecutionError> {
        Ok(CelString::from(parse_cidr(this.inner(), "ip")?.addr().to_string()))
    }

    /// `ip(s).isCanonical()`: the string is the address's canonical form.
    fn is_canonical(this: &CelString<'_>) -> Result<CelBool, ExecutionError> {
        let addr = parse_ip(this.inner(), "isCanonical")?;
        Ok(CelBool::from(addr.to_string() == this.inner()))
    }

    fn link_local_unicast(addr: IpAddr) -> bool {
        match addr {
            IpAddr::V4(v4) => v4.is_link_local(),                       // 169.254.0.0/16
            IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,    // fe80::/10
        }
    }

    fn link_local_multicast(addr: IpAddr) -> bool {
        match addr {
            IpAddr::V4(v4) => v4.octets()[..3] == [224, 0, 0],          // 224.0.0.0/24
            IpAddr::V6(v6) => (v6.segments()[0] & 0xff0f) == 0xff02,    // ff02::/16
        }
    }

    /// Go's IsGlobalUnicast, which Kubernetes exposes: not unspecified, not
    /// loopback, not multicast, not link-local unicast, not the IPv4 broadcast.
    fn global_unicast(addr: IpAddr) -> bool {
        let broadcast = addr == IpAddr::V4(Ipv4Addr::BROADCAST);
        !addr.is_unspecified() && !addr.is_loopback() && !addr.is_multicast() && !link_local_unicast(addr) && !broadcast
    }

    fn is_global_unicast(this: &CelString<'_>) -> Result<CelBool, ExecutionError> {
        Ok(CelBool::from(global_unicast(parse_ip(this.inner(), "isGlobalUnicast")?)))
    }

    fn is_link_local_unicast(this: &CelString<'_>) -> Result<CelBool, ExecutionError> {
        Ok(CelBool::from(link_local_unicast(parse_ip(this.inner(), "isLinkLocalUnicast")?)))
    }

    fn is_link_local_multicast(this: &CelString<'_>) -> Result<CelBool, ExecutionError> {
        Ok(CelBool::from(link_local_multicast(parse_ip(this.inner(), "isLinkLocalMulticast")?)))
    }

    pub fn extension(env: &mut Env) -> Result<(), DeclarationError> {
        cel::add_overload!(env, fn is_ip: (CelString) -> CelBool, name = "isIP")?;
        cel::add_overload!(env, fn is_cidr: (CelString) -> CelBool, name = "isCIDR")?;
        cel::add_overload!(env, fn ip: (CelString) -> Result<CelString>)?;
        cel::add_overload!(env, fn cidr: (CelString) -> Result<CelString>)?;
        cel::add_member_overload!(env, fn contains_ip: (CelString, CelString) -> Result<CelBool>, name = "containsIP")?;
        cel::add_member_overload!(env, fn contains_cidr: (CelString, CelString) -> Result<CelBool>, name = "containsCIDR")?;
        cel::add_member_overload!(env, fn prefix_length: (CelString) -> Result<CelInt>, name = "prefixLength")?;
        cel::add_member_overload!(env, fn masked: (CelString) -> Result<CelString>)?;
        cel::add_member_overload!(env, fn family: (CelString) -> Result<CelInt>)?;
        cel::add_member_overload!(env, fn is_loopback: (CelString) -> Result<CelBool>, name = "isLoopback")?;
        cel::add_member_overload!(env, fn is_unspecified: (CelString) -> Result<CelBool>, name = "isUnspecified")?;
        cel::add_member_overload!(env, fn cidr_ip: (CelString) -> Result<CelString>, name = "ip")?;
        cel::add_member_overload!(env, fn is_canonical: (CelString) -> Result<CelBool>, name = "isCanonical")?;
        cel::add_member_overload!(env, fn is_global_unicast: (CelString) -> Result<CelBool>, name = "isGlobalUnicast")?;
        cel::add_member_overload!(env, fn is_link_local_unicast: (CelString) -> Result<CelBool>, name = "isLinkLocalUnicast")?;
        cel::add_member_overload!(env, fn is_link_local_multicast: (CelString) -> Result<CelBool>, name = "isLinkLocalMulticast")?;
        Ok(())
    }
}

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
    match env().compile(expression) {
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
    let program = env().compile(expression).map_err(|e| format!("compile error: {e}"))?;

    let parsed: serde_json::Value =
        serde_json::from_str(json_data).map_err(|e| format!("invalid json_data: {e}"))?;
    let map = match parsed {
        serde_json::Value::Object(map) => map,
        _ => return Err("json_data must be a JSON object".to_string()),
    };

    let mut ctx = Context::with_env(env().clone());
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

    #[test]
    fn standard_extensions_are_in() {
        assert_eq!(
            eval_bool(
                "request.email.lowerAscii().endsWith(stored.domain) && math.greatest(1, 5, 3) == 5 && [3, 1, 2].sort() == [1, 2, 3]",
                r#"{"request":{"email":"Alice@Example.COM"},"stored":{"domain":"@example.com"}}"#
            )
            .unwrap(),
            Some(true)
        );
    }

    #[test]
    fn net_functions() {
        let ok = |expr: &str| eval_bool(expr, r#"{"request":{"ip":"10.1.2.3"},"stored":{"allowed":"10.0.0.0/8"}}"#).unwrap();
        assert_eq!(ok("cidr(stored.allowed).containsIP(ip(request.ip))"), Some(true));
        assert_eq!(ok("cidr('192.168.0.0/16').containsIP(request.ip)"), Some(false));
        assert_eq!(ok("isIP(request.ip) && !isIP('nope') && isCIDR(stored.allowed) && !isCIDR(request.ip)"), Some(true));
        assert_eq!(ok("cidr('10.0.0.0/8').containsCIDR('10.1.0.0/16') && !cidr('10.1.0.0/16').containsCIDR('10.0.0.0/8')"), Some(true));
        assert_eq!(ok("cidr('10.1.2.3/8').masked() == '10.0.0.0/8' && cidr(stored.allowed).prefixLength() == 8"), Some(true));
        assert_eq!(ok("ip(request.ip).family() == 4 && ip('::1').family() == 6 && ip('127.0.0.1').isLoopback() && ip('0.0.0.0').isUnspecified()"), Some(true));
        assert_eq!(ok("ip('2001:DB8:0:0:0:0:0:1') == '2001:DB8:0:0:0:0:0:1' && !ip('2001:DB8:0:0:0:0:0:1').isCanonical()"), Some(true));
        assert!(eval_bool("ip('nope') == 'x'", "{}").is_err());
        assert!(eval_bool("cidr('10.0.0.0/8').containsIP('nope')", "{}").is_err());
    }

    /// The Kubernetes library's vectors: what its `ip()`/`cidr()` reject and
    /// how its predicates decide. A disagreement here is a condition that
    /// decides differently in pgauthz than in a Kubernetes admission rule.
    #[test]
    fn net_matches_kubernetes_cel() {
        let yes = |expr: &str| assert_eq!(eval_bool(expr, "{}").unwrap(), Some(true), "{expr}");
        // input rules (Go netip): no whitespace, no IPv4-mapped IPv6, no zone, no leading zeros
        yes("!isIP(' 10.0.0.1 ') && !isIP('::ffff:192.0.2.1') && !isIP('fe80::1%eth0') && !isIP('010.0.0.1') && !isIP('')");
        yes("!isCIDR(' 10.0.0.0/8') && !isCIDR('::ffff:10.0.0.0/104') && !isCIDR('10.0.0.0') && !isCIDR('10.0.0.0/33')");
        assert!(eval_bool("ip('::ffff:192.0.2.1') == 'x'", "{}").is_err());
        assert!(eval_bool("cidr('::ffff:10.0.0.0/104') == 'x'", "{}").is_err());
        // canonical forms and isCanonical
        yes("ip('2001:db8::1').isCanonical() && !ip('2001:DB8:0:0:0:0:0:1').isCanonical() && ip('192.168.0.1').isCanonical()");
        // host bits: cidr() keeps them, ip() returns the address, masked() the network
        yes("cidr('192.168.0.1/24') == '192.168.0.1/24' && cidr('192.168.0.1/24').ip() == '192.168.0.1' && cidr('192.168.0.1/24').masked() == '192.168.0.0/24' && cidr('192.168.0.1/24').ip().family() == 4");
        // containment across families is false, never an error; equal and overlapping prefixes
        yes("!cidr('10.0.0.0/8').containsIP('2001:db8::1') && !cidr('2001:db8::/32').containsCIDR('10.0.0.0/8')");
        yes("cidr('10.0.0.0/8').containsCIDR('10.0.0.0/8') && cidr('10.0.0.0/8').containsCIDR('10.0.0.0/9') && !cidr('10.0.0.0/9').containsCIDR('10.0.0.0/8') && !cidr('10.0.0.0/9').containsCIDR('10.128.0.0/9')");
        // the address classes, as Go's net/netip decides them
        yes("ip('192.168.0.1').isGlobalUnicast() && ip('2001:db8::1').isGlobalUnicast() && !ip('127.0.0.1').isGlobalUnicast() && !ip('0.0.0.0').isGlobalUnicast() && !ip('255.255.255.255').isGlobalUnicast() && !ip('224.0.0.1').isGlobalUnicast() && !ip('169.254.1.1').isGlobalUnicast() && !ip('fe80::1').isGlobalUnicast()");
        yes("ip('169.254.1.1').isLinkLocalUnicast() && ip('fe80::1').isLinkLocalUnicast() && !ip('10.0.0.1').isLinkLocalUnicast() && !ip('fec0::1').isLinkLocalUnicast()");
        yes("ip('224.0.0.1').isLinkLocalMulticast() && ip('ff02::1').isLinkLocalMulticast() && !ip('224.0.1.1').isLinkLocalMulticast() && !ip('ff05::1').isLinkLocalMulticast()");
        yes("ip('::1').isLoopback() && ip('::').isUnspecified() && ip('::1').family() == 6");
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
