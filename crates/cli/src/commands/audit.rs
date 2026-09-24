use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};

use clap::Args;
use quote::ToTokens;
use serde::{Deserialize, Serialize};
use syn::visit::{self, Visit};
use syn::{BinOp, Expr, FnArg, ImplItemFn, ItemFn, Local, Pat, Signature, Type};
use walkdir::WalkDir;

use super::CliError;

/// Arguments for `soroban-testkit audit`.
#[derive(Args)]
pub struct AuditArgs {
    /// Path to the contract crate to audit (its `.rs` files are scanned
    /// recursively), or `-` to scan Rust source from stdin.
    #[arg(value_name = "PATH", default_value = ".")]
    path: PathBuf,
    /// Exit non-zero if any findings are reported.
    #[arg(long)]
    strict: bool,
}

/// Configuration for audit rules, loaded from `.soroban-testkit.toml` or
/// `soroban-testkit.toml` in the repository root.
#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct AuditConfig {
    #[serde(default)]
    pub rules: HashMap<String, RuleConfig>,
}

/// Per-rule configuration.
#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct RuleConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    pub severity: Option<String>,
}

fn default_enabled() -> bool {
    true
}

struct Finding {
    file: PathBuf,
    line: usize,
    rule: &'static str,
    severity: String,
    message: String,
}

/// Static checks over a contract crate. **Not a security product** — a
/// linter with four heuristics, each independently useful and each
/// capable of missing real bugs or flagging non-bugs. The absence of a
/// finding here is never a security guarantee.
///
/// 1. Entry points taking an `Address` parameter that never call
///    `require_auth` anywhere in the function body.
/// 2. Arithmetic (`+ - * /`) on an explicitly `i128`-typed binding, done
///    outside a `checked_`/`saturating_`/`wrapping_` call.
/// 3. A `.persistent()`/`.temporary()` storage read with no
///    `.extend_ttl(` call anywhere in the same function.
/// 4. Broad use of `mock_all_auths` in test functions.
pub fn run(args: AuditArgs) -> Result<(), CliError> {
    let config = load_config(&args.path)?;
    let mut findings = Vec::new();

    if args.path == Path::new("-") {
        let mut source = String::new();
        std::io::stdin()
            .read_to_string(&mut source)
            .map_err(|err| CliError(format!("failed to read stdin: {err}")))?;
        audit_source(Path::new("<stdin>"), &source, &mut findings, &config)?;
    } else {
        for entry in WalkDir::new(&args.path).into_iter().filter_map(Result::ok) {
            if !entry.file_type().is_file() {
                continue;
            }
            if entry.path().extension().is_none_or(|ext| ext != "rs") {
                continue;
            }
            audit_file(entry.path(), &mut findings, &config)?;
        }
    }

    if findings.is_empty() {
        println!("audit: no findings");
    } else {
        for finding in &findings {
            println!(
                "{}:{}: [{}] {}: {}",
                finding.file.display(),
                finding.line,
                finding.severity,
                finding.rule,
                finding.message
            );
        }
        println!(
            "\n{} finding(s). soroban-testkit audit is a linter with four heuristics, not a \
             security product — a missing finding is not a security guarantee.",
            findings.len()
        );
    }

    if args.strict && !findings.is_empty() {
        return Err(CliError(format!(
            "{} audit finding(s) (--strict)",
            findings.len()
        )));
    }
    Ok(())
}

fn load_config(root: &Path) -> Result<AuditConfig, CliError> {
    let config_paths = [
        root.join(".soroban-testkit.toml"),
        root.join("soroban-testkit.toml"),
    ];

    for path in &config_paths {
        if path.exists() {
            let content = std::fs::read_to_string(path)
                .map_err(|err| CliError(format!("failed to read {}: {err}", path.display())))?;
            let config = toml::from_str(&content)
                .map_err(|err| CliError(format!("failed to parse {}: {err}", path.display())))?;
            return Ok(config);
        }
    }

    Ok(AuditConfig::default())
}

fn audit_file(path: &Path, findings: &mut Vec<Finding>, config: &AuditConfig) -> Result<(), CliError> {
    let src = std::fs::read_to_string(path)
        .map_err(|err| CliError(format!("failed to read {}: {err}", path.display())))?;
    audit_source(path, &src, findings, config)
}

fn audit_source(path: &Path, src: &str, findings: &mut Vec<Finding>, config: &AuditConfig) -> Result<(), CliError> {
    let file = match syn::parse_file(src) {
        Ok(file) => file,
        Err(_) => return Ok(()), // Not every .rs file under a crate root need parse standalone.
    };

    let mut visitor = FunctionVisitor {
        path: path.to_path_buf(),
        findings,
        config,
    };
    visitor.visit_file(&file);
    Ok(())
}

struct FunctionVisitor<'a> {
    path: PathBuf,
    findings: &'a mut Vec<Finding>,
    config: &'a AuditConfig,
}

impl<'ast> Visit<'ast> for FunctionVisitor<'_> {
    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        let line = line_of(node);
        let fn_name = node.sig.ident.to_string();
        let body_src = node.to_token_stream().to_string();
        self.audit_function(&node.sig, body_src.clone(), line, &fn_name);
        self.audit_i128_arithmetic(&node.sig, &node.block, line);
        self.audit_mock_all_auths(&node.sig, &body_src, line, &fn_name);
        visit::visit_item_fn(self, node);
    }

    fn visit_impl_item_fn(&mut self, node: &'ast ImplItemFn) {
        let line = line_of(node);
        let fn_name = node.sig.ident.to_string();
        let body_src = node.to_token_stream().to_string();
        self.audit_function(&node.sig, body_src.clone(), line, &fn_name);
        self.audit_i128_arithmetic(&node.sig, &node.block, line);
        self.audit_mock_all_auths(&node.sig, &body_src, line, &fn_name);
        visit::visit_impl_item_fn(self, node);
    }
}

impl FunctionVisitor<'_> {
    fn audit_function(&mut self, sig: &Signature, body_src: String, line: usize, fn_name: &str) {
        let name = sig.ident.to_string();

        // Rule 1: an Address parameter that's never checked with require_auth.
        if self.is_enabled("missing-require-auth") {
            let address_params = address_typed_params(sig);
            if !address_params.is_empty() && !body_src.contains("require_auth") {
                self.push(
                    line,
                    "missing-require-auth",
                    "warning",
                    format!(
                        "fn {name} takes Address parameter(s) {address_params:?} but never calls \
                         require_auth in its body"
                    ),
                );
            }
        }

        // Rule 3: a storage read with no extend_ttl anywhere in the function.
        if self.is_enabled("missing-ttl-bump") {
            let reads_persistent = body_src.contains(". persistent () . get (");
            let reads_temporary = body_src.contains(". temporary () . get (");
            if (reads_persistent || reads_temporary) && !body_src.contains(". extend_ttl (") {
                self.push(
                    line,
                    "missing-ttl-bump",
                    "warning",
                    format!(
                        "fn {name} reads from {} storage but never calls extend_ttl in its body",
                        if reads_persistent {
                            "persistent"
                        } else {
                            "temporary"
                        }
                    ),
                );
            }
        }
    }

    fn audit_mock_all_auths(&mut self, sig: &Signature, body_src: &str, line: usize, fn_name: &str) {
        if !self.is_enabled("broad-mock-all-auths") {
            return;
        }

        let is_test = fn_name.contains("test") || body_src.contains("#[test]");
        if !is_test {
            return;
        }

        if body_src.contains("mock_all_auths") {
            self.push(
                line,
                "broad-mock-all-auths",
                "warning",
                format!(
                    "test function {fn_name} uses mock_all_auths; prefer granular auth checks per caller"
                ),
            );
        }
    }

    fn is_enabled(&self, rule: &str) -> bool {
        self.config
            .rules
            .get(rule)
            .map(|r| r.enabled)
            .unwrap_or(true)
    }

    fn push(&mut self, line: usize, rule: &'static str, default_severity: &'static str, message: String) {
        if !self.is_enabled(rule) {
            return;
        }

        let severity = self.config
            .rules
            .get(rule)
            .and_then(|r| r.severity.as_deref())
            .unwrap_or(default_severity);

        self.findings.push(Finding {
            file: self.path.clone(),
            line,
            rule,
            severity: severity.to_string(),
            message,
        });
    }

    fn audit_i128_arithmetic(&mut self, sig: &Signature, body: &syn::Block, line: usize) {
        if !self.is_enabled("unchecked-i128-arithmetic") {
            return;
        }

        let mut i128_bindings: HashSet<String> = HashSet::new();
        for arg in &sig.inputs {
            if let FnArg::Typed(pat_type) = arg {
                if type_is_i128(&pat_type.ty) {
                    if let Pat::Ident(ident) = &*pat_type.pat {
                        i128_bindings.insert(ident.ident.to_string());
                    }
                }
            }
        }

        let mut visitor = I128ArithmeticVisitor {
            path: self.path.clone(),
            fn_name: sig.ident.to_string(),
            fn_line: line,
            i128_bindings,
            findings: self.findings,
            config: self.config,
        };
        visitor.visit_block(body);
    }
}

fn address_typed_params(sig: &Signature) -> Vec<String> {
    sig.inputs
        .iter()
        .filter_map(|arg| match arg {
            FnArg::Typed(pat_type) if type_is_address(&pat_type.ty) => match &*pat_type.pat {
                Pat::Ident(ident) => Some(ident.ident.to_string()),
                _ => Some("<pattern>".to_string()),
            },
            _ => None,
        })
        .collect()
}

fn type_is_address(ty: &Type) -> bool {
    match ty {
        Type::Reference(r) => type_is_address(&r.elem),
        Type::Path(p) => p
            .path
            .segments
            .last()
            .is_some_and(|seg| seg.ident == "Address"),
        _ => false,
    }
}

fn line_of(node: impl quote::ToTokens) -> usize {
    node.to_token_stream()
        .into_iter()
        .next()
        .map(|t| t.span().start().line)
        .unwrap_or(0)
}

/// Rule 2 uses a dedicated AST walk (rather than a text search) because
/// "arithmetic on an i128" needs to know which bindings are actually
/// typed `i128`, and a plain string search over the token stream can't
/// tell an `i128` value from the substring appearing anywhere else.
struct I128ArithmeticVisitor<'a> {
    path: PathBuf,
    fn_name: String,
    fn_line: usize,
    i128_bindings: HashSet<String>,
    findings: &'a mut Vec<Finding>,
    config: &'a AuditConfig,
}

impl<'ast> Visit<'ast> for I128ArithmeticVisitor<'_> {
    fn visit_local(&mut self, node: &'ast Local) {
        if let Pat::Type(pat_type) = &node.pat {
            if type_is_i128(&pat_type.ty) {
                if let Pat::Ident(ident) = &*pat_type.pat {
                    self.i128_bindings.insert(ident.ident.to_string());
                }
            }
        }
        visit::visit_local(self, node);
    }

    fn visit_expr_binary(&mut self, node: &'ast syn::ExprBinary) {
        let is_arith = matches!(
            node.op,
            BinOp::Add(_) | BinOp::Sub(_) | BinOp::Mul(_) | BinOp::Div(_)
        );
        if is_arith && (self.touches_i128(&node.left) || self.touches_i128(&node.right)) {
            let severity = self.config
                .rules
                .get("unchecked-i128-arithmetic")
                .and_then(|r| r.severity.as_deref())
                .unwrap_or("warning");

            self.findings.push(Finding {
                file: self.path.clone(),
                line: self.fn_line,
                rule: "unchecked-i128-arithmetic",
                severity: severity.to_string(),
                message: format!(
                    "fn {} does raw arithmetic on an i128 value; prefer checked_/saturating_/ \
                     wrapping_ variants to avoid silent overflow",
                    self.fn_name
                ),
            });
        }
        visit::visit_expr_binary(self, node);
    }
}

impl I128ArithmeticVisitor<'_> {
    fn touches_i128(&self, expr: &Expr) -> bool {
        match expr {
            Expr::Path(p) => p
                .path
                .get_ident()
                .is_some_and(|ident| self.i128_bindings.contains(&ident.to_string())),
            Expr::Lit(lit) => matches!(&lit.lit, syn::Lit::Int(i) if i.suffix() == "i128"),
            Expr::Paren(p) => self.touches_i128(&p.expr),
            Expr::Group(g) => self.touches_i128(&g.expr),
            _ => false,
        }
    }
}

fn type_is_i128(ty: &Type) -> bool {
    matches!(ty, Type::Path(p) if p.path.is_ident("i128"))
}

#[cfg(test)]
mod tests {
    use super::*;

<<<<<<< HEAD
    fn audit_source_for_test(source: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        audit_source(Path::new("<test>"), source, &mut findings).unwrap();
        findings
    }

    #[test]
    fn macro_expanded_entry_point_is_scanned() {
        let findings = audit_source_for_test(
            r#"
            #[contract]
            pub struct Contract;
            #[contractimpl]
            impl Contract {
                pub fn transfer(env: Env, from: Address) {
                    env.storage().instance().set(&from, &1i128);
                }
            }
            "#,
        );
        assert!(findings
            .iter()
            .any(|finding| finding.rule == "missing-require-auth"));
    }

    #[test]
    fn authorized_macro_entry_point_has_no_auth_finding() {
        let findings = audit_source_for_test(
            r#"
            #[contractimpl]
            impl Contract {
                pub fn transfer(env: Env, from: Address) {
                    from.require_auth();
                }
            }
            "#,
        );
        assert!(!findings
            .iter()
            .any(|finding| finding.rule == "missing-require-auth"));
    }

    #[test]
    fn empty_source_is_a_clean_edge_case() {
        assert!(audit_source_for_test("").is_empty());
=======
    #[test]
    fn test_config_default_enabled() {
        let config = AuditConfig::default();
        assert!(config.rules.is_empty());
    }

    #[test]
    fn test_config_rule_disabled() {
        let mut rules = HashMap::new();
        rules.insert(
            "missing-require-auth".to_string(),
            RuleConfig {
                enabled: false,
                severity: None,
            },
        );
        let config = AuditConfig { rules };
        assert!(!config.rules["missing-require-auth"].enabled);
    }

    #[test]
    fn test_config_severity_override() {
        let mut rules = HashMap::new();
        rules.insert(
            "missing-require-auth".to_string(),
            RuleConfig {
                enabled: true,
                severity: Some("error".to_string()),
            },
        );
        let config = AuditConfig { rules };
        assert_eq!(
            config.rules["missing-require-auth"].severity,
            Some("error".to_string())
        );
    }

    #[test]
    fn test_missing_require_auth_detected() {
        let mut findings = Vec::new();
        let config = AuditConfig::default();

        let code = r#"
            pub fn withdraw(env: &Env, caller: &Address, amount: i128) {
                env.storage().persistent().set(&"amount", &amount);
            }
        "#;

        let file = syn::parse_file(code).unwrap();
        let mut visitor = FunctionVisitor {
            path: PathBuf::from("test.rs"),
            findings: &mut findings,
            config: &config,
        };
        visitor.visit_file(&file);

        assert!(!findings.is_empty());
        assert_eq!(findings[0].rule, "missing-require-auth");
    }

    #[test]
    fn test_mock_all_auths_detected() {
        let mut findings = Vec::new();
        let config = AuditConfig::default();

        let code = r#"
            #[test]
            fn test_broad_auth() {
                let env = Env::default();
                env.mock_all_auths();
                env.invoke_contract(&contract, &Symbol::new(&env, "transfer"), &args);
            }
        "#;

        let file = syn::parse_file(code).unwrap();
        let mut visitor = FunctionVisitor {
            path: PathBuf::from("test.rs"),
            findings: &mut findings,
            config: &config,
        };
        visitor.visit_file(&file);

        let mock_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule == "broad-mock-all-auths")
            .collect();
        assert!(!mock_findings.is_empty(), "Expected to find broad-mock-all-auths finding");
    }

    #[test]
    fn test_rule_disabled_skips_check() {
        let mut findings = Vec::new();
        let mut rules = HashMap::new();
        rules.insert(
            "missing-require-auth".to_string(),
            RuleConfig {
                enabled: false,
                severity: None,
            },
        );
        let config = AuditConfig { rules };

        let code = r#"
            pub fn withdraw(env: &Env, caller: &Address, amount: i128) {
                env.storage().persistent().set(&"amount", &amount);
            }
        "#;

        let file = syn::parse_file(code).unwrap();
        let mut visitor = FunctionVisitor {
            path: PathBuf::from("test.rs"),
            findings: &mut findings,
            config: &config,
        };
        visitor.visit_file(&file);

        let require_auth_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule == "missing-require-auth")
            .collect();
        assert!(
            require_auth_findings.is_empty(),
            "Expected no missing-require-auth findings when disabled"
        );
    }

    #[test]
    fn test_severity_override_applied() {
        let mut findings = Vec::new();
        let mut rules = HashMap::new();
        rules.insert(
            "missing-require-auth".to_string(),
            RuleConfig {
                enabled: true,
                severity: Some("error".to_string()),
            },
        );
        let config = AuditConfig { rules };

        let code = r#"
            pub fn withdraw(env: &Env, caller: &Address, amount: i128) {
                env.storage().persistent().set(&"amount", &amount);
            }
        "#;

        let file = syn::parse_file(code).unwrap();
        let mut visitor = FunctionVisitor {
            path: PathBuf::from("test.rs"),
            findings: &mut findings,
            config: &config,
        };
        visitor.visit_file(&file);

        let auth_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule == "missing-require-auth")
            .collect();
        assert!(!auth_findings.is_empty());
        assert_eq!(auth_findings[0].severity, "error");
    }

    #[test]
    fn test_i128_arithmetic_detection() {
        let mut findings = Vec::new();
        let config = AuditConfig::default();

        let code = r#"
            pub fn calculate(amount: i128) -> i128 {
                amount + 100
            }
        "#;

        let file = syn::parse_file(code).unwrap();
        let mut visitor = FunctionVisitor {
            path: PathBuf::from("test.rs"),
            findings: &mut findings,
            config: &config,
        };
        visitor.visit_file(&file);

        let arith_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule == "unchecked-i128-arithmetic")
            .collect();
        assert!(!arith_findings.is_empty());
>>>>>>> dfc2723a (feat(audit): add configuration, rule control, and mock_all_auths detection)
    }
}
