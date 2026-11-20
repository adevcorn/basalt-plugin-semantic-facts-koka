//! Semantic-facts-koka — parser- and effect-row-derived semantic facts for Koka.
//!
//! Provides `semantic-facts@koka/v1` by consuming:
//! - `parse.call-sites@koka/v1`
//! - `parse.retrieval@koka/v1`
//!
//! Request format from core (capability handle):
//! `[src_len u32][src][path_len u32][path][root_len u32][root]`

#![no_std]
#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]

extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

#[cfg(target_arch = "wasm32")]
use basalt_plugin_sdk::facts::serialize_facts;
use basalt_plugin_sdk::facts::{
    AsyncBoundaryKind, IOKind, MutationKind, MutationTarget, SemanticFact, SymbolKind,
};
use basalt_plugin_sdk::prelude::*;

basalt_plugin_meta! {
    name:              "semantic-facts-koka",
    version:           env!("CARGO_PKG_VERSION"),
    hook_flags:        CAP_CAPABILITY_HANDLE | CAP_SEMANTIC_FACTS,
    provides:          "semantic-facts@koka/v1",
    requires:          "parse.call-sites@kk/v1\nparse.retrieval@kk/v1",
    optional_requires: "",
    file_globs:        "**/*.kk\n**/*.kki",
    activates_on:      "",
    activation_events: "",
}

#[cfg(target_arch = "wasm32")]
#[unsafe(no_mangle)]
pub extern "C" fn basalt_capability_handle(
    cap_ptr: *const u8,
    cap_len: usize,
    req_ptr: *const u8,
    req_len: usize,
) -> i64 {
    let _ = (cap_ptr, cap_len);
    if req_ptr.is_null() || req_len < 4 {
        return pack_empty();
    }
    let request = unsafe { core::slice::from_raw_parts(req_ptr, req_len) };
    let Some((src, path)) = parse_request(request) else {
        return pack_error(-1002);
    };
    if src.is_empty() {
        return pack_empty();
    }

    match derive_semantic_facts(src, path) {
        Ok(facts) => pack_success(facts),
        Err(code) => pack_error(code),
    }
}

#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
fn parse_request(request: &[u8]) -> Option<(&[u8], &str)> {
    if request.len() < 4 {
        return None;
    }
    let src_len = u32::from_le_bytes([request[0], request[1], request[2], request[3]]) as usize;
    if request.len() < 4 + src_len {
        return None;
    }
    let src = &request[4..4 + src_len];

    let mut pos = 4 + src_len;
    let mut path = "";
    if request.len() >= pos + 4 {
        let len = u32::from_le_bytes([
            request[pos],
            request[pos + 1],
            request[pos + 2],
            request[pos + 3],
        ]) as usize;
        pos += 4;
        if request.len() >= pos + len {
            path = core::str::from_utf8(&request[pos..pos + len]).unwrap_or("");
        }
    }
    Some((src, path))
}

#[cfg(target_arch = "wasm32")]
fn derive_semantic_facts(src: &[u8], path: &str) -> Result<Vec<u8>, i64> {
    let call_sites_raw = invoke_parse_call_sites(src).map_err(|_| -1003)?;
    let retrieval_raw = invoke_parse_retrieval(src).map_err(|_| -1003)?;

    let call_sites = decode_call_sites(&call_sites_raw);
    let retrieval = decode_retrieval(&retrieval_raw);
    let module = module_name(path);

    let mut facts: Vec<SemanticFact> = Vec::new();
    derive_declarations(&retrieval, &module, &mut facts);
    derive_signature_effects(src, &retrieval, &mut facts);
    derive_call_edges(&call_sites, &mut facts);
    derive_imports(src, &mut facts);

    Ok(serialize_facts(&facts))
}

#[cfg(target_arch = "wasm32")]
fn invoke_parse_call_sites(src: &[u8]) -> Result<Vec<u8>, i64> {
    let mut request = Vec::with_capacity(4 + src.len() + 4);
    request.extend_from_slice(&(src.len() as u32).to_le_bytes());
    request.extend_from_slice(src);
    request.extend_from_slice(&16384u32.to_le_bytes());
    invoke_capability("parse.call-sites@kk/v1", &request).map_err(|_| -1003)
}

#[cfg(target_arch = "wasm32")]
fn invoke_parse_retrieval(src: &[u8]) -> Result<Vec<u8>, i64> {
    let mut request = Vec::with_capacity(4 + src.len() + 4);
    request.extend_from_slice(&(src.len() as u32).to_le_bytes());
    request.extend_from_slice(src);
    request.extend_from_slice(&8192u32.to_le_bytes());
    invoke_capability("parse.retrieval@kk/v1", &request).map_err(|_| -1003)
}

// ── Parser response decoding ────────────────────────────────────────────────

fn decode_call_sites(data: &[u8]) -> Vec<(u32, &str)> {
    if data.len() < 4 {
        return Vec::new();
    }
    let count = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let mut sites = Vec::with_capacity(count);
    let mut pos = 4;
    for _ in 0..count {
        if pos + 68 > data.len() {
            break;
        }
        let offset = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        let name_bytes = &data[pos + 4..pos + 68];
        let nul = name_bytes.iter().position(|&b| b == 0).unwrap_or(64);
        if let Ok(name) = core::str::from_utf8(&name_bytes[..nul]) {
            if !name.is_empty() {
                sites.push((offset, name));
            }
        }
        pos += 68;
    }
    sites
}

fn decode_retrieval(data: &[u8]) -> Vec<(u32, u32, &str, u8)> {
    if data.len() < 4 {
        return Vec::new();
    }
    let count = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let mut chunks = Vec::with_capacity(count);
    let mut pos = 4;
    for _ in 0..count {
        if pos + 104 > data.len() {
            break;
        }
        let offset = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        let length =
            u32::from_le_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]);
        let label_bytes = &data[pos + 8..pos + 103];
        let kind = data[pos + 103];
        let nul = label_bytes.iter().position(|&b| b == 0).unwrap_or(95);
        if let Ok(label) = core::str::from_utf8(&label_bytes[..nul]) {
            let label = label.trim();
            if !label.is_empty() && length > 0 {
                chunks.push((offset, length, label, kind));
            }
        }
        pos += 104;
    }
    chunks
}

fn module_name(path: &str) -> String {
    let normalized = path.replace('\\', "/");
    let stripped = ["src/", "test/", "./"]
        .iter()
        .find_map(|prefix| normalized.strip_prefix(prefix))
        .unwrap_or(&normalized);
    let module = stripped
        .strip_suffix(".kki")
        .or_else(|| stripped.strip_suffix(".kk"))
        .unwrap_or(stripped);
    module.to_string()
}

fn label_name<'a>(label: &'a str, kind: &str) -> &'a str {
    label
        .strip_prefix(kind)
        .map(str::trim)
        .unwrap_or(label)
        .trim()
}

fn qualified(module: &str, name: &str) -> Option<String> {
    if module.is_empty() {
        None
    } else {
        Some(format!("{module}::{name}"))
    }
}

fn derive_declarations(
    retrieval: &[(u32, u32, &str, u8)],
    module: &str,
    facts: &mut Vec<SemanticFact>,
) {
    let type_scopes: Vec<(u32, u32, &str)> = retrieval
        .iter()
        .filter(|(_, _, _, kind)| *kind == 2)
        .map(|(offset, length, label, _)| (*offset, *length, label_name(label, "type")))
        .collect();

    for &(offset, length, label, kind) in retrieval {
        match kind {
            2 => {
                let name = label_name(label, "type");
                if !name.is_empty() {
                    facts.push(SemanticFact::DeclareSymbol {
                        kind: SymbolKind::Type,
                        offset,
                        length,
                        name: name.to_string(),
                        qualified_name: qualified(module, name),
                    });
                }
            }
            3 => {
                let name = label_name(label, "function");
                if !name.is_empty() {
                    facts.push(SemanticFact::DeclareSymbol {
                        kind: SymbolKind::Function,
                        offset,
                        length,
                        name: name.to_string(),
                        qualified_name: qualified(module, name),
                    });
                }
            }
            5 => {
                let name = label_name(label, "property");
                if !name.is_empty() {
                    facts.push(SemanticFact::DeclareSymbol {
                        kind: SymbolKind::Constant,
                        offset,
                        length,
                        name: name.to_string(),
                        qualified_name: qualified(module, name),
                    });
                }
            }
            6 => {
                let name = label_name(label, "enum_case");
                if !name.is_empty() {
                    let parent = type_scopes
                        .iter()
                        .filter(|(start, len, _)| *start <= offset && offset < start + len)
                        .min_by_key(|(_, len, _)| *len)
                        .map(|(_, _, name)| *name);
                    let qualified_name = match parent {
                        Some(parent) => Some(format!("{module}::{parent}::{name}")),
                        None => qualified(module, name),
                    };
                    facts.push(SemanticFact::DeclareSymbol {
                        kind: SymbolKind::EnumMember,
                        offset,
                        length,
                        name: name.to_string(),
                        qualified_name,
                    });
                }
            }
            _ => {}
        }
    }
}

/// Find the matching `)` for the first `(` in `s`, respecting nested parens.
fn find_matching_rparen(s: &str) -> Option<usize> {
    let mut depth = 0usize;
    let mut started = false;
    for (idx, b) in s.bytes().enumerate() {
        match b {
            b'(' => {
                depth += 1;
                started = true;
            }
            b')' if started => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(idx);
                }
            }
            _ => {}
        }
    }
    None
}

/// Inspect Koka function signatures (`fun f(...) : <eff1,eff2> ret` or `: eff ret`)
/// and emit `IOOperation`, `Mutation`, and `AsyncBoundary` facts directly from
/// declared algebraic effect rows.
fn derive_signature_effects(
    src: &[u8],
    retrieval: &[(u32, u32, &str, u8)],
    facts: &mut Vec<SemanticFact>,
) {
    let text = String::from_utf8_lossy(src);
    for &(offset, length, label, kind) in retrieval {
        if kind != 3 {
            continue;
        }
        let start = offset as usize;
        let end = (start + length as usize).min(text.len());
        if start >= end {
            continue;
        }
        let chunk = &text[start..end];
        let Some(rparen_idx) = find_matching_rparen(chunk) else {
            continue;
        };
        let after_rparen = &chunk[rparen_idx + 1..];
        // Stop at the function body delimiter (`{`, `=`, or newline without continuation).
        let sig_tail = after_rparen
            .split(|c| c == '{' || c == '=' || c == '\n')
            .next()
            .unwrap_or("");
        let Some((_, after_colon)) = sig_tail.split_once(':') else {
            continue;
        };
        let eff_slice = after_colon.trim();
        let fn_name = label_name(label, "function");

        if let Some(inner) = eff_slice.strip_prefix('<') {
            if let Some((row, _)) = inner.split_once('>') {
                for raw_eff in row.split(',') {
                    let eff = raw_eff.split('<').next().unwrap_or(raw_eff).trim();
                    emit_effect_fact(eff, offset, length, fn_name, facts);
                }
            }
        } else {
            let eff = eff_slice
                .split_whitespace()
                .next()
                .unwrap_or("")
                .split('<')
                .next()
                .unwrap_or("");
            // Only emit when there's a return type following the effect token
            if eff_slice.split_whitespace().count() >= 2 {
                emit_effect_fact(eff, offset, length, fn_name, facts);
            }
        }
    }
}

fn emit_effect_fact(
    eff: &str,
    offset: u32,
    length: u32,
    fn_name: &str,
    facts: &mut Vec<SemanticFact>,
) {
    let eff = eff.to_ascii_lowercase();
    match eff.as_str() {
        "console" | "stdio" => {
            facts.push(SemanticFact::IOOperation {
                io_kind: IOKind::StdIO,
                offset,
                length,
                descriptor: Some(format!("effect:{eff} ({fn_name})")),
            });
        }
        "fsys" | "fs" | "file" => {
            facts.push(SemanticFact::IOOperation {
                io_kind: IOKind::FileRead,
                offset,
                length,
                descriptor: Some(format!("effect:{eff} ({fn_name})")),
            });
        }
        "net" | "http" => {
            facts.push(SemanticFact::IOOperation {
                io_kind: IOKind::Network,
                offset,
                length,
                descriptor: Some(format!("effect:{eff} ({fn_name})")),
            });
        }
        "io" | "io-noexn" => {
            facts.push(SemanticFact::IOOperation {
                io_kind: IOKind::StdIO,
                offset,
                length,
                descriptor: Some(format!("effect:{eff} ({fn_name})")),
            });
            facts.push(SemanticFact::IOOperation {
                io_kind: IOKind::FileRead,
                offset,
                length,
                descriptor: Some(format!("effect:{eff} ({fn_name})")),
            });
            facts.push(SemanticFact::IOOperation {
                io_kind: IOKind::Network,
                offset,
                length,
                descriptor: Some(format!("effect:{eff} ({fn_name})")),
            });
        }
        "st" | "alloc" | "write" | "local" => {
            facts.push(SemanticFact::Mutation {
                target: MutationTarget::Variable,
                kind: MutationKind::StateWrite,
                offset,
                length,
                name: fn_name.to_string(),
            });
        }
        "async" | "asyncx" => {
            facts.push(SemanticFact::AsyncBoundary {
                boundary_kind: AsyncBoundaryKind::Await,
                offset,
                length,
            });
        }
        // `total`, `pure`, `exn`, `div`, `ndet`, `read` are pure/non-IO effects in Basalt's model.
        "total" | "pure" | "exn" | "div" | "ndet" | "read" | "" => {}
        // Custom / user-defined algebraic effects: record a ReferenceSymbol edge
        // so `find_callers` on an effect declaration lists every function that performs it.
        custom => {
            facts.push(SemanticFact::ReferenceSymbol {
                offset,
                length,
                target: custom.to_string(),
            });
        }
    }
}

fn derive_call_edges(call_sites: &[(u32, &str)], facts: &mut Vec<SemanticFact>) {
    for &(offset, callee) in call_sites {
        let length = callee.len() as u32;
        facts.push(SemanticFact::Calls {
            caller_offset: offset,
            caller_length: length,
            callee: callee.to_string(),
        });
        if let Some(io_kind) = classify_io(callee) {
            facts.push(SemanticFact::IOOperation {
                io_kind,
                offset,
                length,
                descriptor: Some(callee.to_string()),
            });
        }
    }
}

fn classify_io(callee: &str) -> Option<IOKind> {
    let lower = callee.to_ascii_lowercase();
    let tail = lower.rsplit('/').next().unwrap_or(&lower);
    let tail = tail.rsplit('.').next().unwrap_or(tail);

    if lower.contains("http") || lower.contains("net/") {
        Some(IOKind::Network)
    } else if tail.contains("read-text-file") || tail.contains("read-file") {
        Some(IOKind::FileRead)
    } else if tail.contains("write-text-file") || tail.contains("write-file") {
        Some(IOKind::FileWrite)
    } else if matches!(tail, "println" | "print" | "readline" | "trace") {
        Some(IOKind::StdIO)
    } else {
        None
    }
}

fn derive_imports(src: &[u8], facts: &mut Vec<SemanticFact>) {
    let text = String::from_utf8_lossy(src);
    let base_ptr = text.as_ptr() as usize;
    for line in text.lines() {
        let line_offset = (line.as_ptr() as usize).saturating_sub(base_ptr) as u32;
        let trimmed = line.trim_start();
        let after_pub = trimmed.strip_prefix("pub ").unwrap_or(trimmed).trim_start();
        if let Some(rest) = after_pub.strip_prefix("import ") {
            let rest = rest.trim();
            if rest.is_empty() {
                continue;
            }
            let (alias, module) = if let Some((lhs, rhs)) = rest.split_once('=') {
                (
                    Some(lhs.trim().to_string()),
                    rhs.split_whitespace().next().unwrap_or(""),
                )
            } else {
                (None, rest.split_whitespace().next().unwrap_or(""))
            };
            if !module.is_empty() {
                let offset = line_offset + (line.len() - trimmed.len()) as u32;
                facts.push(SemanticFact::ImportModule {
                    offset,
                    length: module.len() as u32,
                    module_path: module.to_string(),
                    alias,
                });
                facts.push(SemanticFact::DependsOn {
                    offset,
                    length: module.len() as u32,
                    dependency: module.to_string(),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn pure_function_emits_no_io_facts() {
        let src = b"pub fun add(a : int, b : int) : total int { a + b }";
        let retrieval = vec![(0, src.len() as u32, "function add", 3)];
        let mut facts = Vec::new();
        derive_signature_effects(src, &retrieval, &mut facts);
        assert!(facts.is_empty());
    }

    #[test]
    fn effect_row_emits_io_and_mutation_facts() {
        let src = b"pub fun sync(p : string) : <console,fsys,net,st<h>> () { () }";
        let retrieval = vec![(0, src.len() as u32, "function sync", 3)];
        let mut facts = Vec::new();
        derive_signature_effects(src, &retrieval, &mut facts);
        assert_eq!(facts.len(), 4);
    }

    #[test]
    fn extracts_koka_imports() {
        let src = b"import std/os/file\npub import fp = std/os/path\n";
        let mut facts = Vec::new();
        derive_imports(src, &mut facts);
        assert_eq!(facts.len(), 4); // 2 ImportModule + 2 DependsOn
    }

    #[test]
    fn total_function_with_record_copy_and_nested_parens_has_no_mutations() {
        let src = b"pub fun map-entity(e : entity, f : (int) -> total int) : total entity\n  val next = e(relations = [])\n  next\n";
        let retrieval = vec![(0, src.len() as u32, "function map-entity", 3)];
        let mut facts = Vec::new();
        derive_signature_effects(src, &retrieval, &mut facts);
        assert!(
            facts.is_empty(),
            "pure : total function with record copy must emit zero mutation/IO facts, got {facts:?}"
        );
    }

    #[test]
    fn custom_algebraic_effect_emits_effect_reference() {
        let src = b"pub fun sync-loc(id : string) : <catalog-store,exn> ()\n  ()";
        let retrieval = vec![(0, src.len() as u32, "function sync-loc", 3)];
        let mut facts = Vec::new();
        derive_signature_effects(src, &retrieval, &mut facts);
        assert!(
            facts.iter().any(|f| matches!(
                f,
                SemanticFact::ReferenceSymbol { target, .. } if target == "catalog-store"
            )),
            "expected ReferenceSymbol(catalog-store), got {facts:?}"
        );
    }
}
