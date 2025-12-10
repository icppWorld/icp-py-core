use candid_parser::syntax::Binding;
use pyo3::prelude::*;
use candid_parser::{IDLProg};
use candid_parser::syntax::{Dec, IDLType};
use serde::Serialize;
use std::collections::BTreeMap; // 引入 BTreeMap 以生成 JSON 对象

// --- 1. Define intermediate JSON protocol ---
// We define a clear JSON structure as the communication protocol between Rust and Python

#[derive(Serialize)]
struct ParsedResult {
    env: Vec<DefEntry>,       // Type definitions: type A = ...
    actor: Option<ActorEntry> // Actor definition: service : { ... }
}

#[derive(Serialize)]
struct DefEntry {
    name: String,
    // [FIX 1] Rename 'datatype' to 'def' to match Python's expectation
    #[serde(rename = "def")] 
    datatype: JsonType,
}

#[derive(Serialize)]
struct ActorEntry {
    methods: Vec<MethodEntry>,
    init: Option<Vec<JsonType>>, // Service initialization parameters
}

#[derive(Serialize)]
struct MethodEntry {
    name: String,
    args: Vec<JsonType>,
    rets: Vec<JsonType>,
    modes: Vec<String>, // "query", "oneway"
}

// [FIX 2] Remove #[serde(tag=...)] to use External Tagging (default).
// This produces {"Vec": ...} instead of {"type": "Vec", "value": ...}
// matching the Python loader logic: tag = list(t_node.keys())[0]
#[derive(Serialize)]
enum JsonType {
    Prim(String),                    // nat, int, text...
    Principal,
    Vec(Box<JsonType>),
    Opt(Box<JsonType>),
    // [FIX 3] Use BTreeMap instead of Vec<(String, Type)>
    // This ensures serialization as JSON Object {"k": "v"} instead of Array [["k","v"]]
    // BTreeMap is used to keep keys sorted (deterministic output).
    Record(BTreeMap<String, JsonType>), 
    Variant(BTreeMap<String, JsonType>),
    Func { args: Vec<JsonType>, rets: Vec<JsonType>, modes: Vec<String> },
    Service(Vec<MethodEntry>),
    Id(String),                      // Reference to other type (type A = B)
    Empty,
    Reserved,
    Unknown,
}

// --- 2. Conversion logic: Candid AST -> JSON ---

fn convert_type(t: &IDLType) -> JsonType {
    match t {
        IDLType::PrimT(p) => {
            let s = format!("{:?}", p).to_lowercase();
            JsonType::Prim(s)
        },
        IDLType::PrincipalT => JsonType::Principal,
        IDLType::VarT(name) => JsonType::Id(name.clone()),
        IDLType::OptT(inner) => JsonType::Opt(Box::new(convert_type(inner))),
        IDLType::VecT(inner) => JsonType::Vec(Box::new(convert_type(inner))),
        IDLType::RecordT(fields) => {
            // Convert Vec<Field> to BTreeMap for JSON Map output
            let mut fs = BTreeMap::new();
            for f in fields {
                fs.insert(f.label.to_string(), convert_type(&f.typ));
            }
            JsonType::Record(fs)
        },
        IDLType::VariantT(fields) => {
            let mut fs = BTreeMap::new();
            for f in fields {
                fs.insert(f.label.to_string(), convert_type(&f.typ));
            }
            JsonType::Variant(fs)
        },
        IDLType::FuncT(func) => {
            let args = func.args.iter().map(convert_type).collect();
            let rets = func.rets.iter().map(convert_type).collect();
            let modes = func.modes.iter().map(|m| format!("{:?}", m).to_lowercase()).collect();
            JsonType::Func { args, rets, modes }
        },
        IDLType::ServT(methods) => {
            let ms = methods.iter().map(convert_method).collect();
            JsonType::Service(ms)
        },
        IDLType::ClassT(_, serv) => convert_type(serv), // Class downgraded to Service for processing
    }
}

fn convert_method(m: &Binding) -> MethodEntry {
    if let IDLType::FuncT(func) = &m.typ {
        MethodEntry {
            name: m.id.clone(),
            args: func.args.iter().map(convert_type).collect(),
            rets: func.rets.iter().map(convert_type).collect(),
            modes: func.modes.iter().map(|mode| format!("{:?}", mode).to_lowercase()).collect(),
        }
    } else {
        // Theoretically Service fields must be Func, this is defensive code
        MethodEntry { name: m.id.clone(), args: vec![], rets: vec![], modes: vec![] }
    }
}

// --- 3. Python interface ---

#[pyfunction]
fn parse_did(did_content: String) -> PyResult<String> {
    // Call official Parser
    let prog: IDLProg = did_content.parse()
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyValueError, _>(format!("Candid Syntax Error: {}", e)))?;

    // Convert data
    let mut env_list = Vec::new();
    for dec in &prog.decs {
        if let Dec::TypD(binding) = dec {
            env_list.push(DefEntry {
                name: binding.id.clone(),
                datatype: convert_type(&binding.typ),
            });
        }
    }

    let mut actor_entry = None;
    if let Some(actor) = &prog.actor {
        // Process actor definition, could be Service or Class
        match &actor.typ {
            IDLType::ServT(methods) => {
                let ms = methods.iter().map(convert_method).collect();
                actor_entry = Some(ActorEntry { methods: ms, init: None });
            },
            IDLType::ClassT(args, serv) => {
                let init_args = args.iter().map(convert_type).collect();
                if let IDLType::ServT(methods) = &**serv {
                     let ms = methods.iter().map(convert_method).collect();
                     actor_entry = Some(ActorEntry { methods: ms, init: Some(init_args) });
                }
            },
            _ => {}
        }
    }

    let result = ParsedResult { env: env_list, actor: actor_entry };
    
    // Serialize to JSON string and return
    serde_json::to_string(&result)
        .map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
}

#[pymodule]
fn ic_candid_parser(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(parse_did, m)?)?;
    Ok(())
}