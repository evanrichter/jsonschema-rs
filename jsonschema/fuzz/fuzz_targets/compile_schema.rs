#![no_main]
use std::sync::Arc;

use libfuzzer_sys::fuzz_target;

use anyhow::bail;
use jsonschema::{Draft, JSONSchema};
use serde_json::from_str;
use url::Url;

fuzz_target!(|data: (&str, &str, &str, u8)| {
    let draft = match data.3 & 0b11 {
        0 => Draft::Draft4,
        1 => Draft::Draft6,
        _ => Draft::Draft7,
    };

    let schema = match from_str(data.0) {
        Ok(s) => s,
        Err(_) => return,
    };

    let resolver = match from_str(data.1) {
        Ok(v) => FuzzResolver::Ok(Arc::new(v)),
        Err(_) => FuzzResolver::Err,
    };

    let schema = match JSONSchema::options()
        .should_validate_formats(true)
        .with_draft(draft)
        .with_resolver(resolver)
        .compile(&schema)
    {
        Ok(s) => s,
        Err(_) => return,
    };

    let instance = match from_str(data.2) {
        Ok(i) => i,
        Err(_) => return,
    };

    let result = schema.validate(&instance);
    match result {
        Ok(_) => return,
        Err(e) => {
            let _ = e.count();
        }
    }
});

enum FuzzResolver {
    Ok(Arc<serde_json::Value>),
    Err,
}

impl jsonschema::SchemaResolver for FuzzResolver {
    fn resolve(
        &self,
        _root_schema: &serde_json::Value,
        _url: &Url,
        _original_reference: &str,
    ) -> Result<Arc<serde_json::Value>, jsonschema::SchemaResolverError> {
        match self {
            FuzzResolver::Ok(v) => Ok(v.clone()),
            FuzzResolver::Err => bail!("error"),
        }
    }
}
