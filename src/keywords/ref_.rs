use super::Validate;
use super::{CompilationResult, ValidationResult};
use crate::context::CompilationContext;
use crate::validator::{compile_validators, JSONSchema};
use serde_json::Value;
use url::Url;

pub struct RefValidator {
    reference: Url,
}

impl<'a> RefValidator {
    pub(crate) fn compile(reference: &str, context: &CompilationContext) -> CompilationResult<'a> {
        let reference = context.build_url(reference)?;
        Ok(Box::new(RefValidator { reference }))
    }
}

impl<'a> Validate<'a> for RefValidator {
    fn validate(&self, config: &JSONSchema, instance: &Value) -> ValidationResult {
        match config
            .resolver
            .resolve_fragment(config.draft, &self.reference, config.schema)
        {
            Ok((scope, resolved)) => {
                let context = CompilationContext::new(scope, config.draft);
                let validators = compile_validators(&resolved, &context)?;
                for v in validators.iter() {
                    v.validate(config, instance)?
                }
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    fn name(&self) -> String {
        format!("<ref: {}>", self.reference)
    }
}
pub(crate) fn compile<'a>(
    _: &'a Value,
    reference: &str,
    context: &CompilationContext,
) -> Option<CompilationResult<'a>> {
    Some(RefValidator::compile(reference, &context))
}
