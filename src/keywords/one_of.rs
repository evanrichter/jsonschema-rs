use super::{CompilationResult, ValidationResult};
use super::{Validate, Validators};
use crate::context::CompilationContext;
use crate::error::{CompilationError, ValidationError};
use crate::validator::compile_validators;
use crate::JSONSchema;
use serde_json::{Map, Value};

pub struct OneOfValidator<'a> {
    schemas: Vec<Validators<'a>>,
}

impl<'a> OneOfValidator<'a> {
    pub(crate) fn compile(
        schema: &'a Value,
        context: &CompilationContext,
    ) -> CompilationResult<'a> {
        match schema.as_array() {
            Some(items) => {
                let mut schemas = Vec::with_capacity(items.len());
                for item in items {
                    schemas.push(compile_validators(item, context)?)
                }
                Ok(Box::new(OneOfValidator { schemas }))
            }
            None => Err(CompilationError::SchemaError),
        }
    }

    fn get_first_valid(
        &self,
        config: &JSONSchema,
        instance: &Value,
    ) -> (Option<&Validators<'a>>, Option<usize>) {
        let mut first_valid = None;
        let mut first_valid_idx = None;
        for (idx, validators) in self.schemas.iter().enumerate() {
            if validators
                .iter()
                .all(|validator| validator.is_valid(config, instance))
            {
                first_valid = Some(validators);
                first_valid_idx = Some(idx);
                break;
            }
        }
        (first_valid, first_valid_idx)
    }

    fn are_others_valid(&self, config: &JSONSchema, instance: &Value, idx: Option<usize>) -> bool {
        for validators in self.schemas.iter().skip(idx.unwrap() + 1) {
            if validators
                .iter()
                .all(|validator| validator.is_valid(config, instance))
            {
                return true;
            }
        }
        false
    }
}

impl<'a> Validate<'a> for OneOfValidator<'a> {
    fn validate(&self, config: &JSONSchema, instance: &Value) -> ValidationResult {
        let (first_valid, first_valid_idx) = self.get_first_valid(config, instance);
        if first_valid.is_none() {
            return Err(ValidationError::one_of_not_valid(instance.clone()));
        }
        if self.are_others_valid(config, instance, first_valid_idx) {
            return Err(ValidationError::one_of_multiple_valid(instance.clone()));
        }
        Ok(())
    }
    fn is_valid(&self, config: &JSONSchema, instance: &Value) -> bool {
        let (first_valid, first_valid_idx) = self.get_first_valid(config, instance);
        if first_valid.is_none() {
            return false;
        }
        !self.are_others_valid(config, instance, first_valid_idx)
    }
    fn name(&self) -> String {
        format!("<one of: {:?}>", self.schemas)
    }
}

pub(crate) fn compile<'a>(
    _: &'a Map<String, Value>,
    schema: &'a Value,
    context: &CompilationContext,
) -> Option<CompilationResult<'a>> {
    Some(OneOfValidator::compile(schema, context))
}
