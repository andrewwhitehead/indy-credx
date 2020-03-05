use std::collections::HashSet;

use crate::identifiers::schema::SchemaId;
use crate::utils::qualifier::Qualifiable;
use crate::utils::validation::{Validatable, ValidationError};

pub const MAX_ATTRIBUTES_COUNT: usize = 125;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SchemaV1 {
    pub id: SchemaId,
    pub name: String,
    pub version: String,
    #[serde(rename = "attrNames")]
    pub attr_names: AttributeNames,
    pub seq_no: Option<u32>,
}

impl Validatable for SchemaV1 {
    fn validate(&self) -> Result<(), ValidationError> {
        self.attr_names.validate()?;
        self.id.validate()?;
        if let Some((_, _, name, version)) = self.id.parts() {
            if name != self.name {
                return Err(invalid!(
                    "Inconsistent Schema Id and Schema Name: {:?} and {}",
                    self.id,
                    self.name
                ));
            }
            if version != self.version {
                return Err(invalid!(
                    "Inconsistent Schema Id and Schema Version: {:?} and {}",
                    self.id,
                    self.version
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "ver")]
pub enum Schema {
    #[serde(rename = "1.0")]
    SchemaV1(SchemaV1),
}

impl Schema {
    pub fn to_unqualified(self) -> Schema {
        match self {
            Schema::SchemaV1(schema) => Schema::SchemaV1(SchemaV1 {
                id: schema.id.to_unqualified(),
                name: schema.name,
                version: schema.version,
                attr_names: schema.attr_names,
                seq_no: schema.seq_no,
            }),
        }
    }
}

impl Validatable for Schema {
    fn validate(&self) -> Result<(), ValidationError> {
        match self {
            Schema::SchemaV1(schema) => schema.validate(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AttributeNames(pub HashSet<String>);

#[allow(dead_code)]
impl AttributeNames {
    pub fn new() -> Self {
        AttributeNames(HashSet::new())
    }
}

impl From<HashSet<String>> for AttributeNames {
    fn from(attrs: HashSet<String>) -> Self {
        AttributeNames(attrs)
    }
}

impl Into<HashSet<String>> for AttributeNames {
    fn into(self) -> HashSet<String> {
        self.0
    }
}

impl Validatable for AttributeNames {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.0.is_empty() {
            return Err(invalid!("Empty list of Schema attributes has been passed"));
        }

        if self.0.len() > MAX_ATTRIBUTES_COUNT {
            return Err(invalid!(
                "The number of Schema attributes {} cannot be greater than {}",
                self.0.len(),
                MAX_ATTRIBUTES_COUNT
            ));
        }
        Ok(())
    }
}
