use super::DELIMITER;

use named_type::NamedType;
use std::collections::HashSet;

use crate::common::did::DidValue;
use crate::utils::qualifier::{self, Qualifiable};
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

#[derive(Debug, Serialize, Deserialize, NamedType)]
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

qualifiable_type!(SchemaId);

impl Qualifiable for SchemaId {
    fn prefix() -> &'static str {
        Self::PREFIX
    }

    fn combine(method: Option<&str>, entity: &str) -> Self {
        let sid = Self(entity.to_owned());
        match sid.parts() {
            Some((_, did, name, version)) => Self::from(qualifier::combine(
                Self::PREFIX,
                method,
                Self::new(&did.default_method(method), &name, &version).as_str(),
            )),
            None => sid,
        }
    }

    fn to_unqualified(&self) -> Self {
        match self.parts() {
            Some((method, did, name, version)) => {
                let did = if let Some(method) = method {
                    did.remove_method(method)
                } else {
                    did
                };
                Self::new(&did, &name, &version)
            }
            None => self.clone(),
        }
    }
}

impl SchemaId {
    pub const PREFIX: &'static str = "schema";
    pub const MARKER: &'static str = "2";

    pub fn new(did: &DidValue, name: &str, version: &str) -> SchemaId {
        let id = format!(
            "{}{}{}{}{}{}{}",
            did.0,
            DELIMITER,
            Self::MARKER,
            DELIMITER,
            name,
            DELIMITER,
            version
        );
        Self::from(qualifier::combine(
            Self::PREFIX,
            did.get_method(),
            id.as_str(),
        ))
    }

    pub fn parts(&self) -> Option<(Option<&str>, DidValue, String, String)> {
        let parts = self.0.split_terminator(DELIMITER).collect::<Vec<&str>>();

        if parts.len() == 1 {
            // 1
            return None;
        }

        if parts.len() == 4 {
            // NcYxiDXkpYi6ov5FcYDi1e:2:gvt:1.0
            let did = parts[0].to_string();
            let name = parts[2].to_string();
            let version = parts[3].to_string();
            return Some((None, DidValue(did), name, version));
        }

        if parts.len() == 8 {
            // schema:sov:did:sov:NcYxiDXkpYi6ov5FcYDi1e:2:gvt:1.0
            let method = parts[1];
            let did = parts[2..5].join(DELIMITER);
            let name = parts[6].to_string();
            let version = parts[7].to_string();
            return Some((Some(method), DidValue(did), name, version));
        }

        None
    }
}

impl Validatable for SchemaId {
    fn validate(&self) -> Result<(), ValidationError> {
        if self.0.parse::<i32>().is_ok() {
            return Ok(());
        }

        self.parts().ok_or(invalid!(
            "SchemaId validation failed: {:?}, doesn't match pattern",
            self.0
        ))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn _did() -> DidValue {
        DidValue("NcYxiDXkpYi6ov5FcYDi1e".to_string())
    }

    fn _did_qualified() -> DidValue {
        DidValue("did:sov:NcYxiDXkpYi6ov5FcYDi1e".to_string())
    }

    fn _schema_id_seq_no() -> SchemaId {
        SchemaId("1".to_string())
    }

    fn _schema_id_unqualified() -> SchemaId {
        SchemaId("NcYxiDXkpYi6ov5FcYDi1e:2:gvt:1.0".to_string())
    }

    fn _schema_id_qualified() -> SchemaId {
        SchemaId("schema:sov:did:sov:NcYxiDXkpYi6ov5FcYDi1e:2:gvt:1.0".to_string())
    }

    fn _schema_id_invalid() -> SchemaId {
        SchemaId("NcYxiDXkpYi6ov5FcYDi1e:2".to_string())
    }

    mod to_unqualified {
        use super::*;

        #[test]
        fn test_schema_id_unqualify_for_id_as_seq_no() {
            assert_eq!(_schema_id_seq_no(), _schema_id_seq_no().to_unqualified());
        }

        #[test]
        fn test_schema_id_parts_for_id_as_unqualified() {
            assert_eq!(
                _schema_id_unqualified(),
                _schema_id_unqualified().to_unqualified()
            );
        }

        #[test]
        fn test_schema_id_parts_for_id_as_qualified() {
            assert_eq!(
                _schema_id_unqualified(),
                _schema_id_qualified().to_unqualified()
            );
        }

        #[test]
        fn test_schema_id_parts_for_invalid_unqualified() {
            assert_eq!(_schema_id_invalid(), _schema_id_invalid().to_unqualified());
        }
    }

    mod parts {
        use super::*;

        #[test]
        fn test_schema_id_parts_for_id_as_seq_no() {
            assert!(_schema_id_seq_no().parts().is_none());
        }

        #[test]
        fn test_schema_id_parts_for_id_as_unqualified() {
            let (_, did, _, _) = _schema_id_unqualified().parts().unwrap();
            assert_eq!(_did(), did);
        }

        #[test]
        fn test_schema_id_parts_for_id_as_qualified() {
            let (_, did, _, _) = _schema_id_qualified().parts().unwrap();
            assert_eq!(_did_qualified(), did);
        }

        #[test]
        fn test_schema_id_parts_for_invalid_unqualified() {
            assert!(_schema_id_invalid().parts().is_none());
        }
    }

    mod validate {
        use super::*;

        #[test]
        fn test_validate_schema_id_as_seq_no() {
            _schema_id_seq_no().validate().unwrap();
        }

        #[test]
        fn test_validate_schema_id_as_unqualified() {
            _schema_id_unqualified().validate().unwrap();
        }

        #[test]
        fn test_validate_schema_id_as_fully_qualified() {
            _schema_id_qualified().validate().unwrap();
        }

        #[test]
        fn test_validate_schema_id_for_invalid_unqualified() {
            _schema_id_invalid().validate().unwrap_err();
        }

        #[test]
        fn test_validate_schema_id_for_invalid_fully_qualified() {
            let id = SchemaId("schema:sov:NcYxiDXkpYi6ov5FcYDi1e:2:1.0".to_string());
            id.validate().unwrap_err();
        }
    }

    mod test_schema_validation {
        use super::*;

        #[test]
        fn test_valid_schema() {
            let schema_json = json!({
                "id": _schema_id_qualified(),
                "name": "gvt",
                "ver": "1.0",
                "version": "1.0",
                "attrNames": ["aaa", "bbb", "ccc"],
            })
            .to_string();

            let schema: Schema = serde_json::from_str(&schema_json).unwrap();
            schema.validate().unwrap();
            match schema {
                Schema::SchemaV1(schema) => {
                    assert_eq!(schema.name, "gvt");
                    assert_eq!(schema.version, "1.0");
                }
            }
        }

        #[test]
        fn test_invalid_name_schema() {
            let schema_json = json!({
                "id": _schema_id_qualified(),
                "name": "gvt1",
                "ver": "1.0",
                "version": "1.0",
                "attrNames": ["aaa", "bbb", "ccc"],
            })
            .to_string();

            let schema: Schema = serde_json::from_str(&schema_json).unwrap();
            schema.validate().unwrap_err();
        }

        #[test]
        fn test_invalid_version_schema() {
            let schema_json = json!({
                "id": _schema_id_qualified(),
                "name": "gvt",
                "ver": "1.0",
                "version": "1.1",
                "attrNames": ["aaa", "bbb", "ccc"],
            })
            .to_string();

            let schema: Schema = serde_json::from_str(&schema_json).unwrap();
            schema.validate().unwrap_err();
        }
    }
}
