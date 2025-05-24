// Copyright 2025 Takayuki Okazaki
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::collections::HashMap;
use anyhow::Result;
use serde_json::Value;
use crate::verifier::OpenApiSpec;

/// Represents an API limitation
#[derive(Debug, Clone)]
pub struct ApiLimit {
    pub entity: String,      // The entity that is limited (e.g., "FileRequest")
    pub scope: String,       // The scope of the limit (e.g., "User", "Team", "Global")
    pub limit_type: String,  // The type of limit (e.g., "Count", "Size", "Rate")
    pub value: i64,          // The numerical value of the limit
    pub description: String, // A human-readable description of the limit
}

/// Extracts API limitations from OpenAPI extensions
pub fn extract_api_limits(openapi: &OpenApiSpec) -> Result<Vec<ApiLimit>> {
    let mut limits = Vec::new();
    
    // Look for x-api-limits extension in the OpenAPI spec
    if let Some(extensions) = get_extensions(openapi) {
        if let Some(api_limits) = extensions.get("x-api-limits") {
            if let Some(limits_array) = api_limits.as_array() {
                for limit_obj in limits_array {
                    if let Some(limit) = parse_limit(limit_obj) {
                        limits.push(limit);
                    }
                }
            }
        }
    }
    
    // Look for limits in component schemas
    if let Some(components) = &openapi.components {
        if let Some(schemas) = &components.schemas {
            for (schema_name, schema) in schemas {
                if let Some(extensions) = get_schema_extensions(schema) {
                    if let Some(limits_obj) = extensions.get("x-limits") {
                        if let Some(limit) = parse_entity_limit(schema_name, limits_obj) {
                            limits.push(limit);
                        }
                    }
                }
            }
        }
    }
    
    Ok(limits)
}

/// Gets the extensions from the OpenAPI spec
fn get_extensions(openapi: &OpenApiSpec) -> Option<HashMap<String, Value>> {
    // This is a placeholder - in a real implementation, you would
    // need to access the extensions field in the OpenAPI spec
    // This would depend on how the OpenApiSpec struct is defined
    None
}

/// Gets the extensions from an OpenAPI schema
fn get_schema_extensions(schema: &crate::verifier::OpenApiSchema) -> Option<HashMap<String, Value>> {
    // This is a placeholder - in a real implementation, you would
    // need to access the extensions field in the schema
    None
}

/// Parses a limit object from the OpenAPI extensions
fn parse_limit(limit_obj: &Value) -> Option<ApiLimit> {
    // Extract fields from the limit object
    let entity = limit_obj.get("entity")?.as_str()?.to_string();
    let scope = limit_obj.get("scope")?.as_str()?.to_string();
    let limit_type = limit_obj.get("type")?.as_str()?.to_string();
    let value = limit_obj.get("value")?.as_i64()?;
    let description = limit_obj.get("description").and_then(|d| d.as_str())
        .unwrap_or("").to_string();
    
    Some(ApiLimit {
        entity,
        scope,
        limit_type,
        value,
        description,
    })
}

/// Parses an entity limit from a schema extension
fn parse_entity_limit(entity_name: &str, limit_obj: &Value) -> Option<ApiLimit> {
    // For schema-level limits, the entity is the schema name
    let scope = limit_obj.get("scope")?.as_str()?.to_string();
    let limit_type = limit_obj.get("type")?.as_str()?.to_string();
    let value = limit_obj.get("value")?.as_i64()?;
    let description = limit_obj.get("description").and_then(|d| d.as_str())
        .unwrap_or("").to_string();
    
    Some(ApiLimit {
        entity: entity_name.to_string(),
        scope,
        limit_type,
        value,
        description,
    })
}

/// Generates Alloy constraints for API limitations
pub fn generate_alloy_limits(limits: &[ApiLimit]) -> String {
    let mut constraints = String::from("// API Limitations\nfact ApiLimitations {\n");
    
    for limit in limits {
        // Add a comment describing the limitation
        constraints.push_str(&format!("  // {}\n", limit.description));
        
        // Generate the appropriate Alloy constraint based on the limit type and scope
        match (limit.limit_type.as_str(), limit.scope.as_str()) {
            ("Count", "User") => {
                constraints.push_str(&format!(
                    "  all u: User | #{} <= {}\n",
                    limit.entity.to_lowercase(),
                    limit.value
                ));
            },
            ("Count", "Team") => {
                constraints.push_str(&format!(
                    "  all t: Team | #{} <= {}\n",
                    limit.entity.to_lowercase(),
                    limit.value
                ));
            },
            ("Count", "Global") => {
                constraints.push_str(&format!(
                    "  #{} <= {}\n",
                    limit.entity,
                    limit.value
                ));
            },
            ("Size", _) => {
                constraints.push_str(&format!(
                    "  all f: {} | f.size <= {}\n",
                    limit.entity,
                    limit.value
                ));
            },
            ("Rate", _) => {
                // Rate limits are harder to model in Alloy since it's not temporal
                constraints.push_str(&format!(
                    "  // Rate limit: {} requests per timeframe for {}\n",
                    limit.value,
                    limit.scope
                ));
            },
            _ => {
                constraints.push_str(&format!(
                    "  // Unmodeled limit: {} {} per {}\n",
                    limit.value,
                    limit.limit_type,
                    limit.scope
                ));
            }
        }
        
        constraints.push_str("\n");
    }
    
    constraints.push_str("}\n");
    constraints
}
