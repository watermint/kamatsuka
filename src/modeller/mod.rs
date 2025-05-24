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

use std::fs;
use std::collections::{HashMap, HashSet};
use std::io::Write;

use anyhow::{Context, Result};
use colored::*;

use crate::verifier::{OpenApiSpec, OpenApiSchema};

/// Converts an OpenAPI specification to Alloy definitions
pub fn convert_openapi_to_alloy(openapi_path: &str, output_path: &str, verbose: bool) -> Result<()> {
    println!("{}", "OpenAPI to Alloy Conversion".green().bold());
    println!("Input: {}", openapi_path.cyan());
    println!("Output: {}", output_path.cyan());
    println!();

    // Parse OpenAPI spec
    let openapi_content = fs::read_to_string(openapi_path)
        .with_context(|| format!("Failed to read OpenAPI file: {}", openapi_path))?;
    
    let openapi_spec: OpenApiSpec = serde_yaml::from_str(&openapi_content)
        .with_context(|| "Failed to parse OpenAPI YAML")?;
    
    // Generate Alloy definitions
    let alloy_content = generate_alloy_definitions(&openapi_spec, verbose)?;
    
    // Write to output file
    let mut output_file = fs::File::create(output_path)
        .with_context(|| format!("Failed to create output file: {}", output_path))?;
    
    output_file.write_all(alloy_content.as_bytes())
        .with_context(|| "Failed to write Alloy definitions to file")?;
    
    println!("{}", "✓ Successfully generated Alloy definitions!".green().bold());
    println!("  Wrote {} bytes to {}", alloy_content.len(), output_path);
    
    Ok(())
}

/// Generates Alloy definitions from an OpenAPI specification
fn generate_alloy_definitions(openapi: &OpenApiSpec, verbose: bool) -> Result<String> {
    let mut alloy_content = String::new();
    
    // Add module header
    alloy_content.push_str(&format!(
        "module api\n\n// Generated from OpenAPI spec: {}\n// Title: {}\n// Version: {}\n\n",
        openapi.info.title,
        openapi.info.title,
        openapi.info.version
    ));
    
    // Add base signatures
    alloy_content.push_str("// Base signatures\n");
    alloy_content.push_str("abstract sig Operation {\n");
    alloy_content.push_str("  id: String,\n");
    alloy_content.push_str("  path: String,\n");
    alloy_content.push_str("  method: String,\n");
    alloy_content.push_str("  request: lone Request,\n");
    alloy_content.push_str("  responses: set Response\n");
    alloy_content.push_str("}\n\n");
    
    alloy_content.push_str("sig Request {\n");
    alloy_content.push_str("  content: univ\n");
    alloy_content.push_str("}\n\n");
    
    alloy_content.push_str("sig Response {\n");
    alloy_content.push_str("  status: Int,\n");
    alloy_content.push_str("  content: lone univ\n");
    alloy_content.push_str("}\n\n");
    
    // Process schemas
    if let Some(components) = &openapi.components {
        if let Some(schemas) = &components.schemas {
            alloy_content.push_str("// Schema definitions\n");
            
            // Process all schemas
            for (schema_name, schema) in schemas {
                if verbose {
                    println!("Processing schema: {}", schema_name);
                }
                
                let schema_definition = generate_alloy_schema(schema_name, schema, schemas, verbose)?;
                alloy_content.push_str(&schema_definition);
                alloy_content.push_str("\n\n");
            }
        }
    }
    
    // Process API paths
    alloy_content.push_str("// API operations\n");
    for (path, operations) in &openapi.paths {
        for (method, operation) in operations {
            if let Some(operation_id) = &operation.operation_id {
                if verbose {
                    println!("Processing operation: {} {} ({})", method.to_uppercase(), path, operation_id);
                }
                
                let operation_definition = generate_alloy_operation(
                    operation_id, 
                    method, 
                    path, 
                    operation, 
                    verbose
                )?;
                
                alloy_content.push_str(&operation_definition);
                alloy_content.push_str("\n\n");
            }
        }
    }
    
    // Add constraints and assertions
    alloy_content.push_str("// Global constraints\n");
    alloy_content.push_str("fact APIConstraints {\n");
    alloy_content.push_str("  // All operations must have unique IDs\n");
    alloy_content.push_str("  all disj op1, op2: Operation | op1.id != op2.id\n");
    alloy_content.push_str("}\n\n");
    
    alloy_content.push_str("// Sample assertions for API verification\n");
    alloy_content.push_str("assert NoEmptyResponses {\n");
    alloy_content.push_str("  all op: Operation | some op.responses\n");
    alloy_content.push_str("}\n\n");
    
    alloy_content.push_str("// Run commands for analysis\n");
    alloy_content.push_str("pred show {}\n");
    alloy_content.push_str("run show for 3\n");
    alloy_content.push_str("check NoEmptyResponses for 4\n");
    
    Ok(alloy_content)
}

/// Generates Alloy definition for a schema
fn generate_alloy_schema(
    schema_name: &str, 
    schema: &OpenApiSchema, 
    all_schemas: &HashMap<String, OpenApiSchema>,
    _verbose: bool
) -> Result<String> {
    let mut definition = String::new();
    
    match schema {
        OpenApiSchema::Reference { reference } => {
            // Handle reference schemas
            let ref_name = extract_schema_name(reference)
                .ok_or_else(|| anyhow::anyhow!("Invalid reference: {}", reference))?;
            
            definition.push_str(&format!("// {} is an alias for {}\n", schema_name, ref_name));
            definition.push_str(&format!("sig {} {{\n", schema_name));
            definition.push_str(&format!("  // Reference to: {}\n", reference));
            definition.push_str("}\n");
        },
        OpenApiSchema::Object { 
            schema_type, 
            properties, 
            required, 
            all_of, 
            items, 
            enum_values 
        } => {
            if let Some(enum_values) = enum_values {
                // Handle enum
                definition.push_str(&format!("abstract sig {} {{\n", schema_name));
                definition.push_str("}\n\n");
                
                for (i, value) in enum_values.iter().enumerate() {
                    let enum_value = match value.as_str() {
                        Some(v) => v.to_string(),
                        None => format!("Value{}", i)
                    };
                    definition.push_str(&format!("one sig {}_{} extends {} {{\n", schema_name, enum_value, schema_name));
                    definition.push_str("}\n");
                }
            } else if let Some(schema_type) = schema_type {
                if schema_type == "object" {
                    // Handle object type
                    if let Some(all_of) = all_of {
                        // Handle inheritance/composition with allOf
                        let parent = match &all_of[0] {
                            OpenApiSchema::Reference { reference } => {
                                extract_schema_name(reference)
                                    .ok_or_else(|| anyhow::anyhow!("Invalid reference in allOf: {}", reference))?
                            },
                            _ => "Object".to_string()
                        };
                        
                        definition.push_str(&format!("sig {} extends {} {{\n", schema_name, parent));
                    } else {
                        definition.push_str(&format!("sig {} {{\n", schema_name));
                    }
                    
                    // Add properties
                    if let Some(props) = properties {
                        let required_fields = required.as_ref().map_or_else(HashSet::new, |r| {
                            r.iter().collect::<HashSet<_>>()
                        });
                        
                        for (prop_name, prop_schema) in props {
                            let field_type = schema_to_alloy_type(prop_schema, all_schemas)?;
                            let multiplicity = if required_fields.contains(prop_name) { "" } else { "lone " };
                            
                            definition.push_str(&format!("  {}: {}{},\n", prop_name, multiplicity, field_type));
                        }
                    }
                    
                    definition.push_str("}\n");
                } else if schema_type == "array" {
                    // Handle array type
                    if let Some(item_schema) = items.as_ref() {
                        let item_type = schema_to_alloy_type(item_schema, all_schemas)?;
                        
                        definition.push_str(&format!("sig {} {{\n", schema_name));
                        definition.push_str(&format!("  items: set {}\n", item_type));
                        definition.push_str("}\n");
                    } else {
                        definition.push_str(&format!("sig {} {{\n", schema_name));
                        definition.push_str("  items: set univ\n");
                        definition.push_str("}\n");
                    }
                } else {
                    // Handle primitive types
                    definition.push_str(&format!("sig {} {{\n", schema_name));
                    definition.push_str(&format!("  // Primitive type: {}\n", schema_type));
                    definition.push_str(&format!("  value: {}\n", map_primitive_type(schema_type)));
                    definition.push_str("}\n");
                }
            } else {
                // Generic object
                definition.push_str(&format!("sig {} {{\n", schema_name));
                definition.push_str("  // Generic object with no specific type\n");
                definition.push_str("}\n");
            }
        }
    }
    
    Ok(definition)
}

/// Converts an OpenAPI schema to an Alloy type
fn schema_to_alloy_type(
    schema: &OpenApiSchema, 
    all_schemas: &HashMap<String, OpenApiSchema>
) -> Result<String> {
    match schema {
        OpenApiSchema::Reference { reference } => {
            let ref_name = extract_schema_name(reference)
                .ok_or_else(|| anyhow::anyhow!("Invalid reference: {}", reference))?;
            Ok(ref_name)
        },
        OpenApiSchema::Object { 
            schema_type, 
            items,
            ..
        } => {
            if let Some(schema_type) = schema_type {
                if schema_type == "array" {
                    if let Some(item_schema) = items.as_ref() {
                        let item_type = schema_to_alloy_type(item_schema, all_schemas)?;
                        Ok(format!("set {}", item_type))
                    } else {
                        Ok("set univ".to_string())
                    }
                } else {
                    Ok(map_primitive_type(schema_type))
                }
            } else {
                Ok("univ".to_string())
            }
        }
    }
}

/// Maps OpenAPI primitive types to Alloy types
fn map_primitive_type(openapi_type: &str) -> String {
    match openapi_type {
        "integer" | "number" => "Int".to_string(),
        "boolean" => "Bool".to_string(),
        "string" => "String".to_string(),
        _ => "univ".to_string()
    }
}

/// Generates Alloy definition for an API operation
fn generate_alloy_operation(
    operation_id: &str,
    method: &str,
    path: &str,
    operation: &crate::verifier::OpenApiOperation,
    _verbose: bool
) -> Result<String> {
    let mut definition = String::new();
    
    definition.push_str(&format!("// Operation: {} {}\n", method.to_uppercase(), path));
    if let Some(description) = &operation.description {
        definition.push_str(&format!("// {}\n", description.replace("\n", "\n// ")));
    }
    
    definition.push_str(&format!("one sig Operation_{} extends Operation {{\n", operation_id));
    definition.push_str(&format!("  id: {},\n", operation_id));
    definition.push_str(&format!("  path: \"{}\",\n", path));
    definition.push_str(&format!("  method: \"{}\",\n", method.to_uppercase()));
    
    // Handle request body
    if let Some(_req_body) = &operation.request_body {
        definition.push_str("  request: Request,\n");
    }
    
    // Handle responses
    definition.push_str("  responses: set Response\n");
    
    definition.push_str("}\n");
    
    // Add constraints for this operation
    definition.push_str(&format!("fact Operation_{}_Constraints {{\n", operation_id));
    
    // Response constraints
    for (status_code, _response) in &operation.responses {
        definition.push_str(&format!("  // Response for status code: {}\n", status_code));
        definition.push_str(&format!("  some r: Response | r.status = {} and r in Operation_{}.responses\n", 
            status_code, operation_id));
    }
    
    definition.push_str("}\n");
    
    Ok(definition)
}

/// Extracts the schema name from a reference string
/// For example, from "#/components/schemas/User" extracts "User"
fn extract_schema_name(reference: &str) -> Option<String> {
    let parts: Vec<&str> = reference.split('/').collect();
    if parts.len() >= 4 && parts[1] == "components" && parts[2] == "schemas" {
        Some(parts[3].to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    
    #[test]
    fn test_extract_schema_name() {
        assert_eq!(extract_schema_name("#/components/schemas/User"), Some("User".to_string()));
        assert_eq!(extract_schema_name("#/components/schemas/Error"), Some("Error".to_string()));
        assert_eq!(extract_schema_name("invalid/reference"), None);
    }
    
    #[test]
    fn test_map_primitive_type() {
        assert_eq!(map_primitive_type("integer"), "Int");
        assert_eq!(map_primitive_type("number"), "Int");
        assert_eq!(map_primitive_type("boolean"), "Bool");
        assert_eq!(map_primitive_type("string"), "String");
        assert_eq!(map_primitive_type("unknown"), "univ");
    }
}
