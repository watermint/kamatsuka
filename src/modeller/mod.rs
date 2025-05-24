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

// Import the API limitations module
mod limits;
use limits::{extract_api_limits, generate_alloy_limits, ApiLimit};

// Define manual API limitations when they're not specified in the OpenAPI spec
const MANUAL_LIMITS: &[(&str, &str, &str, i64, &str)] = &[
    ("FileRequest", "User", "Count", 4000, "Maximum of 4000 file requests per user"),
    ("File", "User", "Size", 1_073_741_824, "Maximum file size of 1GB per file"),
    ("SharedFolder", "User", "Count", 100_000, "Maximum of 100,000 shared folders per user"),
    ("Member", "SharedFolder", "Count", 1000, "Maximum of 1000 members per shared folder"),
];

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
    
    // Add custom type definitions needed for the model
    alloy_content.push_str("// Custom type definitions\n");
    alloy_content.push_str("abstract sig Bool {}\n");
    alloy_content.push_str("one sig True extends Bool {}\n");
    alloy_content.push_str("one sig False extends Bool {}\n\n");
    
    // Define basic fact about Bool values
    alloy_content.push_str("fact BooleanValues {\n");
    alloy_content.push_str("  // Ensure Bool is partitioned into True and False\n");
    alloy_content.push_str("  Bool = True + False\n");
    alloy_content.push_str("}\n\n");
    
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
    
    // Add API limitations
    alloy_content.push_str("// API Limitations\n");
    alloy_content.push_str("fact APILimitations {\n");
    
    // Extract limitations from OpenAPI spec (currently returns empty list as placeholder)
    let mut api_limits = match extract_api_limits(openapi) {
        Ok(limits) => {
            if verbose {
                println!("Found {} API limitations in the OpenAPI spec", limits.len());
            }
            limits
        },
        Err(e) => {
            println!("Warning: Failed to extract API limitations: {}", e);
            Vec::new()
        }
    };
    
    // Add manual API limitations
    for (entity, scope, limit_type, value, description) in MANUAL_LIMITS {
        // Check if we already have this limitation
        let exists = api_limits.iter().any(|limit| 
            limit.entity == *entity && 
            limit.scope == *scope && 
            limit.limit_type == *limit_type
        );
        
        if !exists {
            if verbose {
                println!("Adding manual API limitation: {} {} per {}", value, entity, scope);
            }
            
            api_limits.push(ApiLimit {
                entity: entity.to_string(),
                scope: scope.to_string(),
                limit_type: limit_type.to_string(),
                value: *value,
                description: description.to_string(),
            });
        }
    }
    
    // Generate Alloy constraints for each limitation
    for limit in &api_limits {
        // Add a comment describing the limitation
        alloy_content.push_str(&format!("  // {}\n", limit.description));
        
        // Generate the appropriate Alloy constraint based on the limit type and scope
        match (limit.limit_type.as_str(), limit.scope.as_str()) {
            ("Count", "User") => {
                alloy_content.push_str(&format!(
                    "  all u: User | #{}.u <= {}\n",
                    limit.entity,
                    limit.value
                ));
            },
            ("Count", "Team") => {
                alloy_content.push_str(&format!(
                    "  all t: Team | #{}.t <= {}\n",
                    limit.entity,
                    limit.value
                ));
            },
            ("Count", "Global") => {
                alloy_content.push_str(&format!(
                    "  #{} <= {}\n",
                    limit.entity,
                    limit.value
                ));
            },
            ("Count", "SharedFolder") => {
                alloy_content.push_str(&format!(
                    "  all sf: SharedFolder | #{}.sf <= {}\n",
                    limit.entity,
                    limit.value
                ));
            },
            ("Size", _) => {
                alloy_content.push_str(&format!(
                    "  all f: {} | f.size <= {}\n",
                    limit.entity,
                    limit.value
                ));
            },
            ("Rate", _) => {
                // Rate limits are harder to model in Alloy since it's not temporal
                alloy_content.push_str(&format!(
                    "  // Rate limit: {} requests per timeframe for {}\n",
                    limit.value,
                    limit.scope
                ));
            },
            _ => {
                alloy_content.push_str(&format!(
                    "  // Unmodeled limit: {} {} per {}\n",
                    limit.value,
                    limit.limit_type,
                    limit.scope
                ));
            }
        }
        
        alloy_content.push_str("\n");
    }
    
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
    // Sanitize the schema name to ensure it's a valid Alloy identifier
    let safe_schema_name = sanitize_type_name(schema_name);
    let mut definition = String::new();
    
    match schema {
        OpenApiSchema::Reference { reference } => {
            // Handle reference schemas
            let ref_name = extract_schema_name(reference)
                .ok_or_else(|| anyhow::anyhow!("Invalid reference: {}", reference))?;
            let safe_ref_name = sanitize_type_name(&ref_name);
            
            definition.push_str(&format!("// {} is an alias for {}\n", safe_schema_name, safe_ref_name));
            definition.push_str(&format!("sig {} {{\n", safe_schema_name));
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
                definition.push_str(&format!("abstract sig {} {{\n", safe_schema_name));
                definition.push_str("}\n\n");
                
                for (i, value) in enum_values.iter().enumerate() {
                    let enum_value = match value.as_str() {
                        Some(v) => sanitize_field_name(v),
                        None => format!("Value{}", i)
                    };
                    definition.push_str(&format!("one sig {}_{} extends {} {{\n", safe_schema_name, enum_value, safe_schema_name));
                    definition.push_str("}\n");
                }
            } else if let Some(schema_type) = schema_type {
                if schema_type == "object" {
                    // Handle object type
                    if let Some(all_of) = all_of {
                        // Handle inheritance/composition with allOf
                        let parent = match &all_of[0] {
                            OpenApiSchema::Reference { reference } => {
                                let parent_name = extract_schema_name(reference)
                                    .ok_or_else(|| anyhow::anyhow!("Invalid reference in allOf: {}", reference))?;
                                sanitize_type_name(&parent_name)
                            },
                            _ => "Object".to_string()
                        };
                        
                        definition.push_str(&format!("sig {} extends {} {{\n", safe_schema_name, parent));
                    } else {
                        definition.push_str(&format!("sig {} {{\n", safe_schema_name));
                    }
                    
                    // Add properties
                    if let Some(props) = properties {
                        let required_fields = required.as_ref().map_or_else(HashSet::new, |r| {
                            r.iter().collect::<HashSet<_>>()
                        });
                        
                        for (prop_name, prop_schema) in props {
                            // Process the property schema to get the field type
                            let (field_type, is_set) = process_field_type(prop_schema, all_schemas)?;
                            
                            // Determine the multiplicity
                            // For set types, we don't need lone - set already implies 0 or more
                            // For required fields, we don't need any multiplicity as it's exactly 1
                            // For optional non-set fields, we use 'lone' to indicate 0 or 1
                            let multiplicity = if is_set {
                                "set "
                            } else if !required_fields.contains(prop_name) {
                                "lone "
                            } else {
                                ""
                            };
                            
                            // Clean the property name to ensure it's a valid Alloy identifier
                            let clean_prop_name = sanitize_field_name(prop_name);
                            
                            // Add the field definition with proper formatting
                            // Always end with a comma to avoid syntax issues - Alloy is tolerant of trailing commas
                            definition.push_str(&format!("  {}: {}{},\n", clean_prop_name, multiplicity, field_type));
                        }
                    }
                    
                    definition.push_str("}\n");
                } else if schema_type == "array" {
                    // Handle array type
                    if let Some(item_schema) = items.as_ref() {
                        let item_type = schema_to_alloy_type(item_schema, all_schemas)?;
                        
                        definition.push_str(&format!("sig {} {{\n", safe_schema_name));
                        definition.push_str(&format!("  items: set {}\n", item_type));
                        definition.push_str("}\n");
                    } else {
                        definition.push_str(&format!("sig {} {{\n", safe_schema_name));
                        definition.push_str("  items: set univ\n");
                        definition.push_str("}\n");
                    }
                } else {
                    // Handle primitive types
                    definition.push_str(&format!("sig {} {{\n", safe_schema_name));
                    definition.push_str(&format!("  // Primitive type: {}\n", schema_type));
                    definition.push_str(&format!("  value: {}\n", sanitize_type_name(&map_primitive_type(schema_type))));
                    definition.push_str("}\n");
                }
            } else {
                // Generic object
                definition.push_str(&format!("sig {} {{\n", safe_schema_name));
                definition.push_str("  // Generic object with no specific type\n");
                definition.push_str("}\n");
            }
        }
    }
    
    Ok(definition)
}

/// Converts an OpenAPI schema to an Alloy type
/// Processes a field type to determine if it's a set and return the proper type name
/// Returns a tuple of (type_name, is_set)
fn process_field_type(
    schema: &OpenApiSchema,
    all_schemas: &HashMap<String, OpenApiSchema>
) -> Result<(String, bool)> {
    match schema {
        OpenApiSchema::Reference { reference } => {
            let ref_name = extract_schema_name(reference)
                .ok_or_else(|| anyhow::anyhow!("Invalid reference: {}", reference))?;
            // Sanitize the type name
            Ok((sanitize_type_name(&ref_name), false))
        },
        OpenApiSchema::Object { schema_type, items, .. } => {
            if let Some(schema_type) = schema_type {
                if schema_type == "array" {
                    if let Some(item_schema) = items.as_ref() {
                        // For arrays, we need to get the item type and mark as a set
                        let (item_type, _) = process_field_type(item_schema, all_schemas)?;
                        Ok((item_type, true))
                    } else {
                        Ok(("univ".to_string(), true))
                    }
                } else {
                    // For primitive types, sanitize and mark as not a set
                    let primitive_type = map_primitive_type(schema_type);
                    Ok((sanitize_type_name(&primitive_type), false))
                }
            } else {
                Ok(("univ".to_string(), false))
            }
        }
    }
}

/// Converts an OpenAPI schema to an Alloy type
fn schema_to_alloy_type(
    schema: &OpenApiSchema, 
    all_schemas: &HashMap<String, OpenApiSchema>
) -> Result<String> {
    // This function is now a simplified wrapper around process_field_type
    let (type_name, is_set) = process_field_type(schema, all_schemas)?;
    if is_set {
        Ok(format!("set {}", type_name))
    } else {
        Ok(type_name)
    }
}

/// Maps OpenAPI primitive types to Alloy types
fn map_primitive_type(openapi_type: &str) -> String {
    match openapi_type {
        "integer" | "number" => "Int".to_string(),
        "boolean" => "Bool".to_string(), // 'Bool' is not a native Alloy type, but we'll define it
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
    // Sanitize operation ID to ensure it's a valid Alloy identifier
    let safe_operation_id = sanitize_type_name(operation_id);
    let mut definition = String::new();
    
    definition.push_str(&format!("// Operation: {} {}\n", method.to_uppercase(), path));
    if let Some(description) = &operation.description {
        definition.push_str(&format!("// {}\n", description.replace("\n", "\n// ")));
    }
    
    // In Alloy, when a signature extends another, it inherits all fields
    // We'll define the operation signature and use a separate fact to set the field values
    definition.push_str(&format!("one sig Operation_{} extends Operation {{}}\n\n", safe_operation_id));
    
    // Add fact to set the field values
    definition.push_str(&format!("fact Operation_{}_FieldValues {{\n", safe_operation_id));
    definition.push_str(&format!("  Operation_{}.id = \"{}\"\n", safe_operation_id, operation_id));
    definition.push_str(&format!("  Operation_{}.path = \"{}\"\n", safe_operation_id, path));
    definition.push_str(&format!("  Operation_{}.method = \"{}\"\n", safe_operation_id, method.to_uppercase()));
    
    // Handle request body
    if let Some(_req_body) = &operation.request_body {
        definition.push_str(&format!("  // This operation has a request body\n"));
        definition.push_str(&format!("  some req: Request | req in Operation_{}.request\n", safe_operation_id));
    } else {
        definition.push_str(&format!("  // This operation has no request body\n"));
        definition.push_str(&format!("  no Operation_{}.request\n", safe_operation_id));
    }
    
    // Response constraints
    for (status_code, _response) in &operation.responses {
        definition.push_str(&format!("  // Response for status code: {}\n", status_code));
        definition.push_str(&format!("  some r: Response | r.status = {} and r in Operation_{}.responses\n", 
            status_code, safe_operation_id));
    }
    
    definition.push_str("}\n");
    
    Ok(definition)
}

/// Sanitizes a field name to ensure it's a valid Alloy identifier
/// Removes leading dots and replaces invalid characters
fn sanitize_field_name(field_name: &str) -> String {
    let clean_name = field_name.trim_start_matches('.');
    
    // Replace any other problematic characters
    if clean_name.is_empty() {
        // If the field name was just a dot or is empty, use a fallback name
        "field".to_string()
    } else if clean_name.chars().next().unwrap().is_numeric() {
        // If the field name starts with a number, prefix it
        format!("f_{}", clean_name)
    } else {
        clean_name.to_string()
    }
}

/// Sanitizes a type name to ensure it's a valid Alloy identifier
/// Handles special characters, reserved words, etc.
fn sanitize_type_name(type_name: &str) -> String {
    // List of Alloy reserved keywords to avoid
    let reserved_words = [
        "all", "abstract", "and", "as", "assert", "but", "check", "disj", "else", 
        "exactly", "extends", "fact", "for", "fun", "iden", "iff", "implies", 
        "in", "Int", "let", "lone", "module", "no", "none", "not", "one", 
        "open", "or", "pred", "run", "set", "sig", "some", "String", "sum", 
        "this", "univ"
    ];
    
    // Replace problematic characters
    let sanitized = type_name
        .replace('-', "_")
        .replace('.', "_")
        .replace(':', "_")
        .replace('/', "_");
    
    // Check if it's a reserved word
    if reserved_words.contains(&sanitized.to_lowercase().as_str()) {
        format!("Type_{}", sanitized)
    } else if sanitized.is_empty() {
        "UnknownType".to_string()
    } else if sanitized.chars().next().unwrap().is_numeric() {
        format!("Type_{}", sanitized)
    } else {
        sanitized
    }
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
