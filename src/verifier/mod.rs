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
use std::fs;

use anyhow::{Context, Result};
use colored::*;
use pest::iterators::Pair;
use pest::Parser as PestParser;
use serde::Deserialize;

use crate::{StoneParser, Rule};

#[derive(Debug, Clone)]
pub struct StoneRoute {
    pub name: String,
    pub params: Vec<String>,
    pub description: Option<String>,
    pub attrs: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct StoneStruct {
    pub name: String,
    pub fields: Vec<StoneField>,
    pub extends: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone)]
pub struct StoneField {
    pub name: String,
    pub field_type: String,
    pub optional: bool,
    pub description: Option<String>,
}

#[derive(Debug, Clone)]
pub struct StoneUnion {
    pub name: String,
    pub variants: Vec<StoneVariant>,
    pub closed: bool,
    pub description: Option<String>,
}

#[derive(Debug, Clone)]
pub struct StoneVariant {
    pub name: String,
    pub variant_type: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone)]
pub struct StoneNamespace {
    pub name: String,
    pub description: Option<String>,
    pub routes: Vec<StoneRoute>,
    pub structs: Vec<StoneStruct>,
    pub unions: Vec<StoneUnion>,
    pub aliases: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
pub struct OpenApiSpec {
    pub openapi: String,
    pub info: OpenApiInfo,
    pub paths: HashMap<String, HashMap<String, OpenApiOperation>>,
    pub components: Option<OpenApiComponents>,
}

#[derive(Debug, Deserialize)]
pub struct OpenApiInfo {
    pub title: String,
    pub description: Option<String>,
    pub version: String,
}

#[derive(Debug, Deserialize)]
pub struct OpenApiOperation {
    #[serde(rename = "operationId")]
    pub operation_id: Option<String>,
    pub summary: Option<String>,
    pub description: Option<String>,
    #[serde(rename = "requestBody")]
    pub request_body: Option<OpenApiRequestBody>,
    pub responses: HashMap<String, OpenApiResponse>,
}

#[derive(Debug, Deserialize)]
pub struct OpenApiRequestBody {
    pub required: Option<bool>,
    pub content: HashMap<String, OpenApiMediaType>,
}

#[derive(Debug, Deserialize)]
pub struct OpenApiMediaType {
    pub schema: Option<OpenApiSchema>,
}

#[derive(Debug, Deserialize)]
pub struct OpenApiResponse {
    pub description: String,
    pub content: Option<HashMap<String, OpenApiMediaType>>,
}

#[derive(Debug, Deserialize)]
pub struct OpenApiComponents {
    pub schemas: Option<HashMap<String, OpenApiSchema>>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum OpenApiSchema {
    Reference {
        #[serde(rename = "$ref")]
        reference: String,
    },
    Object {
        #[serde(rename = "type")]
        schema_type: Option<String>,
        properties: Option<HashMap<String, OpenApiSchema>>,
        required: Option<Vec<String>>,
        #[serde(rename = "allOf")]
        all_of: Option<Vec<OpenApiSchema>>,
        items: Option<Box<OpenApiSchema>>,
        #[serde(rename = "enum")]
        enum_values: Option<Vec<serde_json::Value>>,
    },
}

#[derive(Debug)]
pub enum ComparisonResult {
    Match,
    Missing(String),
    Extra(String),
    Mismatch(String),
}

pub fn verify_stone_openapi(stone_path: &str, openapi_path: &str, verbose: bool) -> Result<Vec<ComparisonResult>> {
    // Parse Stone DSL
    let stone_content = fs::read_to_string(stone_path)
        .with_context(|| format!("Failed to read Stone file: {}", stone_path))?;
    
    let stone_namespace = parse_stone_dsl(&stone_content)
        .with_context(|| "Failed to parse Stone DSL")?;
    
    // Parse OpenAPI
    let openapi_content = fs::read_to_string(openapi_path)
        .with_context(|| format!("Failed to read OpenAPI file: {}", openapi_path))?;
    
    let openapi_spec: OpenApiSpec = serde_yaml::from_str(&openapi_content)
        .with_context(|| "Failed to parse OpenAPI YAML")?;
    
    // Compare
    let results = compare_specifications(&stone_namespace, &openapi_spec, verbose);
    
    Ok(results)
}

pub fn parse_stone_dsl(content: &str) -> Result<StoneNamespace> {
    let pairs = StoneParser::parse(Rule::spec, content)
        .map_err(|e| anyhow::anyhow!("Parse error: {}", e))?;
    
    let mut namespace = StoneNamespace {
        name: String::new(),
        description: None,
        routes: Vec::new(),
        structs: Vec::new(),
        unions: Vec::new(),
        aliases: HashMap::new(),
    };
    
    for pair in pairs {
        for inner_pair in pair.into_inner() {
            match inner_pair.as_rule() {
                Rule::spec_namespace => {
                    parse_namespace_def(inner_pair, &mut namespace)?;
                }
                Rule::spec_definition => {
                    // spec_definition contains the actual definitions
                    for def_pair in inner_pair.into_inner() {
                        match def_pair.as_rule() {
                            Rule::spec_route => {
                                let route = parse_route_def(def_pair)?;
                                namespace.routes.push(route);
                            }
                            Rule::spec_struct => {
                                let struct_def = parse_struct_def(def_pair)?;
                                namespace.structs.push(struct_def);
                            }
                            Rule::spec_union => {
                                let union_def = parse_union_def(def_pair)?;
                                namespace.unions.push(union_def);
                            }
                            Rule::spec_alias => {
                                let (name, alias_type) = parse_alias_def(def_pair)?;
                                namespace.aliases.insert(name, alias_type);
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
    }
    
    Ok(namespace)
}

fn parse_namespace_def(pair: Pair<Rule>, namespace: &mut StoneNamespace) -> Result<()> {
    for inner_pair in pair.into_inner() {
        match inner_pair.as_rule() {
            Rule::identity => {
                namespace.name = inner_pair.as_str().to_string();
            }
            Rule::spec_doc => {
                namespace.description = Some(parse_doc(inner_pair)?);
            }
            _ => {}
        }
    }
    Ok(())
}

fn parse_route_def(pair: Pair<Rule>) -> Result<StoneRoute> {
    let mut route = StoneRoute {
        name: String::new(),
        params: Vec::new(),
        description: None,
        attrs: HashMap::new(),
    };
    
    for inner_pair in pair.into_inner() {
        match inner_pair.as_rule() {
            Rule::identity_route => {
                route.name = inner_pair.as_str().to_string();
            }
            Rule::type_all => {
                // Routes have 3 type_all parameters inline
                route.params.push(inner_pair.as_str().trim().to_string());
            }
            Rule::spec_doc => {
                route.description = Some(parse_doc(inner_pair)?);
            }
            Rule::spec_route_attrs => {
                // Parse attributes block
                for attr_pair in inner_pair.into_inner() {
                    if let Rule::spec_route_attr = attr_pair.as_rule() {
                        let mut key = String::new();
                        let mut value = String::new();
                        for attr_inner in attr_pair.into_inner() {
                            match attr_inner.as_rule() {
                                Rule::identity => key = attr_inner.as_str().to_string(),
                                Rule::literal => value = attr_inner.as_str().to_string(),
                                _ => {}
                            }
                        }
                        if !key.is_empty() {
                            route.attrs.insert(key, value);
                        }
                    }
                }
            }
            _ => {}
        }
    }
    
    Ok(route)
}

fn parse_struct_def(pair: Pair<Rule>) -> Result<StoneStruct> {
    let mut struct_def = StoneStruct {
        name: String::new(),
        fields: Vec::new(),
        extends: None,
        description: None,
    };
    
    for inner_pair in pair.into_inner() {
        match inner_pair.as_rule() {
            Rule::identity => {
                struct_def.name = inner_pair.as_str().to_string();
            }
            Rule::spec_struct_extends => {
                for extends_pair in inner_pair.into_inner() {
                    if let Rule::identity_ref = extends_pair.as_rule() {
                        struct_def.extends = Some(extends_pair.as_str().trim().to_string());
                    }
                }
            }
            Rule::spec_doc => {
                struct_def.description = Some(parse_doc(inner_pair)?);
            }
            Rule::spec_struct_field => {
                let field = parse_field_def(inner_pair)?;
                struct_def.fields.push(field);
            }
            _ => {}
        }
    }
    
    Ok(struct_def)
}

fn parse_union_def(pair: Pair<Rule>) -> Result<StoneUnion> {
    let mut union_def = StoneUnion {
        name: String::new(),
        variants: Vec::new(),
        closed: false,
        description: None,
    };
    
    // Check if it starts with "union_closed" or "union"
    let rule_str = pair.as_str();
    if rule_str.starts_with("union_closed") {
        union_def.closed = true;
    }
    
    for inner_pair in pair.into_inner() {
        match inner_pair.as_rule() {
            Rule::identity => {
                union_def.name = inner_pair.as_str().to_string();
            }
            Rule::spec_doc => {
                union_def.description = Some(parse_doc(inner_pair)?);
            }
            Rule::spec_union_tag => {
                let variant = parse_union_tag(inner_pair)?;
                union_def.variants.push(variant);
            }
            Rule::spec_union_void_tag => {
                let variant = parse_union_void_tag(inner_pair)?;
                union_def.variants.push(variant);
            }
            _ => {}
        }
    }
    
    Ok(union_def)
}

fn parse_field_def(pair: Pair<Rule>) -> Result<StoneField> {
    let mut field = StoneField {
        name: String::new(),
        field_type: String::new(),
        optional: false,
        description: None,
    };
    
    for inner_pair in pair.into_inner() {
        match inner_pair.as_rule() {
            Rule::identity => {
                field.name = inner_pair.as_str().to_string();
            }
            Rule::type_all_optional => {
                field.field_type = inner_pair.as_str().trim().to_string();
                field.optional = field.field_type.ends_with('?');
            }
            Rule::spec_doc => {
                field.description = Some(parse_doc(inner_pair)?);
            }
            _ => {}
        }
    }
    
    Ok(field)
}

fn parse_union_tag(pair: Pair<Rule>) -> Result<StoneVariant> {
    let mut variant = StoneVariant {
        name: String::new(),
        variant_type: None,
        description: None,
    };
    
    for inner_pair in pair.into_inner() {
        match inner_pair.as_rule() {
            Rule::identity => {
                variant.name = inner_pair.as_str().to_string();
            }
            Rule::type_all_optional => {
                variant.variant_type = Some(inner_pair.as_str().trim().to_string());
            }
            Rule::spec_doc => {
                variant.description = Some(parse_doc(inner_pair)?);
            }
            _ => {}
        }
    }
    
    Ok(variant)
}

fn parse_union_void_tag(pair: Pair<Rule>) -> Result<StoneVariant> {
    let mut variant = StoneVariant {
        name: String::new(),
        variant_type: None,
        description: None,
    };
    
    for inner_pair in pair.into_inner() {
        match inner_pair.as_rule() {
            Rule::identity => {
                variant.name = inner_pair.as_str().to_string();
            }
            Rule::spec_doc => {
                variant.description = Some(parse_doc(inner_pair)?);
            }
            _ => {}
        }
    }
    
    Ok(variant)
}

fn parse_alias_def(pair: Pair<Rule>) -> Result<(String, String)> {
    let mut name = String::new();
    let mut alias_type = String::new();
    
    for inner_pair in pair.into_inner() {
        match inner_pair.as_rule() {
            Rule::identity => {
                name = inner_pair.as_str().to_string();
            }
            Rule::type_all_optional => {
                alias_type = inner_pair.as_str().trim().to_string();
            }
            _ => {}
        }
    }
    
    Ok((name, alias_type))
}

fn parse_doc(pair: Pair<Rule>) -> Result<String> {
    for inner_pair in pair.into_inner() {
        if let Rule::literal_string = inner_pair.as_rule() {
            return Ok(inner_pair.as_str().trim_matches('"').to_string());
        }
    }
    Ok(String::new())
}

fn parse_union_void_variant(pair: Pair<Rule>) -> Result<StoneVariant> {
    parse_union_void_tag(pair)
}

fn compare_specifications(
    stone: &StoneNamespace,
    openapi: &OpenApiSpec,
    verbose: bool,
) -> Vec<ComparisonResult> {
    let mut results = Vec::new();
    
    // Compare routes vs paths
    for stone_route in &stone.routes {
        let expected_path = format!("/{}/{}", stone.name, stone_route.name);
        
        if let Some(path_methods) = openapi.paths.get(&expected_path) {
            if path_methods.contains_key("post") {
                results.push(ComparisonResult::Match);
                if verbose {
                    println!("✓ Route {} found in OpenAPI", stone_route.name.green());
                }
            } else {
                results.push(ComparisonResult::Mismatch(
                    format!("Route {} found but no POST method", stone_route.name)
                ));
            }
        } else {
            results.push(ComparisonResult::Missing(
                format!("Route {} not found in OpenAPI", stone_route.name)
            ));
        }
    }
    
    // Compare structs vs schemas
    if let Some(schemas) = &openapi.components.as_ref().and_then(|c| c.schemas.as_ref()) {
        for stone_struct in &stone.structs {
            if schemas.contains_key(&stone_struct.name) {
                results.push(ComparisonResult::Match);
                if verbose {
                    println!("✓ Struct {} found in OpenAPI", stone_struct.name.green());
                }
            } else {
                results.push(ComparisonResult::Missing(
                    format!("Struct {} not found in OpenAPI schemas", stone_struct.name)
                ));
            }
        }
    }
    
    // Check for extra OpenAPI paths not in Stone
    for (path, _) in &openapi.paths {
        let path_parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        if path_parts.len() >= 2 {
            let namespace_part = path_parts[0];
            let route_part = path_parts[1];
            
            if namespace_part == stone.name {
                let found = stone.routes.iter().any(|r| r.name == route_part);
                if !found {
                    results.push(ComparisonResult::Extra(
                        format!("OpenAPI path {} not found in Stone", path)
                    ));
                }
            }
        }
    }
    
    results
}

pub fn report_results(results: &[ComparisonResult]) {
    let mut matches = 0;
    let mut mismatches = 0;
    let mut missing = 0;
    let mut extra = 0;
    
    println!("{}", "Comparison Results:".yellow().bold());
    println!();
    
    for result in results {
        match result {
            ComparisonResult::Match => {
                matches += 1;
            }
            ComparisonResult::Missing(msg) => {
                missing += 1;
                println!("{} {}", "MISSING:".red().bold(), msg);
            }
            ComparisonResult::Extra(msg) => {
                extra += 1;
                println!("{} {}", "EXTRA:".blue().bold(), msg);
            }
            ComparisonResult::Mismatch(msg) => {
                mismatches += 1;
                println!("{} {}", "MISMATCH:".yellow().bold(), msg);
            }
        }
    }
    
    println!();
    println!("{}", "Summary:".green().bold());
    println!("  {} Matches", matches.to_string().green());
    println!("  {} Missing", missing.to_string().red());
    println!("  {} Extra", extra.to_string().blue());
    println!("  {} Mismatches", mismatches.to_string().yellow());
    
    if missing == 0 && extra == 0 && mismatches == 0 {
        println!();
        println!("{}", "✓ All checks passed!".green().bold());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    
    #[test]
    fn test_parse_stone_dsl() {
        let stone_content = "namespace test\n\nstruct User";
        
        let result = parse_stone_dsl(stone_content);
        assert!(result.is_ok());
        
        let namespace = result.unwrap();
        assert_eq!(namespace.name, "test");
        assert_eq!(namespace.structs.len(), 1);
    }
    
    #[test]
    fn test_comparison_result_counts() {
        let results = vec![
            ComparisonResult::Match,
            ComparisonResult::Missing("field1".to_string()),
            ComparisonResult::Extra("field2".to_string()),
            ComparisonResult::Mismatch("type mismatch".to_string()),
            ComparisonResult::Missing("field3".to_string()),
        ];
        
        let mut missing = 0;
        let mut extra = 0;
        let mut mismatches = 0;
        
        for result in &results {
            match result {
                ComparisonResult::Missing(_) => missing += 1,
                ComparisonResult::Extra(_) => extra += 1,
                ComparisonResult::Mismatch(_) => mismatches += 1,
                ComparisonResult::Match => {},
            }
        }
        
        assert_eq!(missing, 2);
        assert_eq!(extra, 1);
        assert_eq!(mismatches, 1);
    }
    
    #[test]
    fn test_create_stone_structs() {
        let stone_struct = StoneStruct {
            name: "User".to_string(),
            fields: vec![
                StoneField {
                    name: "id".to_string(),
                    field_type: "String".to_string(),
                    optional: false,
                    description: Some("User ID".to_string()),
                },
            ],
            extends: None,
            description: Some("User struct".to_string()),
        };
        
        assert_eq!(stone_struct.name, "User");
        assert_eq!(stone_struct.fields.len(), 1);
        assert_eq!(stone_struct.fields[0].name, "id");
        assert!(!stone_struct.fields[0].optional);
    }
    
    #[test]
    fn test_create_stone_unions() {
        let stone_union = StoneUnion {
            name: "Status".to_string(),
            variants: vec![
                StoneVariant {
                    name: "active".to_string(),
                    variant_type: None,
                    description: Some("Active status".to_string()),
                },
                StoneVariant {
                    name: "error".to_string(),
                    variant_type: Some("ErrorInfo".to_string()),
                    description: None,
                },
            ],
            closed: true,
            description: Some("Status union".to_string()),
        };
        
        assert_eq!(stone_union.name, "Status");
        assert_eq!(stone_union.variants.len(), 2);
        assert!(stone_union.closed);
        assert_eq!(stone_union.variants[1].variant_type, Some("ErrorInfo".to_string()));
    }
    
    #[test]
    fn test_create_openapi_schema() {
        // Test reference schema
        let ref_schema = OpenApiSchema::Reference {
            reference: "#/components/schemas/User".to_string(),
        };
        
        match ref_schema {
            OpenApiSchema::Reference { reference } => {
                assert_eq!(reference, "#/components/schemas/User");
            }
            _ => panic!("Expected Reference variant"),
        }
        
        // Test object schema
        let mut properties = HashMap::new();
        properties.insert("id".to_string(), OpenApiSchema::Object {
            schema_type: Some("string".to_string()),
            properties: None,
            required: None,
            all_of: None,
            items: None,
            enum_values: None,
        });
        
        let obj_schema = OpenApiSchema::Object {
            schema_type: Some("object".to_string()),
            properties: Some(properties),
            required: Some(vec!["id".to_string()]),
            all_of: None,
            items: None,
            enum_values: None,
        };
        
        match obj_schema {
            OpenApiSchema::Object { schema_type, properties, required, .. } => {
                assert_eq!(schema_type, Some("object".to_string()));
                assert!(properties.is_some());
                assert_eq!(required, Some(vec!["id".to_string()]));
            }
            _ => panic!("Expected Object variant"),
        }
    }
    
    #[test]
    fn test_report_results() {
        // This test ensures report_results doesn't panic
        let results = vec![
            ComparisonResult::Match,
            ComparisonResult::Missing("test".to_string()),
        ];
        
        // report_results prints to stdout, so we just ensure it doesn't panic
        report_results(&results);
    }
}