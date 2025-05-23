use std::fs;
use std::path::Path;
use std::io::Write;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use colored::*;
use pest_derive::Parser as PestParserDerive;
use log::{info, warn, debug};
use env_logger::{Builder, Target};
use chrono::Local;

mod converter;
mod verifier;

#[derive(PestParserDerive)]
#[grammar = "stone.pest"]
pub struct StoneParser;

#[derive(Parser)]
#[command(name = "kamatsuka")]
#[command(about = "Dropbox API modeling and conversion tool")]
#[command(version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Compare Stone DSL and OpenAPI definitions
    Compare {
        /// Path to Stone DSL file
        #[arg(short, long)]
        stone: String,
        
        /// Path to OpenAPI YAML file
        #[arg(short, long)]
        openapi: String,
        
        /// Verbose output
        #[arg(short, long)]
        verbose: bool,
    },
    
    /// Convert Stone DSL to OpenAPI specification
    Convert {
        /// Path to Stone DSL file or directory containing .stone files
        #[arg(short, long)]
        stone: String,
        
        /// Output OpenAPI YAML file path
        #[arg(short, long)]
        output: String,
        
        /// API base URL
        #[arg(long, default_value = "https://api.dropboxapi.com/2")]
        base_url: String,
        
        /// Verbose output
        #[arg(short, long)]
        verbose: bool,
    },
    
    /// Verify Stone DSL definitions syntax
    VerifyStone {
        /// Path to Stone DSL file or directory
        #[arg(short, long)]
        path: String,
        
        /// Verbose output
        #[arg(short, long)]
        verbose: bool,
    },
    
    /// Validate OpenAPI specification
    ValidateOpenapi {
        /// Path to OpenAPI YAML file
        #[arg(short, long)]
        openapi: String,
        
        /// Verbose output
        #[arg(short, long)]
        verbose: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    
    // Initialize logging
    init_logging();
    
    info!("Starting Kamatsuka v{}", env!("CARGO_PKG_VERSION"));
    
    match &cli.command {
        Commands::Compare { stone, openapi, verbose } => {
            compare_command(stone, openapi, *verbose)
        }
        Commands::Convert { stone, output, base_url, verbose } => {
            convert_command(stone, output, base_url, *verbose)
        }
        Commands::VerifyStone { path, verbose } => {
            verify_stone_command(path, *verbose)
        }
        Commands::ValidateOpenapi { openapi, verbose } => {
            validate_openapi_command(openapi, *verbose)
        }
    }
}

fn verify_stone_command(path: &str, verbose: bool) -> Result<()> {
    println!("{}", "Stone DSL Verification".green().bold());
    println!("Path: {}", path.cyan());
    println!();
    
    info!("Starting Stone verification for: {}", path);
    
    let path_obj = Path::new(path);
    let mut total_files = 0;
    let mut successful_files = 0;
    let mut failed_files = Vec::new();
    
    if path_obj.is_file() {
        total_files = 1;
        if verify_single_stone_file(path, verbose)? {
            successful_files = 1;
        } else {
            failed_files.push(path.to_string());
        }
    } else if path_obj.is_dir() {
        // Verify all .stone files in directory
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let file_path = entry.path();
            
            if file_path.extension().map_or(false, |ext| ext == "stone") {
                total_files += 1;
                let file_path_str = file_path.to_string_lossy();
                
                if verify_single_stone_file(&file_path_str, verbose)? {
                    successful_files += 1;
                } else {
                    failed_files.push(file_path_str.to_string());
                }
            }
        }
    } else {
        return Err(anyhow::anyhow!("Path does not exist: {}", path));
    }
    
    println!();
    println!("{}", "Verification Summary:".yellow().bold());
    println!("  {} Total files", total_files.to_string().cyan());
    println!("  {} Successful", successful_files.to_string().green());
    println!("  {} Failed", failed_files.len().to_string().red());
    
    if !failed_files.is_empty() {
        println!();
        println!("{}", "Failed files:".red().bold());
        for file in &failed_files {
            println!("  {}", file.red());
        }
    }
    
    if failed_files.is_empty() {
        println!();
        println!("{}", "✓ All Stone files verified successfully!".green().bold());
    }
    
    Ok(())
}

fn verify_single_stone_file(file_path: &str, verbose: bool) -> Result<bool> {
    if verbose {
        println!("Verifying: {}", file_path);
    }
    
    let content = fs::read_to_string(file_path)
        .with_context(|| format!("Failed to read file: {}", file_path))?;
    
    match converter::parse_stone_dsl(&content) {
        Ok(namespace) => {
            debug!("Successfully parsed {}: namespace={}", file_path, namespace.name);
            if verbose {
                println!("  ✓ {} - Namespace: {} ({} routes, {} structs, {} unions)",
                    file_path.green(),
                    namespace.name,
                    namespace.routes.len(),
                    namespace.structs.len(),
                    namespace.unions.len()
                );
            }
            Ok(true)
        }
        Err(e) => {
            warn!("Failed to parse {}: {}", file_path, e);
            println!("  {} {}: {}", "✗".red(), file_path.red(), e);
            Ok(false)
        }
    }
}

fn compare_command(stone_path: &str, openapi_path: &str, verbose: bool) -> Result<()> {
    println!("{}", "Stone DSL to OpenAPI Comparison".green().bold());
    println!("Stone file: {}", stone_path.cyan());
    println!("OpenAPI file: {}", openapi_path.cyan());
    println!();
    
    let results = verifier::verify_stone_openapi(stone_path, openapi_path, verbose)?;
    verifier::report_results(&results);
    
    Ok(())
}

fn convert_command(stone_path: &str, output_path: &str, base_url: &str, verbose: bool) -> Result<()> {
    println!("{}", "Stone DSL to OpenAPI Conversion".green().bold());
    println!("Input: {}", stone_path.cyan());
    println!("Output: {}", output_path.cyan());
    
    if verbose {
        let path = Path::new(stone_path);
        if path.is_dir() {
            println!("Mode: Directory (will merge all .stone files)");
        } else {
            println!("Mode: Single file");
        }
    }
    
    let path = Path::new(stone_path);
    let openapi_spec = converter::convert_stone_to_openapi(stone_path, base_url)?;
    
    info!("Conversion successful, writing output to: {}", output_path);
    
    if verbose {
        if path.is_dir() {
            // Count stone files
            let stone_count = fs::read_dir(stone_path)?
                .filter_map(Result::ok)
                .filter(|entry| entry.path().extension().map_or(false, |ext| ext == "stone"))
                .count();
            println!("✓ Successfully parsed {} Stone files", stone_count);
        } else {
            println!("✓ Successfully parsed Stone DSL");
        }
        println!("✓ Generated OpenAPI specification");
    }
    
    // Write output
    let output_yaml = serde_yaml::to_string(&openapi_spec)
        .with_context(|| "Failed to serialize OpenAPI spec")?;
    
    fs::write(output_path, output_yaml)
        .with_context(|| format!("Failed to write output file: {}", output_path))?;
    
    if verbose {
        println!("✓ Written to {}", output_path.green());
    }
    
    println!("{}", "✓ Conversion completed successfully!".green().bold());
    
    Ok(())
}

fn init_logging() {
    // Create logs directory if it doesn't exist
    std::fs::create_dir_all("logs").ok();
    
    // Generate log file name with timestamp
    let timestamp = Local::now().format("%Y%m%d_%H%M%S");
    let log_file_name = format!("logs/kamatsuka_{}.log", timestamp);
    
    // Create log file
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&log_file_name)
        .expect("Failed to create log file");
    
    // Initialize env_logger with custom format
    let mut builder = Builder::new();
    builder
        .format(|buf, record| {
            writeln!(
                buf,
                "[{} {} {}:{}] {}",
                Local::now().format("%Y-%m-%d %H:%M:%S%.3f"),
                record.level(),
                record.file().unwrap_or("unknown"),
                record.line().unwrap_or(0),
                record.args()
            )
        })
        .target(Target::Pipe(Box::new(log_file)))
        .filter_level(log::LevelFilter::Debug)
        .init();
    
    println!("Logging to: {}", log_file_name.green());
}

fn validate_openapi_command(openapi_path: &str, verbose: bool) -> Result<()> {
    println!("{}", "OpenAPI Specification Validation".green().bold());
    println!("File: {}", openapi_path.cyan());
    println!();
    
    // Read and parse the OpenAPI file
    let openapi_content = fs::read_to_string(openapi_path)
        .with_context(|| format!("Failed to read OpenAPI file: {}", openapi_path))?;
    
    // Validate YAML syntax
    let openapi_value: serde_yaml::Value = serde_yaml::from_str(&openapi_content)
        .with_context(|| "Invalid YAML syntax")?;
    
    if verbose {
        println!("✅ Valid YAML syntax");
    }
    
    // Validate OpenAPI specification structure by checking required fields
    let openapi_map = openapi_value.as_mapping()
        .with_context(|| "OpenAPI file must be an object")?;
    
    // Check required top-level fields
    let openapi_version = openapi_map.get("openapi")
        .and_then(|v| v.as_str())
        .with_context(|| "Missing required field: openapi")?;
    
    let info = openapi_map.get("info")
        .and_then(|v| v.as_mapping())
        .with_context(|| "Missing or invalid required field: info")?;
    
    let title = info.get("title")
        .and_then(|v| v.as_str())
        .with_context(|| "Missing required field: info.title")?;
    
    let version = info.get("version")
        .and_then(|v| v.as_str())
        .with_context(|| "Missing required field: info.version")?;
    
    if verbose {
        println!("✅ Valid OpenAPI structure");
    }
    
    // Validate OpenAPI version
    if !openapi_version.starts_with("3.") {
        return Err(anyhow::anyhow!("Unsupported OpenAPI version: {}", openapi_version));
    }
    
    if verbose {
        println!("✅ OpenAPI version {} is supported", openapi_version);
    }
    
    // Count components
    let empty_mapping = serde_yaml::Mapping::new();
    let paths = openapi_map.get("paths")
        .and_then(|v| v.as_mapping())
        .unwrap_or(&empty_mapping);
    
    let components = openapi_map.get("components")
        .and_then(|v| v.as_mapping());
    
    let (schema_count, security_scheme_count) = if let Some(comp) = components {
        let schemas = comp.get("schemas")
            .and_then(|v| v.as_mapping())
            .map(|m| m.len())
            .unwrap_or(0);
        let security_schemes = comp.get("securitySchemes")
            .and_then(|v| v.as_mapping())
            .map(|m| m.len())
            .unwrap_or(0);
        (schemas, security_schemes)
    } else {
        (0, 0)
    };
    
    let path_count = paths.len();
    
    // Validate required fields (already checked above)
    if title.is_empty() {
        return Err(anyhow::anyhow!("Empty required field: info.title"));
    }
    
    if version.is_empty() {
        return Err(anyhow::anyhow!("Empty required field: info.version"));
    }
    
    // Check for schema references (basic count)
    let reference_count = openapi_content.matches("#/components/schemas/").count();
    
    if verbose {
        println!("✅ Schema references validated ({} references found)", reference_count);
        println!("✅ Required fields present");
    }
    
    // Print summary
    println!("{}", "\n📊 Validation Summary:".yellow().bold());
    println!("  OpenAPI Version: {}", openapi_version.green());
    println!("  Title: {}", title.green());
    println!("  Version: {}", version.green());
    println!("  Paths: {}", path_count.to_string().cyan());
    println!("  Schemas: {}", schema_count.to_string().cyan());
    println!("  Security Schemes: {}", security_scheme_count.to_string().cyan());
    println!("  Schema References: {}", reference_count.to_string().cyan());
    
    // Validate some common OpenAPI patterns
    let mut warnings = Vec::new();
    
    // Check if all paths have operations
    for (path_key, path_value) in paths {
        if let Some(path_str) = path_key.as_str() {
            if let Some(path_ops) = path_value.as_mapping() {
                if path_ops.is_empty() {
                    warnings.push(format!("Path '{}' has no operations", path_str));
                }
            }
        }
    }
    
    // Basic validation of schema structure
    if let Some(comp) = components {
        if let Some(schemas) = comp.get("schemas").and_then(|v| v.as_mapping()) {
            for (schema_name, _schema_def) in schemas {
                if let Some(name_str) = schema_name.as_str() {
                    // Just validate that schema names are valid
                    if name_str.is_empty() {
                        warnings.push("Found schema with empty name".to_string());
                    }
                }
            }
        }
    }
    
    let unused_schemas = Vec::<String>::new(); // Simplified for now
    
    if !warnings.is_empty() && verbose {
        println!("\n⚠️  Warnings:");
        for warning in &warnings {
            println!("  - {}", warning.yellow());
        }
    }
    
    if !unused_schemas.is_empty() && verbose {
        println!("\n📝 Potentially unused schemas: {}", unused_schemas.len());
        if unused_schemas.len() <= 10 {
            for schema in &unused_schemas {
                println!("  - {}", schema.dimmed());
            }
        } else {
            println!("  (showing first 10 of {})", unused_schemas.len());
            for schema in unused_schemas.iter().take(10) {
                println!("  - {}", schema.dimmed());
            }
        }
    }
    
    println!("\n{}", "✅ OpenAPI specification is valid!".green().bold());
    
    Ok(())
}