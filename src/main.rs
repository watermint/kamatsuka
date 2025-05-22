use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use colored::*;
use pest_derive::Parser as PestParserDerive;

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
        /// Path to Stone DSL file
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
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    
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
    }
}

fn verify_stone_command(path: &str, verbose: bool) -> Result<()> {
    println!("{}", "Stone DSL Verification".green().bold());
    println!("Path: {}", path.cyan());
    println!();
    
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
    if verbose {
        println!("Converting Stone DSL to OpenAPI...");
        println!("Input: {}", stone_path);
        println!("Output: {}", output_path);
    }
    
    let openapi_spec = converter::convert_stone_to_openapi(stone_path, base_url)?;
    
    if verbose {
        println!("✓ Successfully parsed Stone DSL");
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