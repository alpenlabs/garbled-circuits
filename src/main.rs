use std::fs::File;
use std::path::PathBuf;
use clap::Parser;
use anyhow::Result;

use manage_io::stream::BufferedLineStream;
use manage_io::counter::count_gate_types;
use manage_io::wire_analyzer::analyze_wire_usage;

/// High-performance Bristol circuit file analyzer
#[derive(Parser, Debug)]
#[command(name = "manage_io")]
#[command(about = "Count gate types in Bristol circuit files")]
#[command(version)]
struct Args {
    /// Path to the Bristol circuit file
    #[arg(help = "Bristol circuit file to analyze")]
    file: PathBuf,

    /// Buffer size for reading (e.g., 128MB, 256MB, 512MB)
    #[arg(
        short = 'b',
        long = "buffer-size", 
        default_value = "256MB",
        help = "Buffer size for file reading (supports MB/GB suffixes)"
    )]
    buffer_size: String,

    /// Analyze wire usage and save binary report
    #[arg(
        short = 'w',
        long = "wire-analysis",
        help = "Perform wire usage analysis and save binary report"
    )]
    wire_analysis: bool,

    /// Output file for wire analysis (default: <input>.wire_analysis)
    #[arg(
        short = 'o',
        long = "output",
        help = "Output file for wire analysis results"
    )]
    output: Option<PathBuf>,
}

/// Parse buffer size string (e.g., "64MB", "128MB", "1GB") to bytes
fn parse_buffer_size(size_str: &str) -> Result<usize> {
    let size_str = size_str.to_uppercase();
    
    if let Some(num_str) = size_str.strip_suffix("GB") {
        let num: f64 = num_str.parse()?;
        Ok((num * 1024.0 * 1024.0 * 1024.0) as usize)
    } else if let Some(num_str) = size_str.strip_suffix("MB") {
        let num: f64 = num_str.parse()?;
        Ok((num * 1024.0 * 1024.0) as usize)
    } else if let Some(num_str) = size_str.strip_suffix("KB") {
        let num: f64 = num_str.parse()?;
        Ok((num * 1024.0) as usize)
    } else {
        // Assume bytes if no suffix
        Ok(size_str.parse()?)
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Parse buffer size
    let buffer_size = parse_buffer_size(&args.buffer_size)?;

    // Open file
    let file = File::open(&args.file)?;
    
    // Create streaming reader with specified buffer size
    let mut stream = BufferedLineStream::with_buffer_size(file, buffer_size);
    
    if args.wire_analysis {
        // Perform wire usage analysis
        let wire_report = analyze_wire_usage(&mut stream)?;
        
        // Determine output file
        let output_path = args.output.unwrap_or_else(|| {
            let mut path = args.file.clone();
            path.set_extension("wire_analysis");
            path
        });
        
        // Save binary report
        wire_report.save_binary(&output_path)?;
        
        // Print summary
        println!("Wire analysis saved to: {}", output_path.display());
        println!("Total wires: {}", wire_report.total_wires);
        println!("Primary inputs: {}", wire_report.primary_inputs);
        println!("Intermediate wires: {}", wire_report.intermediate_wires);
        println!("Primary outputs: {}", wire_report.primary_outputs);
        println!("Missing/unused wires: {}", wire_report.missing_wires_count);
        
    } else {
        // Default: Count gate types
        let counts = count_gate_types(&mut stream)?;
        
        // Output as JSON
        let json_output = serde_json::to_string_pretty(&counts)?;
        println!("{}", json_output);
    }
    
    Ok(())
}
