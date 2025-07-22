use std::fs::File;
use std::path::PathBuf;
use clap::Parser;
use anyhow::Result;

use gc::stream::BufferedLineStream;
use gc::counter::count_gate_types;
use gc::wire_analyzer::analyze_wire_usage;

/// High-performance Bristol circuit file analyzer
#[derive(Parser, Debug)]
#[command(name = "gc")]
#[command(about = "Bristol circuit file analysis and processing")]
#[command(version)]
#[command(args_conflicts_with_subcommands = true)]
#[command(subcommand_required = true)]
struct Args {
    #[command(subcommand)]
    command: Commands,

    /// Buffer size for reading (e.g., 128MB, 256MB, 512MB)
    #[arg(
        short = 'b',
        long = "buffer-size", 
        default_value = "256MB",
        global = true,
        help = "Buffer size for file reading (supports MB/GB suffixes)"
    )]
    buffer_size: String,

    /// Path to the Bristol circuit file
    #[arg(global = true, help = "Bristol circuit file to process")]
    file: PathBuf,
}

#[derive(Parser, Debug)]
enum Commands {
    /// Count occurrences of each gate type
    Count,
    /// Analyze wire usage patterns and connectivity
    WireAnalysis {
        /// Output file for wire analysis (default: <input>.wire_analysis)
        #[arg(
            short = 'o',
            long = "output",
            help = "Output file for wire analysis results"
        )]
        output: Option<PathBuf>,
    },
    /// Garble a Bristol circuit file using the provided seed
    Garble {
        /// File containing seed for the garbling process
        #[arg(
            short = 's',
            long = "seed-file",
            help = "File containing seed for the garbling process"
        )]
        seed_file: PathBuf,
        /// Output file for garbled circuit (default: <input>.garbled)
        #[arg(
            short = 'o',
            long = "output",
            help = "Output file for garbled circuit"
        )]
        output: Option<PathBuf>,
    },
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
    
    match args.command {
        Commands::Count => {
            // Count gate types
            let counts = count_gate_types(&mut stream)?;
            
            // Output as JSON
            let json_output = serde_json::to_string_pretty(&counts)?;
            println!("{}", json_output);
        }
        Commands::WireAnalysis { output } => {
            // Perform wire usage analysis
            let wire_report = analyze_wire_usage(&mut stream)?;
            
            // Determine output file
            let output_path = output.unwrap_or_else(|| {
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
        }
        Commands::Garble { seed_file, output } => {
            let output_path = output.unwrap_or_else(|| {
                let mut path = args.file.clone();
                path.set_extension("garbled");
                path
            });
            println!("Garbling {} with seed from {} to {} - to be implemented", 
                     args.file.display(), seed_file.display(), output_path.display());
        }
    }
    
    Ok(())
}
