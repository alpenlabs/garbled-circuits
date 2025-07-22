use std::fs::File;
use std::path::PathBuf;
use clap::Parser;
use anyhow::{Result, bail};

use gc::stream::BufferedLineStream;
use gc::counter::count_gate_types;
use gc::wire_analyzer::analyze_wire_usage;
use gc::garbler::garble_circuit;

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


fn main() -> Result<()> {
    let args = Args::parse();

    // Open file
    let file = File::open(&args.file)?;
    
    // Create streaming reader with default buffer size
    let mut stream = BufferedLineStream::new(file);
    
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
            // Load 32-byte seed from file
            let seed_data = std::fs::read(&seed_file)?;
            if seed_data.len() != 32 {
                bail!("Seed file must contain exactly 32 bytes, got {}", seed_data.len());
            }
            let mut seed_array = [0u8; 32];
            seed_array.copy_from_slice(&seed_data);
            
            // Garble the circuit
            let garbling_result = garble_circuit(&mut stream, &seed_array)?;
            
            // Determine output paths
            let labels_path = output.as_ref().map(|p| {
                let mut path = p.clone();
                path.set_extension("labels.json");
                path
            }).unwrap_or_else(|| {
                let mut path = args.file.clone();
                path.set_extension("labels.json");
                path
            });
            
            let tables_path = output.unwrap_or_else(|| {
                let mut path = args.file.clone();
                path.set_extension("garbled");
                path
            });
            
            // Save results
            garbling_result.save(&labels_path, &tables_path)?;
            
            println!("Garbling completed:");
            println!("  Wire labels saved to: {}", labels_path.display());
            println!("  Garbled tables saved to: {}", tables_path.display());
            println!("  Input wires: {}", garbling_result.wire_labels.input_labels.len());
            println!("  Output wires: {}", garbling_result.wire_labels.output_labels.len());
            println!("  AND gates: {}", garbling_result.garbled_tables.len());
        }
    }
    
    Ok(())
}
