use std::fs::File;
use std::path::PathBuf;
use clap::Parser;
use anyhow::{Result, bail};

use gc::stream::BufferedLineStream;
use gc::counter::count_gate_types;
use gc::wire_analyzer::{analyze_wire_usage, WireUsageReport};
use gc::memory_simulation::simulate_memory_usage;
use gc::garbler::{garble_circuit, WireLabels};
use gc::ot_simulation::simulate_ot;
use gc::evaluator::evaluate_circuit;

/// High-performance Bristol circuit file analyzer
#[derive(Parser, Debug)]
#[command(name = "gc")]
#[command(about = "Bristol circuit file analysis and processing")]
#[command(version)]
#[command(subcommand_required = true)]
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Parser, Debug)]
enum Commands {
    /// Count occurrences of each gate type
    Count {
        /// Path to the Bristol circuit file
        #[arg(help = "Bristol circuit file to process")]
        file: PathBuf,
    },
    /// Analyze wire usage patterns and connectivity
    WireAnalysis {
        /// Path to the Bristol circuit file
        #[arg(help = "Bristol circuit file to process")]
        file: PathBuf,
        /// Output file for wire analysis (default: <input>.wire_analysis)
        #[arg(
            short = 'o',
            long = "output",
            help = "Output file for wire analysis results"
        )]
        output: Option<PathBuf>,
    },
    /// Simulate memory usage during circuit execution
    MemorySimulation {
        /// Path to the Bristol circuit file
        #[arg(help = "Bristol circuit file to process")]
        file: PathBuf,
        /// Wire analysis file (required for memory simulation)
        #[arg(
            short = 'w',
            long = "wire-analysis",
            help = "Wire analysis file (.wire_analysis)"
        )]
        wire_analysis_file: PathBuf,
        /// Output CSV file for memory snapshots (default: <input>.memory_sim.csv)
        #[arg(
            short = 'o',
            long = "output",
            help = "Output CSV file for memory simulation results"
        )]
        output: Option<PathBuf>,
    },
    /// Garble a Bristol circuit file using the provided seed
    Garble {
        /// Path to the Bristol circuit file
        #[arg(help = "Bristol circuit file to process")]
        file: PathBuf,
        /// Binary file containing wire usage analysis
        #[arg(
            short = 'w',
            long = "wire-analysis", 
            help = "Binary file containing wire usage analysis"
        )]
        wire_analysis_file: PathBuf,
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
    /// Simulate OT protocol to select input wire labels
    OtSimulate {
        /// Wire labels file from garbler output
        #[arg(
            short = 'w',
            long = "wire-labels",
            help = "Wire labels JSON file from garbler"
        )]
        wire_labels_file: PathBuf,
        /// File containing seed for OT simulation
        #[arg(
            short = 's',
            long = "seed-file",
            help = "File containing seed for OT simulation"
        )]
        seed_file: PathBuf,
        /// Output file for OT results (default: <input>.ot.json)
        #[arg(
            short = 'o',
            long = "output",
            help = "Output file for OT simulation results"
        )]
        output: Option<PathBuf>,
    },
    /// Evaluate a garbled circuit using OT-selected input labels
    Evaluate {
        /// Path to the Bristol circuit file
        #[arg(help = "Bristol circuit file to process")]
        file: PathBuf,
        /// Binary file containing wire usage analysis
        #[arg(
            short = 'w',
            long = "wire-analysis",
            help = "Binary file containing wire usage analysis"
        )]
        wire_analysis_file: PathBuf,
        /// OT simulation results file
        #[arg(
            short = 't',
            long = "ot-result",
            help = "OT simulation results JSON file"
        )]
        ot_result_file: PathBuf,
        /// Garbled tables binary file
        #[arg(
            short = 'g',
            long = "garbled-tables",
            help = "Garbled tables binary file from garbler"
        )]
        garbled_tables_file: PathBuf,
        /// Output file for evaluation results (default: <input>.eval.json)
        #[arg(
            short = 'o',
            long = "output",
            help = "Output file for evaluation results"
        )]
        output: Option<PathBuf>,
    },
}


fn main() -> Result<()> {
    let args = Args::parse();

    match args.command {
        Commands::Count { file } => {
            // Open file and create streaming reader
            let file_handle = File::open(&file)?;
            let mut stream = BufferedLineStream::new(file_handle);
            
            // Count gate types
            let counts = count_gate_types(&mut stream)?;
            
            // Output as JSON
            let json_output = serde_json::to_string_pretty(&counts)?;
            println!("{}", json_output);
        }
        Commands::WireAnalysis { file, output } => {
            // Open file and create streaming reader
            let file_handle = File::open(&file)?;
            let mut stream = BufferedLineStream::new(file_handle);
            
            // Perform wire usage analysis
            let wire_report = analyze_wire_usage(&mut stream)?;
            
            // Determine output file
            let output_path = output.unwrap_or_else(|| {
                let mut path = file.clone();
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
        Commands::MemorySimulation { file, wire_analysis_file, output } => {
            // Open file and create streaming reader
            let file_handle = File::open(&file)?;
            let mut stream = BufferedLineStream::new(file_handle);
            
            // Load wire analysis report
            let wire_report = WireUsageReport::load_binary(&wire_analysis_file)?;
            
            // Perform memory simulation
            let memory_report = simulate_memory_usage(&mut stream, &wire_report)?;
            
            // Determine output file
            let output_path = output.unwrap_or_else(|| {
                let mut path = file.clone();
                path.set_extension("memory_sim.csv");
                path
            });
            
            // Export CSV results
            memory_report.export_csv(&output_path)?;
            
            // Print summary
            memory_report.print_summary();
            println!("Memory simulation results saved to: {}", output_path.display());
        }
        Commands::Garble { file, wire_analysis_file, seed_file, output } => {
            // Load wire usage analysis
            println!("Loading wire analysis from: {}", wire_analysis_file.display());
            let wire_report = WireUsageReport::load_binary(&wire_analysis_file)?;
            
            // Open file and create streaming reader
            let file_handle = File::open(&file)?;
            let mut stream = BufferedLineStream::new(file_handle);
            
            // Load 32-byte seed from file
            let seed_data = std::fs::read(&seed_file)?;
            if seed_data.len() != 32 {
                bail!("Seed file must contain exactly 32 bytes, got {}", seed_data.len());
            }
            let mut seed_array = [0u8; 32];
            seed_array.copy_from_slice(&seed_data);
            
            // Garble the circuit
            let garbling_result = garble_circuit(&mut stream, &wire_report, &seed_array)?;
            
            // Determine output paths
            let labels_path = output.as_ref().map(|p| {
                let mut path = p.clone();
                path.set_extension("labels.json");
                path
            }).unwrap_or_else(|| {
                let mut path = file.clone();
                path.set_extension("labels.json");
                path
            });
            
            let tables_path = output.unwrap_or_else(|| {
                let mut path = file.clone();
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
        Commands::OtSimulate { wire_labels_file, seed_file, output } => {
            // Load wire labels from garbler output
            println!("Loading wire labels from: {}", wire_labels_file.display());
            let wire_labels = WireLabels::load_json(&wire_labels_file)?;
            
            // Load 32-byte seed from file
            let seed_data = std::fs::read(&seed_file)?;
            if seed_data.len() != 32 {
                bail!("Seed file must contain exactly 32 bytes, got {}", seed_data.len());
            }
            let mut seed_array = [0u8; 32];
            seed_array.copy_from_slice(&seed_data);
            
            // Simulate OT protocol
            let ot_result = simulate_ot(&wire_labels, &seed_array)?;
            
            // Determine output file
            let output_path = output.unwrap_or_else(|| {
                let mut path = wire_labels_file.clone();
                path.set_extension("ot.json");
                path
            });
            
            // Save OT results
            ot_result.save_json(&output_path)?;
            
            println!("OT simulation completed:");
            println!("  Selected inputs: {}", ot_result.selected_inputs.len());
            println!("  Results saved to: {}", output_path.display());
        }
        Commands::Evaluate { file, wire_analysis_file, ot_result_file, garbled_tables_file, output } => {
            // Load wire usage analysis
            println!("Loading wire analysis from: {}", wire_analysis_file.display());
            let wire_report = WireUsageReport::load_binary(&wire_analysis_file)?;
            
            // Load OT simulation results
            println!("Loading OT results from: {}", ot_result_file.display());
            let ot_result = gc::ot_simulation::OTResult::load_json(&ot_result_file)?;
            
            // Open circuit file and create streaming reader
            let file_handle = File::open(&file)?;
            let mut stream = BufferedLineStream::new(file_handle);
            
            // Evaluate the circuit
            let evaluation_result = evaluate_circuit(&mut stream, &wire_report, &ot_result, &garbled_tables_file)?;
            
            // Determine output file
            let output_path = output.unwrap_or_else(|| {
                let mut path = file.clone();
                path.set_extension("eval.json");
                path
            });
            
            // Save evaluation results
            evaluation_result.save_json(&output_path)?;
            
            // Print summary
            evaluation_result.print_summary();
            println!("Evaluation results saved to: {}", output_path.display());
        }
    }
    
    Ok(())
}
