use std::collections::HashSet;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use anyhow::{Result, bail};
use indicatif::{ProgressBar, ProgressStyle};

use crate::stream::BufferedLineStream;
use crate::wire_analyzer::WireUsageReport;

/// Memory simulation results with periodic snapshots
#[derive(Debug)]
pub struct MemorySimulationReport {
    /// Maximum number of live wires observed during simulation
    pub max_live_wires: usize,
    /// Final number of live wires (should be primary outputs)
    pub final_live_wires: usize,
    /// Total number of gates processed
    pub total_gates_processed: usize,
    /// Snapshots taken every 10,000 gates
    pub snapshots: Vec<MemorySnapshot>,
}

/// Snapshot of memory state at a specific point
#[derive(Debug)]
pub struct MemorySnapshot {
    /// Gate number when snapshot was taken
    pub gate_number: usize,
    /// Number of live wires at this point
    pub live_wire_count: usize,
}

/// Parsed gate information
#[derive(Debug)]
struct Gate {
    inputs: Vec<usize>,
    outputs: Vec<usize>,
}

/// Parse a single gate line into input/output wire lists
/// Bristol format: "2 1 466 466 467 XOR"
fn parse_gate_line(line: &str) -> Result<Gate> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    
    if tokens.len() < 4 {
        bail!("Invalid gate line: too few tokens: '{}'", line);
    }
    
    let num_inputs: usize = tokens[0].parse()
        .map_err(|_| anyhow::anyhow!("Invalid number of inputs: '{}'", tokens[0]))?;
    let num_outputs: usize = tokens[1].parse()
        .map_err(|_| anyhow::anyhow!("Invalid number of outputs: '{}'", tokens[1]))?;
    
    if tokens.len() < 2 + num_inputs + num_outputs + 1 {
        bail!("Invalid gate line: expected {} tokens, got {}: '{}'", 
              2 + num_inputs + num_outputs + 1, tokens.len(), line);
    }
    
    // Parse input wires
    let mut inputs = Vec::with_capacity(num_inputs);
    for i in 0..num_inputs {
        let wire_id: usize = tokens[2 + i].parse()
            .map_err(|_| anyhow::anyhow!("Invalid input wire ID: '{}'", tokens[2 + i]))?;
        inputs.push(wire_id);
    }
    
    // Parse output wires  
    let mut outputs = Vec::with_capacity(num_outputs);
    for i in 0..num_outputs {
        let wire_id: usize = tokens[2 + num_inputs + i].parse()
            .map_err(|_| anyhow::anyhow!("Invalid output wire ID: '{}'", tokens[2 + num_inputs + i]))?;
        outputs.push(wire_id);
    }
    
    Ok(Gate { inputs, outputs })
}

/// Simulate memory usage during circuit execution
/// 
/// This function simulates the memory requirements for executing a garbled circuit
/// by tracking which wires are "live" (actively needed) at any given time.
/// 
/// # Arguments
/// * `stream` - The line stream to process gates from
/// * `wire_report` - Wire usage analysis from wire_analyzer module
/// 
/// # Returns
/// * `Ok(MemorySimulationReport)` - Memory simulation results with snapshots
/// * `Err(anyhow::Error)` - Parse error or IO error
/// 
/// # Algorithm
/// 1. Start with primary input wires in the active set
/// 2. For each gate:
///    - Decrement usage count for input wires
///    - Remove input wires from active set if usage count reaches 0
///    - Add output wires to active set
/// 3. Take snapshots every 10,000 gates processed
/// 4. Track maximum number of live wires throughout simulation
pub fn simulate_memory_usage(
    stream: &mut BufferedLineStream,
    wire_report: &WireUsageReport
) -> Result<MemorySimulationReport> {
    // Initialize active wire set with primary inputs
    let mut active_wires: HashSet<usize> = wire_report.primary_input_wires.iter().cloned().collect();
    
    // Initialize wire usage counts (mutable copy)
    let mut remaining_usage = wire_report.wire_usage_counts.clone();
    
    // Tracking variables
    let mut max_live_wires = active_wires.len();
    let mut gate_number = 0;
    let mut snapshots = Vec::new();
    let mut line_number = 0;
    
    // Calculate expected number of gates from wire report
    let expected_gates = wire_report.total_wires - wire_report.primary_inputs;
    
    // Create a progress bar with estimated gate count
    let pb = ProgressBar::new(expected_gates as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}")
            .unwrap()
            .progress_chars("##-")
    );
    pb.set_message("Simulating memory usage...");
    
    // Process each gate
    while let Some(line_result) = stream.next_line() {
        line_number += 1;
        let line = line_result?;
        
        if line.trim().is_empty() {
            bail!("Empty line at line number {}", line_number);
        }
        
        let gate = parse_gate_line(line)?;
        gate_number += 1;
        
        // Process input wires: decrement usage and remove if no longer needed
        for &input_wire in &gate.inputs {
            if remaining_usage[input_wire] > 0 {
                remaining_usage[input_wire] -= 1;
                
                // Remove wire from active set if no longer needed
                if remaining_usage[input_wire] == 0 {
                    active_wires.remove(&input_wire);
                }
            }
        }
        
        // Add output wires to active set
        for &output_wire in &gate.outputs {
            active_wires.insert(output_wire);
        }
        
        // Update maximum live wires
        if active_wires.len() > max_live_wires {
            max_live_wires = active_wires.len();
        }
        
        // Take snapshot every 10,000 gates
        if gate_number % 10000 == 0 {
            snapshots.push(MemorySnapshot {
                gate_number,
                live_wire_count: active_wires.len(),
            });
        }
        
        // Update progress bar every 10000 gates
        if gate_number % 10000 == 0 {
            pb.set_position(gate_number as u64);
            pb.set_message(format!("{} live wires", active_wires.len()));
        }
    }
    
    // Finish progress bar
    pb.finish_with_message(format!("✓ Simulated {} gates, max {} live wires", gate_number, max_live_wires));
    
    Ok(MemorySimulationReport {
        max_live_wires,
        final_live_wires: active_wires.len(),
        total_gates_processed: gate_number,
        snapshots,
    })
}

impl MemorySimulationReport {
    /// Export simulation results to CSV file
    /// 
    /// # Arguments
    /// * `path` - Path to write CSV file
    /// 
    /// # CSV Format
    /// ```csv
    /// gate_number,live_wire_count
    /// 10000,1250
    /// 20000,1180
    /// ```
    pub fn export_csv<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        // Create a spinner progress bar for CSV export
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.green} [{elapsed_precise}] {msg}")
                .unwrap()
        );
        pb.set_message("Writing CSV file...");
        
        let mut file = File::create(path)?;
        
        // Write CSV header
        writeln!(file, "gate_number,live_wire_count")?;
        
        // Write snapshots
        for snapshot in &self.snapshots {
            writeln!(file, "{},{}", snapshot.gate_number, snapshot.live_wire_count)?;
        }
        
        pb.finish_with_message("✓ CSV file saved");
        Ok(())
    }
    
    /// Print summary statistics to console
    pub fn print_summary(&self) {
        println!("Memory Simulation Summary:");
        println!("  Total gates processed: {}", self.total_gates_processed);
        println!("  Maximum live wires: {}", self.max_live_wires);
        println!("  Final live wires: {}", self.final_live_wires);
        println!("  Snapshots taken: {}", self.snapshots.len());
        
        if !self.snapshots.is_empty() {
            println!("  First snapshot: gate {}, {} live wires", 
                     self.snapshots[0].gate_number, 
                     self.snapshots[0].live_wire_count);
            println!("  Last snapshot: gate {}, {} live wires", 
                     self.snapshots.last().unwrap().gate_number, 
                     self.snapshots.last().unwrap().live_wire_count);
        }
    }
}