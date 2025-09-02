use anyhow::{Result, bail};
use indicatif::{ProgressBar, ProgressStyle};
use std::collections::HashSet;
use std::fs::File;
use std::io::Write;
use std::path::Path;

use crate::constants::PROGRESS_UPDATE_INTERVAL;
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

/// Simulate memory usage during circuit execution
/// Uses wire analysis data for memory-efficient simulation
///
/// Expected format:
/// First line: `<num_gates> <num_wires>`
/// Followed by gate lines in Bristol format
///
/// This function simulates the memory requirements for executing a garbled circuit
/// by tracking which wires are "live" (actively needed) at any given time.
///
/// # Arguments
/// * `stream` - The line stream to process Bristol circuit
/// * `wire_report` - Wire usage analysis from wire_analyzer module
///
/// # Returns
/// * `Ok(MemorySimulationReport)` - Memory simulation results with snapshots
/// * `Err(anyhow::Error)` - Parse error or IO error
///
/// # Algorithm
/// 1. Parse and validate Bristol format header
/// 2. Start with primary input wires in the active set
/// 3. For each gate:
///    - Decrement usage count for input wires
///    - Remove input wires from active set if usage count reaches 0
///    - Add output wires to active set
/// 4. Take snapshots every PROGRESS_UPDATE_INTERVAL gates processed
/// 5. Track maximum number of live wires throughout simulation
pub fn simulate_memory_usage(
    stream: &mut BufferedLineStream,
    wire_report: &WireUsageReport,
) -> Result<MemorySimulationReport> {
    // Parse and validate header line
    let header_line = stream
        .next_line()
        .ok_or_else(|| anyhow::anyhow!("Missing header line"))??;

    let header_tokens: Vec<&str> = header_line.split_whitespace().collect();
    if header_tokens.len() != 2 {
        bail!(
            "Invalid header: expected '<num_gates> <num_wires>', got: '{}'",
            header_line
        );
    }

    // Parse header values - use num_gates for progress bar
    let num_gates: u32 = header_tokens[0]
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid num_gates: '{}'", header_tokens[0]))?;
    let _num_wires: u32 = header_tokens[1]
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid num_wires: '{}'", header_tokens[1]))?;

    // Initialize active wire set with primary inputs (convert to u32)
    let mut active_wires: HashSet<u32> = wire_report.primary_input_wires.iter().cloned().collect();

    // Initialize wire usage counts (mutable copy)
    let mut remaining_usage = wire_report.wire_usage_counts.clone();

    // Tracking variables
    let mut max_live_wires = active_wires.len();
    let mut gate_number = 0u32;
    let mut snapshots = Vec::new();
    let mut line_number = 0u32;

    // Create progress bar for gate processing (use actual count from header)
    let pb = ProgressBar::new(num_gates as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}")
            .unwrap()
            .progress_chars("##-"),
    );
    pb.set_message("Simulating memory usage...");

    // Process each gate as we read it (streaming approach - matches garbler.rs)
    while let Some(line_result) = stream.next_line() {
        line_number += 1;
        let line = line_result?;

        if line.trim().is_empty() {
            bail!("Empty line at line number {}", line_number);
        }

        // Parse gate line directly using iterator (more efficient - matches garbler.rs)
        let mut tokens = line.split_whitespace();

        // Parse num_inputs and num_outputs
        let num_inputs: u32 = tokens
            .next()
            .ok_or_else(|| anyhow::anyhow!("Missing num_inputs at line {}", line_number))?
            .parse()
            .map_err(|_| {
                anyhow::anyhow!("Invalid num_inputs at line {}: '{}'", line_number, line)
            })?;

        let num_outputs: u32 = tokens
            .next()
            .ok_or_else(|| anyhow::anyhow!("Missing num_outputs at line {}", line_number))?
            .parse()
            .map_err(|_| {
                anyhow::anyhow!("Invalid num_outputs at line {}: '{}'", line_number, line)
            })?;

        // Process input wires directly (no intermediate allocation)
        for i in 0..num_inputs {
            let input_wire: u32 = tokens
                .next()
                .ok_or_else(|| anyhow::anyhow!("Missing input wire {} at line {}", i, line_number))?
                .parse()
                .map_err(|_| {
                    anyhow::anyhow!("Invalid input wire ID at line {}: '{}'", line_number, line)
                })?;

            // Add bounds checking for array access
            if (input_wire as usize) < remaining_usage.len()
                && remaining_usage[input_wire as usize] > 0
            {
                // Wires with count 255 are never decremented (permanent wires)
                if remaining_usage[input_wire as usize] < 255 {
                    remaining_usage[input_wire as usize] -= 1;
                }

                // Remove wire from active set if no longer needed
                if remaining_usage[input_wire as usize] == 0 {
                    active_wires.remove(&input_wire);
                }
            }
        }

        // Process output wires directly (no intermediate allocation)
        for i in 0..num_outputs {
            let output_wire: u32 = tokens
                .next()
                .ok_or_else(|| {
                    anyhow::anyhow!("Missing output wire {} at line {}", i, line_number)
                })?
                .parse()
                .map_err(|_| {
                    anyhow::anyhow!("Invalid output wire ID at line {}: '{}'", line_number, line)
                })?;

            active_wires.insert(output_wire);
        }

        // Parse gate type (last token)
        let _gate_type = tokens.next().ok_or_else(|| {
            anyhow::anyhow!("Missing gate type at line {}: '{}'", line_number, line)
        })?;

        // Validate no extra tokens
        if tokens.next().is_some() {
            bail!("Too many tokens at line {}: '{}'", line_number, line);
        }

        gate_number += 1;

        // Update maximum live wires
        if active_wires.len() > max_live_wires {
            max_live_wires = active_wires.len();
        }

        let gate_index: u32 = line_number - 1;

        if gate_index.is_multiple_of(PROGRESS_UPDATE_INTERVAL) {
            snapshots.push(MemorySnapshot {
                gate_number: gate_number as usize,
                live_wire_count: active_wires.len(),
            });
        }

        if gate_index.is_multiple_of(PROGRESS_UPDATE_INTERVAL) {
            pb.set_position(gate_index as u64);
            pb.set_message("Simulating memory usage...");
        }
    }

    // Finish progress bar
    pb.finish_with_message(format!(
        "✓ Simulated {line_number} gates, max {max_live_wires} live wires"
    ));

    Ok(MemorySimulationReport {
        max_live_wires,
        final_live_wires: active_wires.len(),
        total_gates_processed: line_number as usize,
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
                .unwrap(),
        );
        pb.set_message("Writing CSV file...");

        let mut file = File::create(path)?;

        // Write CSV header
        writeln!(file, "gate_number,live_wire_count")?;

        // Write snapshots
        for snapshot in &self.snapshots {
            writeln!(
                file,
                "{},{}",
                snapshot.gate_number, snapshot.live_wire_count
            )?;
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
            println!(
                "  First snapshot: gate {}, {} live wires",
                self.snapshots[0].gate_number, self.snapshots[0].live_wire_count
            );
            println!(
                "  Last snapshot: gate {}, {} live wires",
                self.snapshots.last().unwrap().gate_number,
                self.snapshots.last().unwrap().live_wire_count
            );
        }
    }
}
