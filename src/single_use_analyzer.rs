use anyhow::{Result, bail};
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize};

use crate::constants::PROGRESS_UPDATE_INTERVAL;
use crate::stream::BufferedLineStream;
use crate::wire_analyzer::WireUsageReport;

/// Results of single-use wire gate type analysis
#[derive(Debug, Serialize, Deserialize)]
pub struct SingleUseGateAnalysis {
    /// Number of single-use wires produced by AND gates
    pub single_use_and_gates: usize,
    /// Number of single-use wires produced by XOR gates  
    pub single_use_xor_gates: usize,
    /// Total single-use wires analyzed
    pub total_single_use_wires: usize,
}

/// Analyze gate types for wires with usage count = 1
/// Uses wire analysis data for efficient single-use wire identification
///
/// Expected format:
/// First line: `<num_gates> <num_wires>`
/// Followed by gate lines in Bristol format
///
/// Takes a Bristol circuit stream and wire usage report, then counts how many
/// single-use wires are produced by AND vs XOR gates.
///
/// # Arguments
/// * `stream` - Buffered stream of Bristol circuit format
/// * `wire_report` - Wire usage analysis results
///
/// # Returns
/// * `SingleUseGateAnalysis` with counts of AND/XOR gates producing single-use wires
///
/// # Algorithm
/// 1. Parse and validate Bristol format header
/// 2. For each gate, check if output wires have usage count = 1
/// 3. Count gate types (AND/XOR) that produce single-use wires
/// 4. Return analysis with detailed counts
pub fn analyze_single_use_gates(
    stream: &mut BufferedLineStream,
    wire_report: &WireUsageReport,
) -> Result<SingleUseGateAnalysis> {
    // Parse and validate header line (matches garbler.rs pattern)
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

    let mut single_use_and_gates = 0;
    let mut single_use_xor_gates = 0;
    let mut total_single_use_wires = 0;
    let mut line_number: u32 = 0;

    // Create progress bar for gate processing (use actual count from header)
    let pb = ProgressBar::new(num_gates as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}")
            .unwrap()
            .progress_chars("##-"),
    );
    pb.set_message("Analyzing single-use gate types...");

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

        // Skip input wire IDs (we don't need them for this analysis)
        for i in 0..num_inputs {
            let _input_wire: u32 = tokens
                .next()
                .ok_or_else(|| anyhow::anyhow!("Missing input wire {} at line {}", i, line_number))?
                .parse()
                .map_err(|_| {
                    anyhow::anyhow!("Invalid input wire ID at line {}: '{}'", line_number, line)
                })?;
        }

        // Process output wires directly (no intermediate allocation)
        let mut gate_has_single_use_output = false;
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

            // Add bounds checking for array access
            if (output_wire as usize) < wire_report.wire_usage_counts.len() {
                // If this output wire has usage count = 1
                if wire_report.wire_usage_counts[output_wire as usize] == 1 {
                    total_single_use_wires += 1;
                    gate_has_single_use_output = true;
                }
            }
        }

        // Parse gate type (last token) - only if gate has single-use outputs
        let gate_type = tokens.next().ok_or_else(|| {
            anyhow::anyhow!("Missing gate type at line {}: '{}'", line_number, line)
        })?;

        // Validate no extra tokens
        if tokens.next().is_some() {
            bail!("Too many tokens at line {}: '{}'", line_number, line);
        }

        // Count gate types only if they produce single-use wires
        if gate_has_single_use_output {
            match gate_type {
                "AND" => single_use_and_gates += 1,
                "XOR" => single_use_xor_gates += 1,
                _ => {
                    // Other gate types (NAND, OR, etc.) - could extend if needed
                }
            }
        }

        let gate_index: u32 = line_number - 1;

        // Update progress bar periodically for better performance
        if gate_index.is_multiple_of(PROGRESS_UPDATE_INTERVAL) {
            pb.set_position(gate_index as u64);
            // Avoid string allocation - use static message
            pb.set_message("Analyzing single-use gate types...");
        }
    }

    // Finish progress bar
    pb.finish_with_message(format!(
        "✓ Analyzed {line_number} gates, found {total_single_use_wires} single-use wires ({single_use_and_gates} AND, {single_use_xor_gates} XOR)"
    ));

    Ok(SingleUseGateAnalysis {
        single_use_and_gates,
        single_use_xor_gates,
        total_single_use_wires,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stream::BufferedLineStream;
    use std::fs::File;
    use std::io::Write;

    fn create_test_file(content: &str) -> Result<tempfile::NamedTempFile> {
        let mut temp_file = tempfile::NamedTempFile::new()?;
        temp_file.write_all(content.as_bytes())?;
        temp_file.flush()?;
        Ok(temp_file)
    }

    fn create_mock_wire_report(usage_counts: Vec<u8>) -> WireUsageReport {
        WireUsageReport {
            total_wires: usage_counts.len() as u32,
            primary_inputs: 0,
            intermediate_wires: 0,
            primary_outputs: 0,
            missing_wires_count: 0,
            wire_usage_counts: usage_counts,
            primary_input_wires: vec![],
            primary_output_wires: vec![],
        }
    }

    #[test]
    fn test_analyze_single_use_gates_basic() -> Result<()> {
        let circuit_data = "3 9\n2 1 0 1 2 XOR\n2 1 3 4 5 AND\n2 1 6 7 8 XOR\n";
        let temp_file = create_test_file(circuit_data)?;
        let file = File::open(temp_file.path())?;
        let mut stream = BufferedLineStream::new(file);

        // Setting 1 for all wires here to simulate single-use counting for intermediate wires
        let wire_report = create_mock_wire_report(vec![1, 1, 1, 1, 1, 1, 1, 1, 1]);

        let analysis = analyze_single_use_gates(&mut stream, &wire_report)?;

        assert_eq!(analysis.single_use_and_gates, 1);
        assert_eq!(analysis.single_use_xor_gates, 2);
        assert_eq!(analysis.total_single_use_wires, 3);

        Ok(())
    }

    #[test]
    fn test_analyze_single_use_gates_no_single_use() -> Result<()> {
        let circuit_data = "2 6\n2 1 0 1 2 XOR\n2 1 3 4 5 AND\n";
        let temp_file = create_test_file(circuit_data)?;
        let file = File::open(temp_file.path())?;
        let mut stream = BufferedLineStream::new(file);

        // All wires have usage > 1
        let wire_report = create_mock_wire_report(vec![2, 2, 2, 2, 2, 2]);

        let analysis = analyze_single_use_gates(&mut stream, &wire_report)?;

        assert_eq!(analysis.single_use_and_gates, 0);
        assert_eq!(analysis.single_use_xor_gates, 0);
        assert_eq!(analysis.total_single_use_wires, 0);

        Ok(())
    }

    #[test]
    fn test_analyze_single_use_gates_mixed_gate_types() -> Result<()> {
        let circuit_data = "4 12\n2 1 0 1 2 NAND\n2 1 3 4 5 AND\n2 1 6 7 8 XOR\n2 1 9 10 11 OR\n";
        let temp_file = create_test_file(circuit_data)?;
        let file = File::open(temp_file.path())?;
        let mut stream = BufferedLineStream::new(file);

        // Only AND and XOR outputs are single-use
        let wire_report = create_mock_wire_report(vec![0, 0, 2, 0, 0, 2, 0, 0, 1, 0, 0, 2]);

        let analysis = analyze_single_use_gates(&mut stream, &wire_report)?;

        assert_eq!(analysis.single_use_and_gates, 0);
        assert_eq!(analysis.single_use_xor_gates, 1);
        assert_eq!(analysis.total_single_use_wires, 1);

        Ok(())
    }
}
