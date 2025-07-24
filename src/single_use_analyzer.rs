use anyhow::{Result, bail};
use serde::{Serialize, Deserialize};
use indicatif::{ProgressBar, ProgressStyle};

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

/// Gate structure for parsing Bristol format
struct Gate {
    inputs: Vec<usize>,
    outputs: Vec<usize>,
    gate_type: String,
}

/// Parse a single gate line into input/output wire lists and gate type
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
    
    // Parse gate type
    let gate_type = tokens[2 + num_inputs + num_outputs].to_string();
    
    Ok(Gate { inputs, outputs, gate_type })
}

/// Analyze gate types for wires with usage count = 1
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
/// # Example
/// ```no_run
/// use gc::single_use_analyzer::analyze_single_use_gates;
/// use gc::stream::BufferedLineStream;
/// use std::fs::File;
/// 
/// let file = File::open("circuit.bristol")?;
/// let mut stream = BufferedLineStream::new(file);
/// let analysis = analyze_single_use_gates(&mut stream, &wire_report)?;
/// println!("Single-use AND gates: {}", analysis.single_use_and_gates);
/// println!("Single-use XOR gates: {}", analysis.single_use_xor_gates);
/// ```
pub fn analyze_single_use_gates(
    stream: &mut BufferedLineStream, 
    wire_report: &WireUsageReport
) -> Result<SingleUseGateAnalysis> {
    let mut single_use_and_gates = 0;
    let mut single_use_xor_gates = 0;
    let mut total_single_use_wires = 0;
    let mut line_number: u64 = 0;
    
    // Create a spinner progress bar
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} [{elapsed_precise}] {msg}")
            .unwrap()
    );
    pb.set_message("Analyzing single-use gate types...");
    
    // Process each gate line
    while let Some(line_result) = stream.next_line() {
        line_number += 1;
        let line = line_result?;
        let line = line.trim();
        
        // Update progress every 10,000 lines
        if line_number % 10_000 == 0 {
            pb.set_message(format!("Analyzing single-use gate types... (line {})", line_number));
        }
        
        // Skip empty lines
        if line.is_empty() {
            continue;
        }
        
        let gate = parse_gate_line(line)?;
        
        // Check each output wire of this gate
        for &output_wire in &gate.outputs {
            // Ensure wire_id is within bounds of usage counts
            if output_wire < wire_report.wire_usage_counts.len() {
                // If this output wire has usage count = 1
                if wire_report.wire_usage_counts[output_wire] == 1 {
                    total_single_use_wires += 1;
                    
                    match gate.gate_type.as_str() {
                        "AND" => single_use_and_gates += 1,
                        "XOR" => single_use_xor_gates += 1,
                        _ => {
                            // Other gate types (NAND, OR, etc.) - could extend if needed
                        }
                    }
                }
            }
        }
    }
    
    pb.finish_with_message(format!("✓ Analyzed {} gates, found {} single-use wires ({} AND, {} XOR)", 
                                  line_number, total_single_use_wires, single_use_and_gates, single_use_xor_gates));
    
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
    use std::io::Write;
    use std::fs::File;
    
    fn create_test_file(content: &str) -> Result<tempfile::NamedTempFile> {
        let mut temp_file = tempfile::NamedTempFile::new()?;
        temp_file.write_all(content.as_bytes())?;
        temp_file.flush()?;
        Ok(temp_file)
    }
    
    fn create_mock_wire_report(usage_counts: Vec<u8>) -> WireUsageReport {
        WireUsageReport {
            total_wires: usage_counts.len(),
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
        let circuit_data = "2 1 0 1 2 XOR\n2 1 3 4 5 AND\n2 1 6 7 8 XOR\n";
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
        let circuit_data = "2 1 0 1 2 XOR\n2 1 3 4 5 AND\n";
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
        let circuit_data = "2 1 0 1 2 NAND\n2 1 3 4 5 AND\n2 1 6 7 8 XOR\n2 1 9 10 11 OR\n";
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