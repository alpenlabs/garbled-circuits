use anyhow::{Result, bail};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::path::Path;
use sha2::{Sha256, Digest};
use indicatif::{ProgressBar, ProgressStyle};

use crate::stream::BufferedLineStream;
use crate::wire_analyzer::WireUsageReport;
use crate::garbler::{WireLabel, GarbledTable};
use crate::ot_simulation::OTResult;

/// Evaluation result containing output wire labels and their bit values
#[derive(Debug, Serialize, Deserialize)]
pub struct EvaluationResult {
    /// Final output labels with their bit values: wire_id -> (label, bit_value)
    pub output_results: HashMap<usize, OutputResult>,
}

/// An evaluated output wire with its label and bit value
#[derive(Debug, Serialize, Deserialize)]
pub struct OutputResult {
    /// The output wire label
    pub label: WireLabel,
    /// The bit value this label represents
    pub bit_value: bool,
}

impl EvaluationResult {
    /// Save evaluation result as JSON
    pub fn save_json<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }
    
    /// Load evaluation result from JSON
    pub fn load_json<P: AsRef<Path>>(path: P) -> Result<Self> {
        let data = std::fs::read_to_string(path)?;
        let result = serde_json::from_str(&data)?;
        Ok(result)
    }
    
    /// Print evaluation results to console
    pub fn print_summary(&self) {
        println!("Circuit Evaluation Results:");
        println!("  Output wires: {}", self.output_results.len());
        
        // Sort by wire ID for consistent output
        let mut sorted_outputs: Vec<_> = self.output_results.iter().collect();
        sorted_outputs.sort_by_key(|&(&wire_id, _)| wire_id);
        
        for (&wire_id, output) in sorted_outputs {
            println!("  Wire {}: {} (label: {:02x}...)", 
                     wire_id, 
                     if output.bit_value { 1 } else { 0 },
                     output.label.as_bytes()[0]);
        }
    }
}

/// Wire label with its corresponding bit value (used during evaluation)
#[derive(Debug, Clone)]
struct LabelWithBit {
    label: WireLabel,
    bit_value: bool,
}

/// Parsed gate information
#[derive(Debug)]
struct Gate {
    inputs: Vec<usize>,
    outputs: Vec<usize>,
    gate_type: String,
}

/// Parse a single gate line into input/output wire lists and gate type
/// Bristol format: "2 1 466 466 467 XOR" or "2 1 466 466 467 AND"
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

/// Hash function for garbling (SHA-256 based PRF) - matches garbler implementation
fn garbling_hash(input_labels: &[WireLabel], gate_id: u32) -> [u8; 16] {
    let mut hasher = Sha256::new();
    
    // Add input labels
    for label in input_labels {
        hasher.update(label.as_bytes());
    }
    
    // Add gate ID for uniqueness
    hasher.update(&gate_id.to_le_bytes());
    
    let hash = hasher.finalize();
    // Take first 16 bytes of SHA-256 output
    let mut result = [0u8; 16];
    result.copy_from_slice(&hash[0..16]);
    result
}

/// Evaluate an AND gate using knowledge of input bit values
/// 
/// Since we know the bit values of input labels, we can directly compute which
/// row of the garbled table to decrypt without trial decryption.
fn evaluate_and_gate(
    input_labels_with_bits: &[LabelWithBit; 2],
    garbled_table: &GarbledTable,
    gate_id: u32,
) -> Result<LabelWithBit> {
    // Compute truth table row index from input bit values
    // Row encoding: (input1_bit, input2_bit) -> row_index
    // (0,0) -> 0, (0,1) -> 1, (1,0) -> 2, (1,1) -> 3
    let row_index = (input_labels_with_bits[0].bit_value as usize) * 2 + 
                   (input_labels_with_bits[1].bit_value as usize);
    
    // Compute output bit value using AND truth table
    let output_bit = input_labels_with_bits[0].bit_value && input_labels_with_bits[1].bit_value;
    
    // Extract the input labels for hashing
    let input_labels = [
        input_labels_with_bits[0].label,
        input_labels_with_bits[1].label,
    ];
    
    // Compute decryption key
    let key = garbling_hash(&input_labels, gate_id);
    
    // Decrypt the appropriate ciphertext
    let ciphertext = &garbled_table.ciphertexts[row_index];
    let mut plaintext = [0u8; 16];
    for i in 0..16 {
        plaintext[i] = ciphertext[i] ^ key[i];
    }
    
    let output_label = WireLabel::new(plaintext);
    
    Ok(LabelWithBit {
        label: output_label,
        bit_value: output_bit,
    })
}

/// Load garbled tables from binary file
/// 
/// Each garbled table is 64 bytes (4 ciphertexts × 16 bytes each)
fn load_garbled_tables<P: AsRef<Path>>(path: P) -> Result<Vec<GarbledTable>> {
    // Create progress bar for loading
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} [{elapsed_precise}] {msg}")
            .unwrap()
    );
    pb.set_message("Loading garbled tables...");
    
    let data = std::fs::read(path)?;
    
    if data.len() % 64 != 0 {
        bail!("Invalid garbled tables file: size {} is not multiple of 64", data.len());
    }
    
    let num_tables = data.len() / 64;
    let mut tables = Vec::with_capacity(num_tables);
    
    pb.set_message(format!("Parsing {} garbled tables...", num_tables));
    
    for i in 0..num_tables {
        let start = i * 64;
        let table_data = &data[start..start + 64];
        
        let mut ciphertexts = [[0u8; 16]; 4];
        for j in 0..4 {
            let ct_start = j * 16;
            ciphertexts[j].copy_from_slice(&table_data[ct_start..ct_start + 16]);
        }
        
        tables.push(GarbledTable { ciphertexts });
        
        // Update progress every 10000 tables
        if i % 10000 == 0 {
            pb.tick();
        }
    }
    
    pb.finish_with_message(format!("✓ Loaded {} garbled tables", num_tables));
    Ok(tables)
}

/// Evaluate a garbled circuit using selected input labels from OT simulation
/// 
/// This function evaluates a Bristol circuit using the same memory-efficient
/// streaming approach as the garbler, maintaining only live wire labels in memory.
/// 
/// # Arguments
/// * `stream` - The line stream to process Bristol circuit gates
/// * `wire_report` - Wire usage analysis for memory optimization
/// * `ot_result` - Selected input labels from OT simulation
/// * `garbled_tables_path` - Path to binary file containing garbled truth tables
/// 
/// # Returns
/// * `Ok(EvaluationResult)` - Output wire labels with their bit values
/// * `Err(anyhow::Error)` - Parse error, file error, or evaluation error
pub fn evaluate_circuit(
    stream: &mut BufferedLineStream,
    wire_report: &WireUsageReport,
    ot_result: &OTResult,
    garbled_tables_path: &Path,
) -> Result<EvaluationResult> {
    // Load all garbled tables into memory
    let garbled_tables = load_garbled_tables(garbled_tables_path)?;
    
    // Initialize usage counts for runtime tracking (clone from wire analysis)
    let mut remaining_usage = wire_report.wire_usage_counts.clone();
    
    // Initialize active wire labels HashMap with input labels from OT
    let mut active_wire_labels: HashMap<usize, LabelWithBit> = HashMap::new();
    
    // Initialize with selected input labels
    for (&wire_id, selected_input) in &ot_result.selected_inputs {
        active_wire_labels.insert(wire_id, LabelWithBit {
            label: selected_input.label,
            bit_value: selected_input.bit_value,
        });
    }
    
    // Process gates using streaming approach
    let mut and_gate_counter = 0usize;
    let mut line_number = 0;
    
    // Create progress bar for gate processing
    let estimated_gates = wire_report.total_wires - wire_report.primary_inputs;
    let pb = ProgressBar::new(estimated_gates as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}")
            .unwrap()
            .progress_chars("##-")
    );
    pb.set_message("Evaluating circuit...");
    
    // Process each gate as we read it (streaming approach)
    while let Some(line_result) = stream.next_line() {
        line_number += 1;
        let line = line_result?;
        
        if line.trim().is_empty() {
            bail!("Empty line at line number {}", line_number);
        }
        
        let gate = parse_gate_line(line)?;
        let gate_index = line_number - 1;
        
        match gate.gate_type.as_str() {
            "XOR" => {
                // Free XOR: output_bit = input1_bit XOR input2_bit
                // output_label = input1_label XOR input2_label
                if gate.inputs.len() != 2 || gate.outputs.len() != 1 {
                    bail!("XOR gate must have 2 inputs and 1 output");
                }
                
                let input1 = active_wire_labels.get(&gate.inputs[0])
                    .ok_or_else(|| anyhow::anyhow!("Input wire {} not found", gate.inputs[0]))?;
                let input2 = active_wire_labels.get(&gate.inputs[1])
                    .ok_or_else(|| anyhow::anyhow!("Input wire {} not found", gate.inputs[1]))?;
                
                // XOR the labels and bit values
                let output_label = input1.label.xor(&input2.label);
                let output_bit = input1.bit_value ^ input2.bit_value;
                
                // Add output wire to active set
                active_wire_labels.insert(gate.outputs[0], LabelWithBit {
                    label: output_label,
                    bit_value: output_bit,
                });
                
                // Process input wires: decrement usage and remove if no longer needed
                for &input_wire in &gate.inputs {
                    if remaining_usage[input_wire] > 0 {
                        // Wires with count 255 are never decremented (permanent wires)
                        if remaining_usage[input_wire] < 255 {
                            remaining_usage[input_wire] -= 1;
                        }
                        
                        // Remove wire label from active set if no longer needed
                        if remaining_usage[input_wire] == 0 {
                            active_wire_labels.remove(&input_wire);
                        }
                    }
                }
            }
            "AND" => {
                // Evaluate AND gate using garbled table
                if gate.inputs.len() != 2 || gate.outputs.len() != 1 {
                    bail!("AND gate must have 2 inputs and 1 output");
                }
                
                let input1 = active_wire_labels.get(&gate.inputs[0])
                    .ok_or_else(|| anyhow::anyhow!("Input wire {} not found", gate.inputs[0]))?;
                let input2 = active_wire_labels.get(&gate.inputs[1])
                    .ok_or_else(|| anyhow::anyhow!("Input wire {} not found", gate.inputs[1]))?;
                
                // Check that we have enough garbled tables
                if and_gate_counter >= garbled_tables.len() {
                    bail!("Not enough garbled tables: need {}, have {}", 
                          and_gate_counter + 1, garbled_tables.len());
                }
                
                let input_labels_with_bits = [input1.clone(), input2.clone()];
                let output = evaluate_and_gate(
                    &input_labels_with_bits,
                    &garbled_tables[and_gate_counter],
                    and_gate_counter as u32,
                )?;
                
                // Add output wire to active set
                active_wire_labels.insert(gate.outputs[0], output);
                and_gate_counter += 1;
                
                // Process input wires: decrement usage and remove if no longer needed
                for &input_wire in &gate.inputs {
                    if remaining_usage[input_wire] > 0 {
                        // Wires with count 255 are never decremented (permanent wires)
                        if remaining_usage[input_wire] < 255 {
                            remaining_usage[input_wire] -= 1;
                        }
                        
                        // Remove wire label from active set if no longer needed
                        if remaining_usage[input_wire] == 0 {
                            active_wire_labels.remove(&input_wire);
                        }
                    }
                }
            }
            _ => {
                bail!("Unsupported gate type: {}", gate.gate_type);
            }
        }
        
        // Update progress bar every 10000 gates
        if gate_index % 10000 == 0 {
            pb.set_position(gate_index as u64);
            pb.set_message(format!("Evaluating... {} active labels", active_wire_labels.len()));
        }
    }
    
    // Finish progress bar
    pb.finish_with_message(format!("✓ Evaluated {} gates, {} AND gates", line_number, and_gate_counter));
    
    // Collect output wire results from remaining active wires
    let mut output_results = HashMap::new();
    for &output_wire_id in &wire_report.primary_output_wires {
        let label_with_bit = active_wire_labels.get(&output_wire_id)
            .ok_or_else(|| anyhow::anyhow!("Output wire {} not found in active labels", output_wire_id))?;
        
        output_results.insert(output_wire_id, OutputResult {
            label: label_with_bit.label,
            bit_value: label_with_bit.bit_value,
        });
    }
    
    Ok(EvaluationResult { output_results })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use crate::ot_simulation::SelectedInput;
    
    #[test]
    fn test_evaluate_and_gate() {
        // Create test input labels with bit values
        let input1 = LabelWithBit {
            label: WireLabel::new([0x01; 16]),
            bit_value: true,
        };
        let input2 = LabelWithBit {
            label: WireLabel::new([0x02; 16]),
            bit_value: false,
        };
        
        // Create a dummy garbled table (normally this would be created by garbler)
        let garbled_table = GarbledTable {
            ciphertexts: [
                [0u8; 16], // (0,0) -> 0
                [0u8; 16], // (0,1) -> 0  
                [0u8; 16], // (1,0) -> 0
                [0u8; 16], // (1,1) -> 1
            ]
        };
        
        let input_labels = [input1, input2];
        let result = evaluate_and_gate(&input_labels, &garbled_table, 0);
        
        // Should succeed and return correct output bit (true AND false = false)
        assert!(result.is_ok());
        let output = result.unwrap();
        assert_eq!(output.bit_value, false);
    }
    
    #[test]
    fn test_evaluation_result_serialization() {
        let mut output_results = HashMap::new();
        output_results.insert(0, OutputResult {
            label: WireLabel::new([0x42; 16]),
            bit_value: true,
        });
        
        let eval_result = EvaluationResult { output_results };
        
        // Test JSON serialization round-trip
        eval_result.save_json("test_eval.json").unwrap();
        let loaded_result = EvaluationResult::load_json("test_eval.json").unwrap();
        
        assert_eq!(loaded_result.output_results.len(), 1);
        let output = loaded_result.output_results.get(&0).unwrap();
        assert_eq!(output.label, WireLabel::new([0x42; 16]));
        assert_eq!(output.bit_value, true);
        
        // Clean up test file
        std::fs::remove_file("test_eval.json").ok();
    }
}