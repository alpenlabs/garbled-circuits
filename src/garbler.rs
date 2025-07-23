use anyhow::{Result, bail};
use serde::{Serialize, Deserialize};
use std::path::Path;
use rand_chacha::ChaCha12Rng;
use rand::{RngCore, SeedableRng};
use sha2::{Sha256, Digest};
use indicatif::{ProgressBar, ProgressStyle};

use crate::stream::BufferedLineStream;
use crate::wire_analyzer::WireUsageReport;

/// 128-bit wire label for garbled circuits
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireLabel([u8; 16]);

impl WireLabel {
    pub fn new(bytes: [u8; 16]) -> Self {
        WireLabel(bytes)
    }
    
    pub fn random(rng: &mut ChaCha12Rng) -> Self {
        let mut bytes = [0u8; 16];
        rng.fill_bytes(&mut bytes);
        WireLabel(bytes)
    }
    
    pub fn xor(&self, other: &WireLabel) -> WireLabel {
        let mut result = [0u8; 16];
        for i in 0..16 {
            result[i] = self.0[i] ^ other.0[i];
        }
        WireLabel(result)
    }
    
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Wire labels for input and output wires (only label_0, label_1 = label_0 XOR delta)
#[derive(Debug, Serialize, Deserialize)]
pub struct WireLabels {
    /// Input wire labels: wire_id -> label_0
    pub input_labels: std::collections::HashMap<usize, WireLabel>,
    /// Output wire labels: wire_id -> label_0
    pub output_labels: std::collections::HashMap<usize, WireLabel>,
    /// Global delta for computing label_1 = label_0 XOR delta
    pub delta: WireLabel,
}

impl WireLabels {
    /// Save wire labels as JSON
    pub fn save_json<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }
    
    /// Load wire labels from JSON
    pub fn load_json<P: AsRef<Path>>(path: P) -> Result<Self> {
        let data = std::fs::read_to_string(path)?;
        let labels = serde_json::from_str(&data)?;
        Ok(labels)
    }
    
    /// Get both labels for a wire
    pub fn get_wire_labels(&self, wire_id: usize) -> Option<[WireLabel; 2]> {
        if let Some(&label_0) = self.input_labels.get(&wire_id) {
            Some([label_0, label_0.xor(&self.delta)])
        } else if let Some(&label_0) = self.output_labels.get(&wire_id) {
            Some([label_0, label_0.xor(&self.delta)])
        } else {
            None
        }
    }
}

/// Garbled truth table for an AND gate (4 ciphertexts, classic Yao)
#[derive(Debug, Clone)]
pub struct GarbledTable {
    /// 4 ciphertexts, each 16 bytes (128 bits)
    pub ciphertexts: [[u8; 16]; 4],
}

impl GarbledTable {
    /// Save garbled table as binary (64 bytes total)
    pub fn as_binary(&self) -> [u8; 64] {
        let mut result = [0u8; 64];
        for i in 0..4 {
            result[i*16..(i+1)*16].copy_from_slice(&self.ciphertexts[i]);
        }
        result
    }
}

/// Result of garbling a Bristol circuit
#[derive(Debug)]
pub struct GarblingResult {
    /// Wire labels for input and output wires (includes delta)
    pub wire_labels: WireLabels,
    /// Garbled truth tables for AND gates
    pub garbled_tables: Vec<GarbledTable>,
}

impl GarblingResult {
    /// Save the complete garbling result
    pub fn save<P: AsRef<Path>>(&self, labels_path: P, tables_path: P) -> Result<()> {
        // Save wire labels as JSON
        self.wire_labels.save_json(labels_path)?;
        
        // Save garbled tables as binary
        let mut tables_data = Vec::new();
        for table in &self.garbled_tables {
            tables_data.extend_from_slice(&table.as_binary());
        }
        std::fs::write(tables_path, tables_data)?;
        
        Ok(())
    }
}

/// Parsed gate information (reusing from wire_analyzer pattern)
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

/// Hash function for garbling (SHA-256 based PRF)
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

/// Garble an AND gate using classic Yao (4 ciphertexts)
fn garble_and_gate(
    input_labels: &[[WireLabel; 2]; 2], // [input1_labels, input2_labels] 
    output_labels: &[WireLabel; 2],     // [output_0, output_1]
    gate_id: u32,
) -> GarbledTable {
    let mut ciphertexts = [[0u8; 16]; 4];
    
    // Truth table for AND: (0,0)->0, (0,1)->0, (1,0)->0, (1,1)->1
    let truth_table = [
        (0, 0, 0), // input1=0, input2=0 -> output=0
        (0, 1, 0), // input1=0, input2=1 -> output=0  
        (1, 0, 0), // input1=1, input2=0 -> output=0
        (1, 1, 1), // input1=1, input2=1 -> output=1
    ];
    
    for (i, (in1_bit, in2_bit, out_bit)) in truth_table.iter().enumerate() {
        let input_combo = [
            input_labels[0][*in1_bit],
            input_labels[1][*in2_bit],
        ];
        
        let key = garbling_hash(&input_combo, gate_id);
        let plaintext = output_labels[*out_bit].as_bytes();
        
        // XOR encryption: ciphertext = plaintext XOR key
        for j in 0..16 {
            ciphertexts[i][j] = plaintext[j] ^ key[j];
        }
    }
    
    GarbledTable { ciphertexts }
}

/// Garble a Bristol circuit using Yao's protocol with free XOR optimization
/// Uses wire analysis data for memory-efficient label management
///
/// # Arguments
/// * `stream` - The line stream to process Bristol circuit
/// * `wire_report` - Wire usage analysis for memory optimization
/// * `seed_data` - 32 bytes of random seed for CSPRNG
/// 
/// # Returns
/// * `Ok(GarblingResult)` - Complete garbling with wire labels and garbled tables
/// * `Err(anyhow::Error)` - Parse error or garbling error
pub fn garble_circuit(
    stream: &mut BufferedLineStream,
    wire_report: &WireUsageReport,
    seed_data: &[u8; 32]
) -> Result<GarblingResult> {
    // Initialize CSPRNG with provided seed
    let mut rng = ChaCha12Rng::from_seed(*seed_data);
    
    // Generate global delta for free XOR (ensure LSB = 1)
    let mut delta_bytes = [0u8; 16];
    rng.fill_bytes(&mut delta_bytes);
    delta_bytes[15] |= 1; // Set LSB to 1
    let delta = WireLabel::new(delta_bytes);
    
    // Initialize usage counts for runtime tracking (clone from wire analysis)
    // TODO: Optimize to avoid cloning - can use mutable reference or move semantics
    let mut remaining_usage = wire_report.wire_usage_counts.clone();
    
    // Initialize active wire labels HashMap (only stores labels for live wires)
    let mut active_wire_labels: std::collections::HashMap<usize, WireLabel> = std::collections::HashMap::new();
    
    // Initialize primary input wires with random labels and collect them for final result
    let mut input_labels = std::collections::HashMap::new();
    for &input_wire_id in &wire_report.primary_input_wires {
        let label_0 = WireLabel::random(&mut rng);
        active_wire_labels.insert(input_wire_id, label_0);
        input_labels.insert(input_wire_id, label_0);  // Save for final result
    }
    
    // Process gates and generate garbled tables using streaming approach
    let mut garbled_tables = Vec::new();
    let mut gate_counter = 0u32;
    let mut line_number = 0;
    
    // Create progress bar for gate processing (use estimated count from wire report)
    let estimated_gates = wire_report.total_wires - wire_report.primary_inputs;
    let pb = ProgressBar::new(estimated_gates as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}")
            .unwrap()
            .progress_chars("##-")
    );
    pb.set_message("Garbling circuit...");
    
    // Process each gate as we read it (streaming approach - no memory accumulation)
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
                // Free XOR: output = input1 XOR input2
                if gate.inputs.len() != 2 || gate.outputs.len() != 1 {
                    bail!("XOR gate must have 2 inputs and 1 output");
                }
                
                let input1_label_0 = active_wire_labels.get(&gate.inputs[0])
                    .ok_or_else(|| anyhow::anyhow!("Input wire {} not found", gate.inputs[0]))?;
                let input2_label_0 = active_wire_labels.get(&gate.inputs[1])
                    .ok_or_else(|| anyhow::anyhow!("Input wire {} not found", gate.inputs[1]))?;
                
                // For XOR: output_0 = input1_0 XOR input2_0
                let output_label_0 = input1_label_0.xor(input2_label_0);
                
                // Add output wire label to active set
                active_wire_labels.insert(gate.outputs[0], output_label_0);
                
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
                // Garbled AND gate with 4 ciphertexts
                if gate.inputs.len() != 2 || gate.outputs.len() != 1 {
                    bail!("AND gate must have 2 inputs and 1 output");
                }
                
                let input1_label_0 = active_wire_labels.get(&gate.inputs[0])
                    .ok_or_else(|| anyhow::anyhow!("Input wire {} not found", gate.inputs[0]))?;
                let input2_label_0 = active_wire_labels.get(&gate.inputs[1])
                    .ok_or_else(|| anyhow::anyhow!("Input wire {} not found", gate.inputs[1]))?;
                
                // Compute both labels for inputs
                let input1_labels = [*input1_label_0, input1_label_0.xor(&delta)];
                let input2_labels = [*input2_label_0, input2_label_0.xor(&delta)];
                
                // Generate output labels
                let output_label_0 = WireLabel::random(&mut rng);
                let output_label_1 = output_label_0.xor(&delta);
                let output_labels = [output_label_0, output_label_1];
                
                // Create garbled table
                let input_label_pairs = [input1_labels, input2_labels];
                let garbled_table = garble_and_gate(&input_label_pairs, &output_labels, gate_counter);
                garbled_tables.push(garbled_table);
                
                // Add output wire label to active set
                active_wire_labels.insert(gate.outputs[0], output_label_0);
                gate_counter += 1;
                
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
            pb.set_message(format!("Garbling... {} active labels", active_wire_labels.len()));
        }
    }
    
    // Finish progress bar
    pb.finish_with_message(format!("✓ Garbled {} gates, {} AND tables generated", line_number, garbled_tables.len()));
    
    // Collect output wire labels from remaining active wires (should be primary outputs)
    let mut output_labels = std::collections::HashMap::new();
    for &output_wire_id in &wire_report.primary_output_wires {
        let label_0 = active_wire_labels.get(&output_wire_id)
            .ok_or_else(|| anyhow::anyhow!("Output wire {} not found in active labels", output_wire_id))?;
        output_labels.insert(output_wire_id, *label_0);
    }
    
    let wire_labels = WireLabels {
        input_labels,
        output_labels,
        delta,
    };
    
    Ok(GarblingResult {
        wire_labels,
        garbled_tables,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_wire_label_xor() {
        let label1 = WireLabel::new([0x01; 16]);
        let label2 = WireLabel::new([0x02; 16]);
        let result = label1.xor(&label2);
        assert_eq!(result.as_bytes(), &[0x03; 16]);
    }
    
    #[test]
    fn test_wire_labels_get_both() {
        let mut input_labels = std::collections::HashMap::new();
        let label_0 = WireLabel::new([0x01; 16]);
        let delta = WireLabel::new([0xFF; 16]);
        
        input_labels.insert(42, label_0);
        
        let wire_labels = WireLabels {
            input_labels,
            output_labels: std::collections::HashMap::new(),
            delta,
        };
        
        let both_labels = wire_labels.get_wire_labels(42).unwrap();
        assert_eq!(both_labels[0], label_0);
        assert_eq!(both_labels[1], label_0.xor(&delta));
    }
}