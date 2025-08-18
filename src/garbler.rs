use anyhow::{Result, bail};
use indicatif::{ProgressBar, ProgressStyle};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha12Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

use crate::constants::PROGRESS_UPDATE_INTERVAL;
use crate::stream::BufferedLineStream;
use crate::wire_analyzer::WireUsageReport;

/// 128-bit wire label for garbled circuits
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireLabel([u8; 16]);

impl WireLabel {
    /// Create a new wire label from 16 bytes
    pub fn new(bytes: [u8; 16]) -> Self {
        WireLabel(bytes)
    }

    /// Generate a random wire label using the provided RNG
    pub fn random(rng: &mut ChaCha12Rng) -> Self {
        let mut bytes = [0u8; 16];
        rng.fill_bytes(&mut bytes);
        WireLabel(bytes)
    }

    /// XOR this wire label with another wire label
    pub fn xor(&self, other: &WireLabel) -> WireLabel {
        let mut result = [0u8; 16];
        for (i, result_byte) in result.iter_mut().enumerate() {
            *result_byte = self.0[i] ^ other.0[i];
        }
        WireLabel(result)
    }

    /// Get the raw bytes of this wire label
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Wire labels for input and output wires (only label_0, label_1 = label_0 XOR delta)
#[derive(Debug, Serialize, Deserialize)]
pub struct WireLabels {
    /// Input wire labels: wire_id -> label_0
    pub input_labels: std::collections::HashMap<u32, WireLabel>,
    /// Output wire labels: wire_id -> label_0
    pub output_labels: std::collections::HashMap<u32, WireLabel>,
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
    pub fn get_wire_labels(&self, wire_id: u32) -> Option<[WireLabel; 2]> {
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
            result[i * 16..(i + 1) * 16].copy_from_slice(&self.ciphertexts[i]);
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

/// Hash function for garbling (SHA-256 based PRF)
pub fn garbling_hash(input_labels: &[WireLabel]) -> [u8; 16] {
    let mut hasher = Sha256::new();

    // Add input labels
    for label in input_labels {
        hasher.update(label.as_bytes());
    }

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
        let input_combo = [input_labels[0][*in1_bit], input_labels[1][*in2_bit]];

        let key = garbling_hash(&input_combo);
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
/// Expected format:
/// First line: `<num_gates> <num_wires>`
/// Followed by gate lines in Bristol format
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
    seed_data: &[u8; 32],
) -> Result<GarblingResult> {
    // Parse and validate header line (but ignore values)
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

    // Initialize CSPRNG with provided seed
    let mut rng = ChaCha12Rng::from_seed(*seed_data);

    // Generate global delta for free XOR
    let delta = WireLabel::random(&mut rng);

    // Initialize usage counts for runtime tracking (clone from wire analysis)
    let mut remaining_usage = wire_report.wire_usage_counts.clone();

    // Initialize active wire labels HashMap (only stores labels for live wires)
    let mut active_wire_labels: std::collections::HashMap<u32, WireLabel> =
        std::collections::HashMap::new();

    // Initialize primary input wires with random labels and collect them for final result
    let mut input_labels = std::collections::HashMap::new();
    for &input_wire_id in &wire_report.primary_input_wires {
        let label_0 = WireLabel::random(&mut rng);
        active_wire_labels.insert(input_wire_id, label_0);
        input_labels.insert(input_wire_id, label_0); // Save for final result
    }

    // Process gates and generate garbled tables using streaming approach
    let mut garbled_tables = Vec::new();
    let mut _gate_counter = 0u32;
    let mut line_number = 0;

    // Create progress bar for gate processing (use actual count from header)
    let pb = ProgressBar::new(num_gates as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}")
            .unwrap()
            .progress_chars("##-"),
    );
    pb.set_message("Garbling circuit...");

    // Process each gate as we read it (streaming approach - no memory accumulation)
    while let Some(line_result) = stream.next_line() {
        line_number += 1;
        let line = line_result?;

        if line.trim().is_empty() {
            bail!("Empty line at line number {}", line_number);
        }

        // Parse gate line directly using iterator (more efficient)
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

        // Collect input wire IDs directly (no intermediate allocation)
        let input_wires: Result<Vec<u32>> = (0..num_inputs)
            .map(|i| {
                let wire_id: u32 = tokens
                    .next()
                    .ok_or_else(|| {
                        anyhow::anyhow!("Missing input wire {} at line {}", i, line_number)
                    })?
                    .parse()
                    .map_err(|_| {
                        anyhow::anyhow!("Invalid input wire ID at line {}: '{}'", line_number, line)
                    })?;
                Ok(wire_id)
            })
            .collect();
        let input_wires = input_wires?;

        // Collect output wire IDs directly (no intermediate allocation)
        let output_wires: Result<Vec<u32>> = (0..num_outputs)
            .map(|i| {
                let wire_id: u32 = tokens
                    .next()
                    .ok_or_else(|| {
                        anyhow::anyhow!("Missing output wire {} at line {}", i, line_number)
                    })?
                    .parse()
                    .map_err(|_| {
                        anyhow::anyhow!(
                            "Invalid output wire ID at line {}: '{}'",
                            line_number,
                            line
                        )
                    })?;
                Ok(wire_id)
            })
            .collect();
        let output_wires = output_wires?;

        // Parse gate type (last token)
        let gate_type = tokens.next().ok_or_else(|| {
            anyhow::anyhow!("Missing gate type at line {}: '{}'", line_number, line)
        })?;

        // Validate no extra tokens
        if tokens.next().is_some() {
            bail!("Too many tokens at line {}: '{}'", line_number, line);
        }

        let gate_index: u32 = line_number - 1;
        match gate_type {
            "XOR" => {
                // Free XOR: output = input1 XOR input2
                if input_wires.len() != 2 || output_wires.len() != 1 {
                    bail!(
                        "XOR gate must have 2 inputs and 1 output at line {}",
                        line_number
                    );
                }

                let input1_label_0 = active_wire_labels.get(&input_wires[0]).ok_or_else(|| {
                    anyhow::anyhow!(
                        "Input wire {} not found at line {}",
                        input_wires[0],
                        line_number
                    )
                })?;
                let input2_label_0 = active_wire_labels.get(&input_wires[1]).ok_or_else(|| {
                    anyhow::anyhow!(
                        "Input wire {} not found at line {}",
                        input_wires[1],
                        line_number
                    )
                })?;

                // For XOR: output_0 = input1_0 XOR input2_0
                let output_label_0 = input1_label_0.xor(input2_label_0);

                // Add output wire label to active set
                active_wire_labels.insert(output_wires[0], output_label_0);

                // Process input wires: decrement usage and remove if no longer needed
                for &input_wire in &input_wires {
                    if remaining_usage[input_wire as usize] > 0 {
                        // Wires with count 255 are never decremented (permanent wires)
                        if remaining_usage[input_wire as usize] < 255 {
                            remaining_usage[input_wire as usize] -= 1;
                        }

                        // Remove wire label from active set if no longer needed
                        if remaining_usage[input_wire as usize] == 0 {
                            active_wire_labels.remove(&input_wire);
                        }
                    }
                }
            }
            "AND" => {
                // Garbled AND gate with 4 ciphertexts
                if input_wires.len() != 2 || output_wires.len() != 1 {
                    bail!(
                        "AND gate must have 2 inputs and 1 output at line {}",
                        line_number
                    );
                }

                let input1_label_0 = active_wire_labels.get(&input_wires[0]).ok_or_else(|| {
                    anyhow::anyhow!(
                        "Input wire {} not found at line {}",
                        input_wires[0],
                        line_number
                    )
                })?;
                let input2_label_0 = active_wire_labels.get(&input_wires[1]).ok_or_else(|| {
                    anyhow::anyhow!(
                        "Input wire {} not found at line {}",
                        input_wires[1],
                        line_number
                    )
                })?;

                // Compute both labels for inputs
                let input1_labels = [*input1_label_0, input1_label_0.xor(&delta)];
                let input2_labels = [*input2_label_0, input2_label_0.xor(&delta)];

                // Generate output labels
                let output_label_0 = WireLabel::random(&mut rng);
                let output_label_1 = output_label_0.xor(&delta);
                let output_labels = [output_label_0, output_label_1];

                // Create garbled table
                let input_label_pairs = [input1_labels, input2_labels];
                let garbled_table = garble_and_gate(&input_label_pairs, &output_labels);
                garbled_tables.push(garbled_table);

                // Add output wire label to active set
                active_wire_labels.insert(output_wires[0], output_label_0);
                _gate_counter += 1;

                // Process input wires: decrement usage and remove if no longer needed
                for &input_wire in &input_wires {
                    if remaining_usage[input_wire as usize] > 0 {
                        // Wires with count 255 are never decremented (permanent wires)
                        if remaining_usage[input_wire as usize] < 255 {
                            remaining_usage[input_wire as usize] -= 1;
                        }

                        // Remove wire label from active set if no longer needed
                        if remaining_usage[input_wire as usize] == 0 {
                            active_wire_labels.remove(&input_wire);
                        }
                    }
                }
            }
            _ => {
                bail!(
                    "Unsupported gate type: {} at line {}",
                    gate_type,
                    line_number
                );
            }
        }

        // Update progress bar periodically for better performance
        if gate_index.is_multiple_of(PROGRESS_UPDATE_INTERVAL) {
            pb.set_position(gate_index as u64);
            // Avoid string allocation - use static message
            pb.set_message("Garbling circuit...");
        }
    }

    // Finish progress bar
    pb.finish_with_message(format!(
        "✓ Garbled {} gates, {} AND tables generated",
        line_number,
        garbled_tables.len()
    ));

    // Collect output wire labels from remaining active wires (should be primary outputs)
    let mut output_labels = std::collections::HashMap::new();
    for &output_wire_id in &wire_report.primary_output_wires {
        let label_0 = active_wire_labels.get(&output_wire_id).ok_or_else(|| {
            anyhow::anyhow!("Output wire {} not found in active labels", output_wire_id)
        })?;
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
    use crate::wire_analyzer::analyze_wire_usage;
    use std::fs::File;
    use std::io::Write;

    fn create_test_file(content: &str) -> Result<tempfile::NamedTempFile> {
        let mut temp_file = tempfile::NamedTempFile::new()?;
        temp_file.write_all(content.as_bytes())?;
        temp_file.flush()?;
        Ok(temp_file)
    }

    fn create_test_seed() -> [u8; 32] {
        [0x42; 32] // Fixed seed for reproducible tests
    }

    // Helper to create wire usage report from circuit data
    fn create_wire_report(circuit_data: &str) -> Result<WireUsageReport> {
        let temp_file = create_test_file(circuit_data)?;
        let file = File::open(temp_file.path())?;
        let mut stream = BufferedLineStream::new(file);
        analyze_wire_usage(&mut stream)
    }

    #[test]
    fn test_wire_label_creation() {
        let bytes = [0x42; 16];
        let label = WireLabel::new(bytes);
        assert_eq!(label.as_bytes(), &bytes);
    }

    #[test]
    fn test_wire_label_random() {
        let seed = create_test_seed();
        let mut rng = ChaCha12Rng::from_seed(seed);

        let label1 = WireLabel::random(&mut rng);
        let label2 = WireLabel::random(&mut rng);

        // length of the labels should be 16 bytes
        assert_eq!(label1.as_bytes().len(), 16);
        assert_eq!(label2.as_bytes().len(), 16);

        // Should be different (extremely high probability)
        assert_ne!(label1.as_bytes(), label2.as_bytes());
    }

    #[test]
    fn test_wire_label_xor() {
        let label1 = WireLabel::new([0x01; 16]);
        let label2 = WireLabel::new([0x02; 16]);
        let result = label1.xor(&label2);
        assert_eq!(result.as_bytes(), &[0x03; 16]);
    }

    #[test]
    fn test_wire_label_xor_identity() {
        let label = WireLabel::new([0xAB; 16]);
        let zero = WireLabel::new([0x00; 16]);
        let result = label.xor(&zero);
        assert_eq!(result.as_bytes(), label.as_bytes());
    }

    #[test]
    fn test_wire_label_xor_self_cancellation() {
        let label = WireLabel::new([0xCD; 16]);
        let result = label.xor(&label);
        assert_eq!(result.as_bytes(), &[0x00; 16]);
    }

    #[test]
    fn test_wire_labels_get_both_input() {
        let mut input_labels = std::collections::HashMap::new();
        let label_0 = WireLabel::new([0x01; 16]);
        let delta = WireLabel::new([0xFF; 16]);

        input_labels.insert(42u32, label_0);

        let wire_labels = WireLabels {
            input_labels,
            output_labels: std::collections::HashMap::new(),
            delta,
        };

        let both_labels = wire_labels.get_wire_labels(42u32).unwrap();
        assert_eq!(both_labels[0], label_0);
        assert_eq!(both_labels[1], label_0.xor(&delta));
    }

    #[test]
    fn test_wire_labels_get_none() {
        let wire_labels = WireLabels {
            input_labels: std::collections::HashMap::new(),
            output_labels: std::collections::HashMap::new(),
            delta: WireLabel::new([0x00; 16]),
        };

        assert!(wire_labels.get_wire_labels(123u32).is_none());
    }

    #[test]
    fn test_garbled_table_binary_conversion() {
        let ciphertexts = [[0x01; 16], [0x02; 16], [0x03; 16], [0x04; 16]];

        let table = GarbledTable { ciphertexts };
        let binary = table.as_binary();

        assert_eq!(binary.len(), 64); // 4 * 16 bytes

        // Check each ciphertext is correctly placed
        for (i, ciphertext) in ciphertexts.iter().enumerate() {
            let start = i * 16;
            let end = start + 16;
            assert_eq!(&binary[start..end], ciphertext);
        }
    }

    #[test]
    fn test_garbling_hash_deterministic() {
        let label1 = WireLabel::new([0x11; 16]);
        let label2 = WireLabel::new([0x22; 16]);
        let labels = [label1, label2];

        let hash1 = garbling_hash(&labels);
        let hash2 = garbling_hash(&labels);

        assert_eq!(hash1, hash2); // Should be deterministic
    }

    #[test]
    fn test_garble_and_gate() {
        let input1_labels = [WireLabel::new([0x10; 16]), WireLabel::new([0x11; 16])];
        let input2_labels = [WireLabel::new([0x20; 16]), WireLabel::new([0x21; 16])];
        let output_labels = [WireLabel::new([0x30; 16]), WireLabel::new([0x31; 16])];

        let input_label_pairs = [input1_labels, input2_labels];
        let table = garble_and_gate(&input_label_pairs, &output_labels);

        // Should produce 4 ciphertexts
        assert_eq!(table.ciphertexts.len(), 4);

        // Each ciphertext should be 16 bytes
        for ciphertext in &table.ciphertexts {
            assert_eq!(ciphertext.len(), 16);
        }
    }

    #[test]
    fn test_garble_circuit_single_xor_gate() -> Result<()> {
        let circuit_data = "1 3\n2 1 0 1 2 XOR\n";
        let wire_report = create_wire_report(circuit_data)?;
        let seed = create_test_seed();

        let temp_file = create_test_file(circuit_data)?;
        let file = File::open(temp_file.path())?;
        let mut stream = BufferedLineStream::new(file);

        let result = garble_circuit(&mut stream, &wire_report, &seed)?;

        // XOR gate should not produce any garbled tables (free XOR)
        assert_eq!(result.garbled_tables.len(), 0);

        // Should have input and output labels
        assert_eq!(result.wire_labels.input_labels.len(), 2); // wires 0, 1
        assert_eq!(result.wire_labels.output_labels.len(), 1); // wire 2

        // Check that input wires are labeled
        assert!(result.wire_labels.input_labels.contains_key(&0));
        assert!(result.wire_labels.input_labels.contains_key(&1));

        // Check that output wire is labeled
        assert!(result.wire_labels.output_labels.contains_key(&2));

        Ok(())
    }

    #[test]
    fn test_garble_circuit_single_and_gate() -> Result<()> {
        let circuit_data = "1 3\n2 1 0 1 2 AND\n";
        let wire_report = create_wire_report(circuit_data)?;
        let seed = create_test_seed();

        let temp_file = create_test_file(circuit_data)?;
        let file = File::open(temp_file.path())?;
        let mut stream = BufferedLineStream::new(file);

        let result = garble_circuit(&mut stream, &wire_report, &seed)?;

        // AND gate should produce exactly 1 garbled table
        assert_eq!(result.garbled_tables.len(), 1);

        // Should have input and output labels
        assert_eq!(result.wire_labels.input_labels.len(), 2); // wires 0, 1
        assert_eq!(result.wire_labels.output_labels.len(), 1); // wire 2

        Ok(())
    }

    #[test]
    fn test_garble_circuit_mixed_gates() -> Result<()> {
        let circuit_data = "3 6\n2 1 0 1 2 XOR\n2 1 2 3 4 AND\n2 1 0 4 5 XOR\n";
        let wire_report = create_wire_report(circuit_data)?;
        let seed = create_test_seed();

        let temp_file = create_test_file(circuit_data)?;
        let file = File::open(temp_file.path())?;
        let mut stream = BufferedLineStream::new(file);

        let result = garble_circuit(&mut stream, &wire_report, &seed)?;

        // Should have 1 garbled table (only 1 AND gate)
        assert_eq!(result.garbled_tables.len(), 1);

        // Should have proper input/output counts
        assert_eq!(result.wire_labels.input_labels.len(), 3); // wires 0, 1, 3 are inputs
        assert!(result.wire_labels.input_labels.len() >= 2);

        Ok(())
    }

    #[test]
    fn test_garble_circuit_empty() -> Result<()> {
        let circuit_data = "0 0\n";
        let wire_report = create_wire_report(circuit_data)?;
        let seed = create_test_seed();

        let temp_file = create_test_file(circuit_data)?;
        let file = File::open(temp_file.path())?;
        let mut stream = BufferedLineStream::new(file);

        let result = garble_circuit(&mut stream, &wire_report, &seed)?;

        // Empty circuit should have no tables or labels
        assert_eq!(result.garbled_tables.len(), 0);
        assert_eq!(result.wire_labels.input_labels.len(), 0);
        assert_eq!(result.wire_labels.output_labels.len(), 0);

        Ok(())
    }

    #[test]
    fn test_garble_circuit_invalid_header() {
        let circuit_data = "invalid header\n2 1 0 1 2 XOR\n";
        let temp_file = create_test_file(circuit_data).unwrap();
        let file = File::open(temp_file.path()).unwrap();
        let mut stream = BufferedLineStream::new(file);

        // Create a dummy wire report
        let wire_report = WireUsageReport {
            total_wires: 3,
            primary_inputs: 2,
            intermediate_wires: 0,
            primary_outputs: 1,
            missing_wires_count: 0,
            wire_usage_counts: vec![1, 1, 0],
            primary_input_wires: vec![0, 1],
            primary_output_wires: vec![2],
        };

        let seed = create_test_seed();
        let result = garble_circuit(&mut stream, &wire_report, &seed);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Invalid num_gates: 'invalid'"));
    }

    #[test]
    fn test_garble_circuit_missing_header() {
        let circuit_data = "";
        let temp_file = create_test_file(circuit_data).unwrap();
        let file = File::open(temp_file.path()).unwrap();
        let mut stream = BufferedLineStream::new(file);

        let wire_report = WireUsageReport {
            total_wires: 0,
            primary_inputs: 0,
            intermediate_wires: 0,
            primary_outputs: 0,
            missing_wires_count: 0,
            wire_usage_counts: vec![],
            primary_input_wires: vec![],
            primary_output_wires: vec![],
        };

        let seed = create_test_seed();
        let result = garble_circuit(&mut stream, &wire_report, &seed);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Missing header line"));
    }

    #[test]
    fn test_garble_circuit_unsupported_gate() {
        let circuit_data = "1 3\n2 1 0 1 2 UNKNOWN\n";
        let wire_report = create_wire_report(circuit_data).unwrap();
        let seed = create_test_seed();

        let temp_file = create_test_file(circuit_data).unwrap();
        let file = File::open(temp_file.path()).unwrap();
        let mut stream = BufferedLineStream::new(file);

        let result = garble_circuit(&mut stream, &wire_report, &seed);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Unsupported gate type: UNKNOWN"));
    }

    #[test]
    fn test_garble_circuit_malformed_gate() {
        let circuit_data = "1 3\ninvalid gate line\n";
        let temp_file = create_test_file(circuit_data).unwrap();
        let file = File::open(temp_file.path()).unwrap();
        let mut stream = BufferedLineStream::new(file);

        let wire_report = WireUsageReport {
            total_wires: 3,
            primary_inputs: 2,
            intermediate_wires: 0,
            primary_outputs: 1,
            missing_wires_count: 0,
            wire_usage_counts: vec![1, 1, 0],
            primary_input_wires: vec![0, 1],
            primary_output_wires: vec![2],
        };

        let seed = create_test_seed();
        let result = garble_circuit(&mut stream, &wire_report, &seed);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Invalid num_inputs at line "));
    }

    #[test]
    fn test_garble_circuit_empty_line_error() {
        let circuit_data = "1 3\n\n";
        let temp_file = create_test_file(circuit_data).unwrap();
        let file = File::open(temp_file.path()).unwrap();
        let mut stream = BufferedLineStream::new(file);

        let wire_report = WireUsageReport {
            total_wires: 3,
            primary_inputs: 2,
            intermediate_wires: 0,
            primary_outputs: 1,
            missing_wires_count: 0,
            wire_usage_counts: vec![1, 1, 0],
            primary_input_wires: vec![0, 1],
            primary_output_wires: vec![2],
        };

        let seed = create_test_seed();
        let result = garble_circuit(&mut stream, &wire_report, &seed);

        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Empty line at line number "));
    }

    #[test]
    fn test_wire_labels_json_serialization() -> Result<()> {
        let mut input_labels = std::collections::HashMap::new();
        let mut output_labels = std::collections::HashMap::new();

        input_labels.insert(0, WireLabel::new([0x01; 16]));
        input_labels.insert(1, WireLabel::new([0x02; 16]));
        output_labels.insert(2, WireLabel::new([0x03; 16]));

        let delta = WireLabel::new([0xFF; 16]);

        let wire_labels = WireLabels {
            input_labels,
            output_labels,
            delta,
        };

        // Test save and load
        let temp_file = tempfile::NamedTempFile::new()?;
        wire_labels.save_json(temp_file.path())?;
        let loaded_labels = WireLabels::load_json(temp_file.path())?;

        // Verify loaded data matches original
        assert_eq!(
            loaded_labels.input_labels.len(),
            wire_labels.input_labels.len()
        );
        assert_eq!(
            loaded_labels.output_labels.len(),
            wire_labels.output_labels.len()
        );
        assert_eq!(loaded_labels.delta, wire_labels.delta);

        for (&wire_id, &label) in &wire_labels.input_labels {
            assert_eq!(loaded_labels.input_labels.get(&wire_id), Some(&label));
        }

        Ok(())
    }

    #[test]
    fn test_garbling_result_save() -> Result<()> {
        let circuit_data = "2 5\n2 1 0 1 2 XOR\n2 1 2 3 4 AND\n";
        let wire_report = create_wire_report(circuit_data)?;
        let seed = create_test_seed();

        let temp_file = create_test_file(circuit_data)?;
        let file = File::open(temp_file.path())?;
        let mut stream = BufferedLineStream::new(file);

        let result = garble_circuit(&mut stream, &wire_report, &seed)?;

        // Test saving
        let labels_file = tempfile::NamedTempFile::new()?;
        let tables_file = tempfile::NamedTempFile::new()?;

        result.save(labels_file.path(), tables_file.path())?;

        // Verify files were created and have content
        assert!(labels_file.path().exists());
        assert!(tables_file.path().exists());

        let labels_size = std::fs::metadata(labels_file.path())?.len();
        let tables_size = std::fs::metadata(tables_file.path())?.len();

        assert!(labels_size > 0);
        // Should have 1 AND gate = 64 bytes
        assert_eq!(tables_size, 64);

        Ok(())
    }

    #[test]
    fn test_deterministic_garbling() -> Result<()> {
        let circuit_data = "2 5\n2 1 0 1 2 XOR\n2 1 2 3 4 AND\n";
        let wire_report = create_wire_report(circuit_data)?;
        let seed = create_test_seed();

        // Garble same circuit twice with same seed
        let temp_file1 = create_test_file(circuit_data)?;
        let file1 = File::open(temp_file1.path())?;
        let mut stream1 = BufferedLineStream::new(file1);
        let result1 = garble_circuit(&mut stream1, &wire_report, &seed)?;

        let temp_file2 = create_test_file(circuit_data)?;
        let file2 = File::open(temp_file2.path())?;
        let mut stream2 = BufferedLineStream::new(file2);
        let result2 = garble_circuit(&mut stream2, &wire_report, &seed)?;

        // Results should be identical
        assert_eq!(result1.garbled_tables.len(), result2.garbled_tables.len());
        assert_eq!(result1.wire_labels.delta, result2.wire_labels.delta);

        // Garbled tables should be identical
        for (table1, table2) in result1
            .garbled_tables
            .iter()
            .zip(result2.garbled_tables.iter())
        {
            assert_eq!(table1.ciphertexts, table2.ciphertexts);
        }

        Ok(())
    }

    #[test]
    fn test_free_xor_correctness() -> Result<()> {
        let circuit_data = "1 3\n2 1 0 1 2 XOR\n";
        let wire_report = create_wire_report(circuit_data)?;
        let seed = create_test_seed();

        let temp_file = create_test_file(circuit_data)?;
        let file = File::open(temp_file.path())?;
        let mut stream = BufferedLineStream::new(file);

        let result = garble_circuit(&mut stream, &wire_report, &seed)?;

        // Get input and output wire labels
        let input0_labels = result.wire_labels.get_wire_labels(0).unwrap();
        let input1_labels = result.wire_labels.get_wire_labels(1).unwrap();
        let output_labels = result.wire_labels.get_wire_labels(2).unwrap();

        // Verify free XOR property: output_0 = input0_0 XOR input1_0
        let expected_output_0 = input0_labels[0].xor(&input1_labels[0]);
        assert_eq!(output_labels[0], expected_output_0);

        // Verify output_1 = output_0 XOR delta
        let expected_output_1 = output_labels[0].xor(&result.wire_labels.delta);
        assert_eq!(output_labels[1], expected_output_1);

        Ok(())
    }
}
