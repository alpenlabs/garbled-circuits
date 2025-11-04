use anyhow::{Result, bail};
use gc::constants::PROGRESS_UPDATE_INTERVAL;
use gc::stream::BufferedLineStream;
use indicatif::{ProgressBar, ProgressStyle};
use std::collections::HashMap;

/// Result of plain circuit evaluation
#[derive(Debug, PartialEq, Eq)]
pub struct PlainEvaluationResult {
    /// Output wire results: wire_id -> bit_value
    pub output_results: HashMap<u32, bool>,
}

/// Evaluate a Bristol circuit in plain (ungarbled) form with given input bits
///
/// This function evaluates a circuit by directly computing gate operations on bit values,
/// providing ground truth for comparing against garbled circuit evaluation.
///
/// Expected Bristol format:
/// First line: `<num_gates> <num_wires>`
/// Followed by gate lines: `<num_inputs> <num_outputs> <input_wires...> <output_wires...> <gate_type>`
///
/// # Arguments
/// * `stream` - The line stream to process Bristol circuit
/// * `input_bits` - Input wire assignments: wire_id -> bit_value mapping
/// * `output_wire_ids` - List of output wire IDs to return
///
/// # Returns
/// * `Ok(PlainEvaluationResult)` - Output wire bit values
/// * `Err(anyhow::Error)` - Parse error or evaluation error
pub fn evaluate_plain_circuit(
    stream: &mut BufferedLineStream,
    input_bits: &HashMap<u32, bool>,
    output_wire_ids: &[u32],
) -> Result<PlainEvaluationResult> {
    // Parse and validate header line
    let header_line = stream.next_line().ok_or_else(|| {
        anyhow::anyhow!(
            "Missing header line - Bristol circuit must start with '<num_gates> <num_wires>'"
        )
    })??;

    let header_tokens: Vec<&str> = header_line.split_whitespace().collect();
    if header_tokens.len() != 2 {
        bail!(
            "Invalid header: expected '<num_gates> <num_wires>', got: '{}'",
            header_line
        );
    }

    let num_gates: u32 = header_tokens[0]
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid num_gates: '{}'", header_tokens[0]))?;
    let num_wires: u32 = header_tokens[1]
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid num_wires: '{}'", header_tokens[1]))?;

    // Initialize Vec-based storage for wire values and computed flags
    let mut wire_values: Vec<bool> = vec![false; num_wires as usize];
    let mut wire_computed: Vec<bool> = vec![false; num_wires as usize];

    // Set Input values
    for (&wire_id, &bit_value) in input_bits {
        wire_values[wire_id as usize] = bit_value;
        wire_computed[wire_id as usize] = true;
    }

    // Create progress bar for gate processing
    let pb = ProgressBar::new(num_gates as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}")
            .unwrap()
            .progress_chars("##-"),
    );
    pb.set_message("Evaluating circuit...");

    // Process gates line by line
    let mut line_number = 0;
    while let Some(line_result) = stream.next_line() {
        line_number += 1;
        let line = line_result?;

        if line.trim().is_empty() {
            bail!("Empty line at line number {}", line_number);
        }

        // Parse gate line
        let mut tokens = line.split_whitespace();

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

        // Validate standard gate in-parity and out-parity for our case
        if num_inputs != 2 || num_outputs != 1 {
            bail!(
                "Gate must have 2 inputs and 1 output at line {}: got {} inputs, {} outputs",
                line_number,
                num_inputs,
                num_outputs
            );
        }

        // Parse input wires directly
        let input_wire_1: u32 = tokens
            .next()
            .ok_or_else(|| anyhow::anyhow!("Missing input wire 1 at line {}", line_number))?
            .parse()
            .map_err(|_| {
                anyhow::anyhow!("Invalid input wire 1 at line {}: '{}'", line_number, line)
            })?;

        let input_wire_2: u32 = tokens
            .next()
            .ok_or_else(|| anyhow::anyhow!("Missing input wire 2 at line {}", line_number))?
            .parse()
            .map_err(|_| {
                anyhow::anyhow!("Invalid input wire 2 at line {}: '{}'", line_number, line)
            })?;

        // Parse output wire directly
        let output_wire: u32 = tokens
            .next()
            .ok_or_else(|| anyhow::anyhow!("Missing output wire at line {}", line_number))?
            .parse()
            .map_err(|_| {
                anyhow::anyhow!("Invalid output wire at line {}: '{}'", line_number, line)
            })?;

        // Parse gate type
        let gate_type = tokens.next().ok_or_else(|| {
            anyhow::anyhow!("Missing gate type at line {}: '{}'", line_number, line)
        })?;

        // Validate no extra tokens
        if tokens.next().is_some() {
            bail!("Too many tokens at line {}: '{}'", line_number, line);
        }

        // Evaluate gate based on type
        match gate_type {
            "XOR" => {
                let input1_idx = input_wire_1 as usize;
                let input2_idx = input_wire_2 as usize;
                let output_idx = output_wire as usize;

                // Check that input wires have been computed
                if !wire_computed[input1_idx] {
                    bail!(
                        "Input wire {} value not computed yet until gate at line {}",
                        input_wire_1,
                        line_number
                    );
                }
                if !wire_computed[input2_idx] {
                    bail!(
                        "Input wire {} value not computed yet until gate at line {}",
                        input_wire_2,
                        line_number
                    );
                }

                let output_bit = wire_values[input1_idx] ^ wire_values[input2_idx];
                wire_values[output_idx] = output_bit;
                wire_computed[output_idx] = true;
            }
            "AND" => {
                let input1_idx = input_wire_1 as usize;
                let input2_idx = input_wire_2 as usize;
                let output_idx = output_wire as usize;

                // Check that input wires have been computed
                if !wire_computed[input1_idx] {
                    bail!(
                        "Input wire {} value not computed yet until gate at line {}",
                        input_wire_1,
                        line_number
                    );
                }
                if !wire_computed[input2_idx] {
                    bail!(
                        "Input wire {} value not computed yet until gate at line {}",
                        input_wire_2,
                        line_number
                    );
                }

                let output_bit = wire_values[input1_idx] & wire_values[input2_idx];
                wire_values[output_idx] = output_bit;
                wire_computed[output_idx] = true;
            }
            _ => {
                bail!(
                    "Unsupported gate type '{}' at line {} - only XOR and AND gates are supported",
                    gate_type,
                    line_number
                );
            }
        }

        // Update progress bar
        let gate_index: u32 = line_number - 1;
        if gate_index.is_multiple_of(PROGRESS_UPDATE_INTERVAL) {
            pb.set_position(gate_index as u64);
            pb.set_message("Evaluating circuit...");
        }
    }

    // Finish progress bar
    pb.finish_with_message(format!("✓ Evaluated {line_number} gates"));

    // Collect output results with validation
    let mut output_results = HashMap::new();
    for &output_wire_id in output_wire_ids {
        // Validate output wire ID bounds
        if output_wire_id >= num_wires {
            bail!(
                "Output wire ID {} exceeds circuit capacity of {} wires",
                output_wire_id,
                num_wires
            );
        }

        let output_idx = output_wire_id as usize;

        // Check if output wire has been computed
        if !wire_computed[output_idx] {
            bail!(
                "Output wire {} value was never computed by any gate",
                output_wire_id
            );
        }

        output_results.insert(output_wire_id, wire_values[output_idx]);
    }

    Ok(PlainEvaluationResult { output_results })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile;

    fn create_test_file(content: &str) -> Result<tempfile::NamedTempFile> {
        let mut temp_file = tempfile::NamedTempFile::new()?;
        temp_file.write_all(content.as_bytes())?;
        temp_file.flush()?;
        Ok(temp_file)
    }

    #[test]
    fn test_plain_evaluate_simple_xor() -> Result<()> {
        let circuit_data = "1 3\n2 1 0 1 2 XOR\n";
        let temp_file = create_test_file(circuit_data)?;
        let file = File::open(temp_file.path())?;
        let mut stream = gc::stream::BufferedLineStream::new(file);

        let mut input_bits = HashMap::new();
        input_bits.insert(0, true); // wire 0 = 1
        input_bits.insert(1, false); // wire 1 = 0
        let output_wire_ids = vec![2];

        let result = evaluate_plain_circuit(&mut stream, &input_bits, &output_wire_ids)?;

        // 1 XOR 0 = 1
        assert_eq!(result.output_results.len(), 1);
        assert!(result.output_results[&2]);

        Ok(())
    }

    #[test]
    fn test_plain_evaluate_simple_and() -> Result<()> {
        let circuit_data = "1 3\n2 1 0 1 2 AND\n";
        let temp_file = create_test_file(circuit_data)?;
        let file = File::open(temp_file.path())?;
        let mut stream = gc::stream::BufferedLineStream::new(file);

        let mut input_bits = HashMap::new();
        input_bits.insert(0, true); // wire 0 = 1
        input_bits.insert(1, true); // wire 1 = 1
        let output_wire_ids = vec![2];

        let result = evaluate_plain_circuit(&mut stream, &input_bits, &output_wire_ids)?;

        // 1 AND 1 = 1
        assert_eq!(result.output_results.len(), 1);
        assert!(result.output_results[&2]);

        Ok(())
    }

    #[test]
    fn test_plain_evaluate_mixed_gates() -> Result<()> {
        let circuit_data = "3 6\n2 1 0 1 2 XOR\n2 1 2 3 4 XOR\n2 1 2 4 5 AND\n";
        let temp_file = create_test_file(circuit_data)?;
        let file = File::open(temp_file.path())?;
        let mut stream = gc::stream::BufferedLineStream::new(file);

        let mut input_bits = HashMap::new();
        input_bits.insert(0, true);
        input_bits.insert(1, false);
        input_bits.insert(3, true);
        let output_wire_ids = vec![5];

        let result = evaluate_plain_circuit(&mut stream, &input_bits, &output_wire_ids)?;

        assert_eq!(result.output_results.len(), 1);
        assert!(!result.output_results[&5]);

        Ok(())
    }
}
