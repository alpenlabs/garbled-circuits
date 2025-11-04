use anyhow::Result;
use base64::prelude::*;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha12Rng;
use std::collections::HashMap;
use std::fs::File;

use gc::evaluator::evaluate_circuit;
use gc::garbler::garble_circuit;
use gc::ot_simulation::create_ot_result_with_specific_inputs;
use gc::stream::BufferedLineStream;
use gc::wire_analyzer::analyze_wire_usage;
use gc_integration_tests::plain_evaluator::evaluate_plain_circuit;

// Fixed seed for reproducible tests
const TEST_SEED: [u8; 32] = [42; 32];

// Circuit output wire IDs.
// These will be eventually incorporated in the circuit in the as per issue
// https://github.com/alpenlabs/dv-pari-circuit/issues/7. These can be removed then
const ADDER64_OUTPUT_WIRES: &[u32] = &[
    440, 441, 442, 443, 444, 445, 446, 447, 448, 449, 450, 451, 452, 453, 454, 455, 456, 457, 458,
    459, 460, 461, 462, 463, 464, 465, 466, 467, 468, 469, 470, 471, 472, 473, 474, 475, 476, 477,
    478, 479, 480, 481, 482, 483, 484, 485, 486, 487, 488, 489, 490, 491, 492, 493, 494, 495, 496,
    497, 498, 499, 500, 501, 502, 503, // 64-bit sum (wires 440-503)
];

const MULT64_OUTPUT_WIRES: &[u32] = &[
    13739, 13740, 13741, 13742, 13743, 13744, 13745, 13746, 13747, 13748, 13749, 13750, 13751,
    13752, 13753, 13754, 13755, 13756, 13757, 13758, 13759, 13760, 13761, 13762, 13763, 13764,
    13765, 13766, 13767, 13768, 13769, 13770, 13771, 13772, 13773, 13774, 13775, 13776, 13777,
    13778, 13779, 13780, 13781, 13782, 13783, 13784, 13785, 13786, 13787, 13788, 13789, 13790,
    13791, 13792, 13793, 13794, 13795, 13796, 13797, 13798, 13799, 13800, 13801,
    13802, // 64-bit product (wires 13739-13802) - lower 64 bits only
];

const DV_OUTPUT_WIRES: &[u32] = &[3284036995]; // Single bit verification result

const AND4_OUTPUT_WIRES: &[u32] = &[6]; // Single output wire for AND4 circuit

/// Load a Bristol circuit file and create a buffered line stream
///
/// # Arguments
/// * `path` - Path to the Bristol circuit file
///
/// # Returns
/// * `Ok(BufferedLineStream)` - Stream ready for circuit processing
/// * `Err(anyhow::Error)` - File IO error
fn load_bristol_circuit_from_file(path: &str) -> Result<BufferedLineStream> {
    let file_handle = File::open(path)?;
    let stream = BufferedLineStream::new(file_handle);
    Ok(stream)
}

/// Test adder64 circuit with random inputs for multiple iterations
///
/// Generates random 64-bit operand pairs and tests the adder circuit
///
/// # Arguments
/// * `iterations` - Number of random test iterations to perform
///
/// # Returns
/// * `Ok(())` - All tests passed
/// * `Err(anyhow::Error)` - Test failure or file error
fn test_adder64_random_inputs(iterations: u32) -> Result<()> {
    let mut rng = ChaCha12Rng::from_seed(TEST_SEED);

    for _ in 0..iterations {
        let a = rng.next_u64();
        let b = rng.next_u64();
        let inputs = create_adder64_inputs(a, b);
        test_circuit_with_specific_inputs(
            "../example_ckts/adder64.bristol",
            &inputs,
            ADDER64_OUTPUT_WIRES,
        )?;
    }

    Ok(())
}

/// Test mult64 circuit with random inputs for multiple iterations
///
/// Generates random 64-bit operand pairs and tests the multiplier circuit
///
/// # Arguments
/// * `iterations` - Number of random test iterations to perform
///
/// # Returns
/// * `Ok(())` - All tests passed
/// * `Err(anyhow::Error)` - Test failure or file error
fn test_mult64_random_inputs(iterations: u32) -> Result<()> {
    let mut rng = ChaCha12Rng::from_seed(TEST_SEED);

    for _ in 0..iterations {
        let a = rng.next_u64();
        let b = rng.next_u64();
        let inputs = create_mult64_inputs(a, b);
        test_circuit_with_specific_inputs(
            "../example_ckts/mult64.bristol",
            &inputs,
            MULT64_OUTPUT_WIRES,
        )?;
    }

    Ok(())
}

/// Test DV circuit with random inputs for multiple iterations
///
/// Generates random byte arrays and tests the DV SNARK verifier circuit
///
/// # Arguments
/// * `iterations` - Number of random test iterations to perform
///
/// # Returns
/// * `Ok(())` - All tests passed
/// * `Err(anyhow::Error)` - Test failure or file error
fn test_dv_random_inputs(iterations: u32) -> Result<()> {
    let mut rng = ChaCha12Rng::from_seed(TEST_SEED);

    for _ in 0..iterations {
        let mut input_data = vec![0u8; 273];
        rng.fill_bytes(&mut input_data);
        let inputs = create_dv_inputs(&input_data);
        test_circuit_with_specific_inputs("../example_ckts/dv.bristol", &inputs, DV_OUTPUT_WIRES)?;
    }

    Ok(())
}

/// Test a Bristol circuit file with one specific set of inputs
///
/// This helper function tests a circuit with the provided input values by comparing
/// plain vs garbled evaluation.
///
/// # Arguments  
/// * `circuit_path` - Path to the Bristol circuit file
/// * `inputs` - Specific input wire values to test
/// * `output_wires` - Primary output wire IDs
///
/// # Returns
/// * `Ok(())` - Test passed
/// * `Err(anyhow::Error)` - Test failure or file error  
fn test_circuit_with_specific_inputs(
    circuit_path: &str,
    inputs: &HashMap<u32, bool>,
    output_wires: &[u32],
) -> Result<()> {
    // === Wire Analysis (run once and reused) ===
    let mut stream_wire = load_bristol_circuit_from_file(circuit_path)?;
    let wire_report = analyze_wire_usage(&mut stream_wire)?;

    // === Plain Evaluation ===
    let mut stream_plain = load_bristol_circuit_from_file(circuit_path)?;
    let plain_result = evaluate_plain_circuit(&mut stream_plain, inputs, output_wires)?;

    // === Garbled Evaluation ===

    // 1. Garble circuit
    let mut stream_garble = load_bristol_circuit_from_file(circuit_path)?;
    let garble_seed = TEST_SEED;
    let garbling_result = garble_circuit(&mut stream_garble, &wire_report, &garble_seed)?;

    // 2. Create OT result with specific input bits
    let ot_result = create_ot_result_with_specific_inputs(&garbling_result.wire_labels, inputs)?;

    // 3. Save garbled tables and evaluate
    let tables_file = tempfile::NamedTempFile::new()?;
    let mut tables_data = Vec::new();
    for table in &garbling_result.garbled_tables {
        tables_data.extend_from_slice(&table.as_binary());
    }
    std::fs::write(tables_file.path(), tables_data)?;

    let mut stream_eval = load_bristol_circuit_from_file(circuit_path)?;
    let garbled_result = evaluate_circuit(
        &mut stream_eval,
        &wire_report,
        &ot_result,
        tables_file.path(),
    )?;

    // === Compare Results ===
    // Check that both evaluations produce the same output

    for (&wire_id, &plain_bit) in &plain_result.output_results {
        let garbled_output = garbled_result.output_results.get(&wire_id).unwrap();
        println!(
            "Output wire {}: plain={}, garbled={}",
            wire_id, plain_bit, garbled_output.bit_value
        );
        assert_eq!(
            plain_bit, garbled_output.bit_value,
            "Mismatch for output wire {}: plain={}, garbled={}",
            wire_id, plain_bit, garbled_output.bit_value
        );
    }

    Ok(())
}

/// Helper function to create input bits for a 64-bit adder circuit
///
/// Adder64 circuit expects two 64-bit inputs (a and b) and produces a 64-bit sum and carry
/// Input wire layout: wires 0-63 for operand A, wires 64-127 for operand B
fn create_adder64_inputs(a: u64, b: u64) -> HashMap<u32, bool> {
    let mut inputs = HashMap::new();

    // Set bits for operand A (wires 0-63)
    for i in 0..64 {
        inputs.insert(i, (a >> i) & 1 == 1);
    }

    // Set bits for operand B (wires 64-127)
    for i in 0..64 {
        inputs.insert(64 + i, (b >> i) & 1 == 1);
    }

    inputs
}

/// Helper function to create input bits for a 64-bit multiplier circuit  
///
/// Mult64 circuit expects two 64-bit inputs (a and b) and produces a 128-bit product
/// Input wire layout: wires 0-63 for operand A, wires 64-127 for operand B
fn create_mult64_inputs(a: u64, b: u64) -> HashMap<u32, bool> {
    let mut inputs = HashMap::new();

    // Set bits for operand A (wires 0-63)
    for i in 0..64 {
        inputs.insert(i, (a >> i) & 1 == 1);
    }

    // Set bits for operand B (wires 64-127)
    for i in 0..64 {
        inputs.insert(64 + i, (b >> i) & 1 == 1);
    }

    inputs
}

/// Helper function to create input bits for the DV SNARK verifier circuit
///
/// DV circuit has 1706 primary inputs for SNARK verification
/// Takes a byte array and uses it to initialize wire values bit by bit
///
/// # Arguments
/// * `input_data` - Byte array to extract bits from (must have at least 273 bytes for 2177 bits)
fn create_dv_inputs(input_data: &[u8]) -> HashMap<u32, bool> {
    let mut inputs = HashMap::new();

    for wire_id in 0..1706 {
        let byte_idx = (wire_id / 8) as usize;
        let bit_idx = wire_id % 8;
        let bit_value = (input_data[byte_idx] >> bit_idx) & 1 == 1;
        inputs.insert(wire_id, bit_value);
    }

    inputs
}

#[test]
fn test_adder64_random() -> Result<()> {
    test_adder64_random_inputs(10)
}

#[test]
fn test_adder64_specific() -> Result<()> {
    let circuit_path = "../example_ckts/adder64.bristol";
    test_circuit_with_specific_inputs(
        circuit_path,
        &create_adder64_inputs(0, 0),
        ADDER64_OUTPUT_WIRES,
    )?;

    test_circuit_with_specific_inputs(
        circuit_path,
        &create_adder64_inputs(u64::MAX, 0),
        ADDER64_OUTPUT_WIRES,
    )?;

    test_circuit_with_specific_inputs(
        circuit_path,
        &create_adder64_inputs(1, 1),
        ADDER64_OUTPUT_WIRES,
    )?;

    test_circuit_with_specific_inputs(
        circuit_path,
        &create_adder64_inputs(u64::MAX, 1),
        ADDER64_OUTPUT_WIRES,
    )?;

    test_circuit_with_specific_inputs(
        circuit_path,
        &create_adder64_inputs(1024, 2048),
        ADDER64_OUTPUT_WIRES,
    )?;

    Ok(())
}

#[test]
fn test_mult64_random() -> Result<()> {
    test_mult64_random_inputs(10)
}

#[test]
fn test_mult64_specific() -> Result<()> {
    let circuit_path = "../example_ckts/mult64.bristol";
    test_circuit_with_specific_inputs(
        circuit_path,
        &create_mult64_inputs(0, u64::MAX),
        MULT64_OUTPUT_WIRES,
    )?;
    test_circuit_with_specific_inputs(
        circuit_path,
        &create_mult64_inputs(u64::MAX, 0),
        MULT64_OUTPUT_WIRES,
    )?;

    test_circuit_with_specific_inputs(
        circuit_path,
        &create_mult64_inputs(1, 12345),
        MULT64_OUTPUT_WIRES,
    )?;
    test_circuit_with_specific_inputs(
        circuit_path,
        &create_mult64_inputs(98765, 1),
        MULT64_OUTPUT_WIRES,
    )?;

    test_circuit_with_specific_inputs(
        circuit_path,
        &create_mult64_inputs(1024, 1),
        MULT64_OUTPUT_WIRES,
    )?;
    test_circuit_with_specific_inputs(
        circuit_path,
        &create_mult64_inputs(1, 2048),
        MULT64_OUTPUT_WIRES,
    )?;

    test_circuit_with_specific_inputs(
        circuit_path,
        &create_mult64_inputs(123, 456),
        MULT64_OUTPUT_WIRES,
    )?;

    Ok(())
}

#[test]
#[ignore = "Long running test - run manually"]
fn test_dv_random() -> Result<()> {
    test_dv_random_inputs(1) // Only 1 iteration due to long time this takes
}

#[test]
#[ignore = "Long running test - run manually"]
fn test_dv_specific() -> Result<()> {
    let circuit_path = "../example_ckts/dv.bristol";

    // Base64 encoded witness for DV circuit (1706 bits) which should pass
    const DV_WITNESS_BASE64: &str = "NopG2gyd3WKkU85x8ovQk86m+b+WUiuXa8nlz259s7+DYQ3hM9/zDoNPzbWLRlMH8rrlgXHgLyORRZW7Ys4VYwLCnYrdDibCNIdmbZvXBUsWnY3JYFWr0PWlFqmdj51EDltJm2/DzlKyCxeawvO8YWr6+OKDF+sP5kS2VwO8G2SNpurjfmbWGr2c4mRy0RQT0ysUr2u45EgI4wAw02M+3Ijm2wb77xWWSVRsCnwE0i+/vq5JaMZxw02Rw9IQqDp+7kyq44XZCtYTx0wVCC25C33PL+3LAQ==";

    // Decode base64 to bytes
    let witness_bytes = base64::prelude::BASE64_STANDARD.decode(DV_WITNESS_BASE64)?;

    // Generate input from the decoded bytes
    let inputs = create_dv_inputs(&witness_bytes);

    // Test circuit with generated inputs
    test_circuit_with_specific_inputs(circuit_path, &inputs, DV_OUTPUT_WIRES)?;

    Ok(())
}

#[test]
fn test_and4_comprehensive() -> Result<()> {
    let circuit_path = "../example_ckts/and4.bristol";

    // Test all 16 possible input combinations (2^4 = 16)
    for combination in 0..16u8 {
        let mut inputs = HashMap::new();
        for wire_id in 0..4 {
            inputs.insert(wire_id, (combination >> wire_id) & 1 == 1);
        }

        test_circuit_with_specific_inputs(circuit_path, &inputs, AND4_OUTPUT_WIRES)?;
    }

    Ok(())
}
