use anyhow::Result;
use indicatif::{ProgressBar, ProgressStyle};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha12Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

use crate::constants::PROGRESS_UPDATE_INTERVAL;
use crate::garbler::{WireLabel, WireLabels};

/// OT simulation result containing selected input labels and their bit values
#[derive(Debug, Serialize, Deserialize)]
pub struct OTResult {
    /// Selected input labels: wire_id -> (selected_label, bit_value)
    pub selected_inputs: HashMap<u32, SelectedInput>,
}

/// A selected input from OT simulation
#[derive(Debug, Serialize, Deserialize)]
pub struct SelectedInput {
    /// The selected wire label
    pub label: WireLabel,
    /// The bit value this label represents (0 or 1)
    pub bit_value: bool,
}

impl OTResult {
    /// Save OT result as JSON
    pub fn save_json<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Load OT result from JSON
    pub fn load_json<P: AsRef<Path>>(path: P) -> Result<Self> {
        let data = std::fs::read_to_string(path)?;
        let ot_result = serde_json::from_str(&data)?;
        Ok(ot_result)
    }

    /// Get the selected label for a wire
    pub fn get_selected_input(&self, wire_id: u32) -> Option<&SelectedInput> {
        self.selected_inputs.get(&wire_id)
    }
}

/// Simulate OT protocol by randomly selecting input wire labels
///
/// For each primary input wire, randomly chooses between label_0 (bit=0) or label_1 (bit=1)
/// using a cryptographically secure random number generator.
///
/// # Arguments
/// * `wire_labels` - Wire labels from garbler output containing input/output labels and delta
/// * `seed_data` - 32 bytes of random seed for CSPRNG
///
/// # Returns
/// * `Ok(OTResult)` - Selected input labels with their corresponding bit values
/// * `Err(anyhow::Error)` - Serialization error
pub fn simulate_ot(wire_labels: &WireLabels, seed_data: &[u8; 32]) -> Result<OTResult> {
    // Initialize CSPRNG with provided seed
    let mut rng = ChaCha12Rng::from_seed(*seed_data);

    let mut selected_inputs = HashMap::new();
    let total_inputs: u32 = wire_labels.input_labels.len() as u32;

    // Create progress bar for OT simulation
    let pb = ProgressBar::new(total_inputs as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template(
                "{bar:40.green/blue} {pos}/{len} inputs [{elapsed_precise}<{eta_precise}] {msg}",
            )
            .unwrap()
            .progress_chars("#>-"),
    );
    pb.set_message("Simulating OT protocol");

    let mut processed: u32 = 0;

    // For each input wire, randomly select bit value and corresponding label
    for (&wire_id, &label_0) in &wire_labels.input_labels {
        // Generate random bit (0 or 1)
        let bit_value = (rng.next_u32() & 1) == 1;

        // Select the appropriate label based on the bit value
        let selected_label = if bit_value {
            // bit_value = 1 -> select label_1 = label_0 XOR delta
            label_0.xor(&wire_labels.delta)
        } else {
            // bit_value = 0 -> select label_0
            label_0
        };

        selected_inputs.insert(
            wire_id,
            SelectedInput {
                label: selected_label,
                bit_value,
            },
        );

        processed += 1;

        // Update progress bar periodically for better performance
        if processed.is_multiple_of(PROGRESS_UPDATE_INTERVAL) {
            pb.set_position(processed as u64);
        }
    }

    // Finish progress bar with final position
    pb.set_position(processed as u64);
    pb.finish_with_message(format!("✓ Simulated OT for {total_inputs} input wires"));

    Ok(OTResult { selected_inputs })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_ot_simulation_deterministic() {
        // Create test wire labels
        let mut input_labels = HashMap::new();
        let label_0 = WireLabel::new([0x01; 16]);
        let delta = WireLabel::new([0xFF; 16]);

        input_labels.insert(0, label_0);
        input_labels.insert(1, label_0);

        let wire_labels = WireLabels {
            input_labels,
            output_labels: HashMap::new(),
            delta,
        };

        // Use fixed seed for deterministic test
        let seed = [0u8; 32];

        // Run OT simulation
        let ot_result = simulate_ot(&wire_labels, &seed).unwrap();

        // Verify we got results for both input wires
        assert_eq!(ot_result.selected_inputs.len(), 2);
        assert!(ot_result.selected_inputs.contains_key(&0));
        assert!(ot_result.selected_inputs.contains_key(&1));

        // Verify selected labels are either label_0 or label_0 XOR delta
        for (&wire_id, selected_input) in &ot_result.selected_inputs {
            let expected_label_0 = wire_labels.input_labels[&wire_id];
            let expected_label_1 = expected_label_0.xor(&delta);

            if selected_input.bit_value {
                assert_eq!(selected_input.label, expected_label_1);
            } else {
                assert_eq!(selected_input.label, expected_label_0);
            }
        }
    }

    #[test]
    fn test_ot_result_serialization() -> anyhow::Result<()> {
        let mut selected_inputs = HashMap::new();
        selected_inputs.insert(
            0u32,
            SelectedInput {
                label: WireLabel::new([0x42; 16]),
                bit_value: true,
            },
        );

        let ot_result = OTResult { selected_inputs };

        // Test JSON serialization round-trip using temporary file
        let temp_file = tempfile::NamedTempFile::new()?;
        ot_result.save_json(temp_file.path())?;
        let loaded_result = OTResult::load_json(temp_file.path())?;

        assert_eq!(loaded_result.selected_inputs.len(), 1);
        let selected = loaded_result.get_selected_input(0u32).unwrap();
        assert_eq!(selected.label, WireLabel::new([0x42; 16]));
        assert!(selected.bit_value);

        Ok(())
    }

    #[test]
    fn test_ot_simulation_empty_inputs() -> anyhow::Result<()> {
        let wire_labels = WireLabels {
            input_labels: HashMap::new(),
            output_labels: HashMap::new(),
            delta: WireLabel::new([0xFF; 16]),
        };

        let seed = [0x42; 32];
        let ot_result = simulate_ot(&wire_labels, &seed)?;

        assert_eq!(ot_result.selected_inputs.len(), 0);

        Ok(())
    }

    #[test]
    fn test_ot_simulation_multiple_inputs() -> anyhow::Result<()> {
        let mut input_labels = HashMap::new();
        let label_0 = WireLabel::new([0x11; 16]);
        let delta = WireLabel::new([0xAA; 16]);

        // Add multiple input wires
        for i in 0..100u32 {
            input_labels.insert(i, label_0);
        }

        let wire_labels = WireLabels {
            input_labels,
            output_labels: HashMap::new(),
            delta,
        };

        let seed = [0x99; 32];
        let ot_result = simulate_ot(&wire_labels, &seed)?;

        // Should have selected labels for all 100 inputs
        assert_eq!(ot_result.selected_inputs.len(), 100);

        // Verify each selection is valid
        for i in 0..100u32 {
            let selected = ot_result.get_selected_input(i).unwrap();
            let expected_label_0 = wire_labels.input_labels[&i];
            let expected_label_1 = expected_label_0.xor(&delta);

            // Selected label should be either label_0 or label_1
            assert!(selected.label == expected_label_0 || selected.label == expected_label_1);

            // If bit_value is true, should have label_1, otherwise label_0
            if selected.bit_value {
                assert_eq!(selected.label, expected_label_1);
            } else {
                assert_eq!(selected.label, expected_label_0);
            }
        }

        Ok(())
    }

    #[test]
    fn test_ot_result_get_nonexistent_wire() {
        let ot_result = OTResult {
            selected_inputs: HashMap::new(),
        };

        assert!(ot_result.get_selected_input(999u32).is_none());
    }

    #[test]
    fn test_ot_simulation_label_consistency() -> anyhow::Result<()> {
        // Test that the XOR relationship holds: label_1 = label_0 XOR delta
        let mut input_labels = HashMap::new();
        let label_0 = WireLabel::new([
            0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0,
            0xF0, 0x00,
        ]);
        let delta = WireLabel::new([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F, 0x10,
        ]);

        input_labels.insert(42u32, label_0);

        let wire_labels = WireLabels {
            input_labels,
            output_labels: HashMap::new(),
            delta,
        };

        // Run OT simulation multiple times to test both bit values
        for seed_byte in 0..10u8 {
            let seed = [seed_byte; 32];
            let ot_result = simulate_ot(&wire_labels, &seed)?;

            let selected = ot_result.get_selected_input(42u32).unwrap();

            if selected.bit_value {
                // Should be label_1 = label_0 XOR delta
                let expected_label_1 = label_0.xor(&delta);
                assert_eq!(selected.label, expected_label_1);
            } else {
                // Should be label_0
                assert_eq!(selected.label, label_0);
            }
        }

        Ok(())
    }
}
