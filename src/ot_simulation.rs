use anyhow::Result;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::path::Path;
use rand_chacha::ChaCha12Rng;
use rand::{RngCore, SeedableRng};
use indicatif::{ProgressBar, ProgressStyle};

use crate::garbler::{WireLabel, WireLabels};

/// OT simulation result containing selected input labels and their bit values
#[derive(Debug, Serialize, Deserialize)]
pub struct OTResult {
    /// Selected input labels: wire_id -> (selected_label, bit_value)
    pub selected_inputs: HashMap<usize, SelectedInput>,
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
    pub fn get_selected_input(&self, wire_id: usize) -> Option<&SelectedInput> {
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
    let total_inputs = wire_labels.input_labels.len();
    
    // Create progress bar for OT simulation
    let pb = ProgressBar::new(total_inputs as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}")
            .unwrap()
            .progress_chars("##-")
    );
    pb.set_message("Simulating OT protocol...");
    
    let mut processed = 0;
    
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
        
        selected_inputs.insert(wire_id, SelectedInput {
            label: selected_label,
            bit_value,
        });
        
        processed += 1;
        if processed % 1000 == 0 {
            pb.set_position(processed as u64);
        }
    }
    
    // Finish progress bar
    pb.finish_with_message(format!("✓ Simulated OT for {} input wires", total_inputs));
    
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
    fn test_ot_result_serialization() {
        let mut selected_inputs = HashMap::new();
        selected_inputs.insert(0, SelectedInput {
            label: WireLabel::new([0x42; 16]),
            bit_value: true,
        });
        
        let ot_result = OTResult { selected_inputs };
        
        // Test JSON serialization round-trip
        ot_result.save_json("test_ot.json").unwrap();
        let loaded_result = OTResult::load_json("test_ot.json").unwrap();
        
        assert_eq!(loaded_result.selected_inputs.len(), 1);
        let selected = loaded_result.get_selected_input(0).unwrap();
        assert_eq!(selected.label, WireLabel::new([0x42; 16]));
        assert_eq!(selected.bit_value, true);
        
        // Clean up test file
        std::fs::remove_file("test_ot.json").ok();
    }
}