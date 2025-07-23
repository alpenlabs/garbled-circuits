use anyhow::{Result, bail};
use serde::{Serialize, Deserialize};
use std::fs::File;
use std::io::Write;
use std::path::Path;
use indicatif::{ProgressBar, ProgressStyle};

use crate::stream::BufferedLineStream;

/// Wire usage analysis results optimized for binary serialization
#[derive(Debug, Serialize, Deserialize)]
pub struct WireUsageReport {
    /// Total number of wires in the circuit
    pub total_wires: usize,
    /// Number of primary input wires
    pub primary_inputs: usize,
    /// Number of intermediate wires  
    pub intermediate_wires: usize,
    /// Number of primary output wires
    pub primary_outputs: usize,
    /// Number of missing/unused wires (gaps in wire numbering)
    pub missing_wires_count: usize,
    /// Wire usage counts: index = wire_id, value = usage_count
    pub wire_usage_counts: Vec<usize>,
    /// List of primary input wire IDs
    pub primary_input_wires: Vec<usize>,
    /// List of primary output wire IDs
    pub primary_output_wires: Vec<usize>,
}

impl WireUsageReport {
    /// Save the report to a binary file for fast loading in processing pipelines
    pub fn save_binary<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        // Create a spinner progress bar for serialization
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.green} [{elapsed_precise}] {msg}")
                .unwrap()
        );
        pb.set_message("Serializing wire analysis data...");
        
        let encoded = bincode::serialize(self)?;
        
        pb.set_message("Writing binary file...");
        std::fs::write(path, encoded)?;
        
        pb.finish_with_message("✓ Binary file saved");
        Ok(())
    }
    
    /// Load a report from a binary file
    pub fn load_binary<P: AsRef<Path>>(path: P) -> Result<Self> {
        let data = std::fs::read(path)?;
        let report = bincode::deserialize(&data)?;
        Ok(report)
    }
    
    /// Export summary as JSON for human inspection (optional)
    pub fn export_summary_json<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let summary = serde_json::json!({
            "total_wires": self.total_wires,
            "primary_inputs": self.primary_inputs,
            "intermediate_wires": self.intermediate_wires,
            "primary_outputs": self.primary_outputs,
            "missing_wires_count": self.missing_wires_count,
            "primary_input_wires": self.primary_input_wires,
            "primary_output_wires": self.primary_output_wires
        });
        
        let mut file = File::create(path)?;
        file.write_all(serde_json::to_string_pretty(&summary)?.as_bytes())?;
        Ok(())
    }
}

/// Parsed gate information
#[derive(Debug)]
struct Gate {
    inputs: Vec<usize>,
    outputs: Vec<usize>,
}

/// Parse a single gate line into input/output wire lists
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
    
    Ok(Gate { inputs, outputs })
}

/// Ensure the vector has capacity for the given wire_id
#[inline]
fn ensure_capacity(vec: &mut Vec<usize>, wire_id: usize) {
    if wire_id >= vec.len() {
        vec.resize(wire_id + 1, 0);
    }
}

/// Ensure the boolean vector has capacity for the given wire_id
#[inline]
fn ensure_capacity_bool(vec: &mut Vec<bool>, wire_id: usize) {
    if wire_id >= vec.len() {
        vec.resize(wire_id + 1, false);
    }
}

/// Analyze wire usage patterns in a Bristol circuit using growing Vec approach
/// 
/// # Arguments
/// * `stream` - The line stream to process
/// 
/// # Returns  
/// * `Ok(WireUsageReport)` - Complete wire usage analysis
/// * `Err(anyhow::Error)` - Parse error or IO error
pub fn analyze_wire_usage(stream: &mut BufferedLineStream) -> Result<WireUsageReport> {
    let mut wire_usage_counts = Vec::new();
    let mut wire_has_producer = Vec::new();
    let mut line_number = 0;
    
    // Create a spinner progress bar
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} [{elapsed_precise}] {msg}")
            .unwrap()
    );
    pb.set_message("Analyzing wire usage...");
    
    // Process each gate
    while let Some(line_result) = stream.next_line() {
        line_number += 1;
        let line = line_result?;
        
        if line.trim().is_empty() {
            bail!("Empty line at line number {}", line_number);
        }
        
        let gate = parse_gate_line(line)?;
        
        // Count input wire usage (growing vec approach)
        for input_wire in &gate.inputs {
            ensure_capacity(&mut wire_usage_counts, *input_wire);
            wire_usage_counts[*input_wire] += 1;
        }
        
        // Track which wires are produced by gates
        for output_wire in &gate.outputs {
            ensure_capacity(&mut wire_usage_counts, *output_wire);
            ensure_capacity_bool(&mut wire_has_producer, *output_wire);
            wire_has_producer[*output_wire] = true;
        }
        
        // Update spinner every 10000 lines
        if line_number % 10000 == 0 {
            pb.tick();
            pb.set_message(format!("Analyzing wire usage... {} gates processed", line_number));
        }
    }
    
    let total_wires = wire_usage_counts.len();
    
    // Classify wires
    let mut primary_input_wires = Vec::new();
    let mut primary_output_wires = Vec::new();
    let mut intermediate_count = 0;
    let mut missing_wires_count = 0;
    
    for wire_id in 0..total_wires {
        let usage_count = wire_usage_counts[wire_id];
        let has_producer = wire_id < wire_has_producer.len() && wire_has_producer[wire_id];
        
        // Missing wire: never referenced as input or output in any gate
        if usage_count == 0 && !has_producer {
            missing_wires_count += 1;
        } else if !has_producer {
            // Wire used as input but never produced -> primary input
            primary_input_wires.push(wire_id);
        } else if usage_count == 0 {
            // Wire produced but never used -> primary output  
            primary_output_wires.push(wire_id);
        } else {
            // Wire produced and used -> intermediate
            intermediate_count += 1;
        }
    }
    
    // Finish progress bar
    pb.finish_with_message(format!("✓ Analyzed {} gates, found {} wires", line_number, total_wires));
    
    Ok(WireUsageReport {
        total_wires,
        primary_inputs: primary_input_wires.len(),
        intermediate_wires: intermediate_count,
        primary_outputs: primary_output_wires.len(),
        missing_wires_count,
        wire_usage_counts,
        primary_input_wires,
        primary_output_wires,
    })
}