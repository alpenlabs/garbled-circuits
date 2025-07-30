use anyhow::{Result, bail};
use serde::{Serialize, Deserialize};
use std::fs::File;
use std::io::{Write, BufReader, Read};
use std::path::Path;
use indicatif::{ProgressBar, ProgressStyle};

use crate::stream::BufferedLineStream;
use crate::constants::{BUFFER_SIZE, PROGRESS_UPDATE_INTERVAL};

/// Wire usage analysis results.
/// can be exported as binary for fast loading and summarized as JSON for human readable reports.
#[derive(Debug, Serialize, Deserialize, bincode::Encode, bincode::Decode)]
pub struct WireUsageReport {
    /// Total number of wires in the circuit
    pub total_wires: u32,
    /// Number of primary input wires
    pub primary_inputs: u32,
    /// Number of intermediate wires
    pub intermediate_wires: u32,
    /// Number of primary output wires
    pub primary_outputs: u32,
    /// Number of missing/unused wires (gaps in wire numbering)
    pub missing_wires_count: u32,
    /// Wire usage counts: index = wire_id, value = usage_count (capped at 255)
    /// Vec is used since our wire values are continuous and have no gaps.
    /// It is capped at 255 to save space, Wires used more than 255 times will be counted as 255.
    /// Wire used 255 times will be held in storage throughout.
    /// Analysis on actual circuit shows these are a tiny fraction of total wires.
    pub wire_usage_counts: Vec<u8>,
    /// List of primary input wire IDs
    pub primary_input_wires: Vec<u32>,
    /// List of primary output wire IDs
    pub primary_output_wires: Vec<u32>,
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
        
        let encoded = bincode::encode_to_vec(self, bincode::config::standard())?;
        
        pb.set_message("Writing binary file...");
        std::fs::write(path, encoded)?;
        
        pb.finish_with_message("✓ Binary file saved");
        Ok(())
    }
    
    /// Load a report from a binary file
    pub fn load_binary<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = File::open(path.as_ref())?;

        // Use large buffered reading for performance
        let mut reader = BufReader::with_capacity(BUFFER_SIZE, file);
        
        // Add progress indication for loading
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.green} [{elapsed_precise}] {msg}")
                .unwrap()
        );
        pb.set_message("Loading binary wire analysis data...");
        
        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer)?;
        let (report, _) = bincode::decode_from_slice(&buffer, bincode::config::standard())?;
        
        pb.finish_with_message("✓ Binary file loaded");
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
    
    /// Export wire usage count distribution as CSV
    /// Shows how many wires have usage count 0, 1, 2, etc.
    pub fn export_usage_distribution_csv<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.green} [{elapsed_precise}] {msg}")
                .unwrap()
        );
        pb.set_message("Computing wire usage distribution...");
        
        // Count frequency of each usage count
        let mut usage_distribution: std::collections::HashMap<u8, usize> = std::collections::HashMap::new();
        
        for &usage_count in &self.wire_usage_counts {
            *usage_distribution.entry(usage_count).or_insert(0) += 1;
        }
        
        pb.set_message("Writing distribution CSV...");
        
        // Write CSV file
        let mut file = File::create(path)?;
        writeln!(file, "usage_count,wire_count")?;
        
        // Sort by usage count for consistent output
        let mut sorted_distribution: Vec<_> = usage_distribution.into_iter().collect();
        sorted_distribution.sort_by_key(|&(usage_count, _)| usage_count);
        
        for (usage_count, wire_count) in sorted_distribution {
            writeln!(file, "{},{}", usage_count, wire_count)?;
        }
        
        pb.finish_with_message("✓ Usage distribution CSV saved");
        Ok(())
    }
}


/// Analyze wire usage patterns in a Bristol circuit with header format
/// 
/// Expected format:
/// First line: `<num_gates> <num_wires>`
/// Followed by gate lines in Bristol format
/// 
/// # Arguments
/// * `stream` - The line stream to process
/// 
/// # Returns  
/// * `Ok(WireUsageReport)` - Complete wire usage analysis
/// * `Err(anyhow::Error)` - Parse error or IO error
pub fn analyze_wire_usage(stream: &mut BufferedLineStream) -> Result<WireUsageReport> {
    // Parse the header line
    let header_line = stream.next_line()
        .ok_or_else(|| anyhow::anyhow!("Missing header line"))??;
    
    let header_tokens: Vec<&str> = header_line.split_whitespace().collect();
    if header_tokens.len() != 2 {
        bail!("Invalid header: expected '<num_gates> <num_wires>', got: '{}'", header_line);
    }
    
    let num_gates: u32 = header_tokens[0].parse()
        .map_err(|_| anyhow::anyhow!("Invalid num_gates: '{}'", header_tokens[0]))?;
    let num_wires: u32 = header_tokens[1].parse()
        .map_err(|_| anyhow::anyhow!("Invalid num_wires: '{}'", header_tokens[1]))?;
    
    // Pre-allocate vectors with exact size needed
    let mut wire_usage_counts = vec![0u8; num_wires as usize];
    let mut wire_has_producer = vec![false; num_wires as usize];
    let mut line_number = 1; // Already processed header
    let mut gates_processed: u32 = 0; // Track actual gates processed
    
    // Create a progress bar with known total gates
    let pb = ProgressBar::new(num_gates as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{bar:40.green/blue} {pos}/{len} gates [{elapsed_precise}<{eta_precise}] {msg}")
            .unwrap()
            .progress_chars("#>-")
    );
    pb.set_message("Analyzing wire usage");
    
    // Process each gate
    while let Some(line_result) = stream.next_line() {
        line_number += 1;
        let line = line_result?;
        
        if line.trim().is_empty() {
            bail!("Empty line at line number {}", line_number);
        }
        
        // Parse gate line directly using iterator (more efficient)
        let mut tokens = line.split_whitespace();
        
        // Parse num_inputs and num_outputs
        let num_inputs: u32 = tokens.next()
            .ok_or_else(|| anyhow::anyhow!("Missing num_inputs at line {}", line_number))?
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid num_inputs at line {}: '{}'", line_number, line))?;
            
        let num_outputs: u32 = tokens.next()
            .ok_or_else(|| anyhow::anyhow!("Missing num_outputs at line {}", line_number))?
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid num_outputs at line {}: '{}'", line_number, line))?;
        
        // Process input wires directly (no intermediate allocation)
        for i in 0..num_inputs {
            let wire_id: u32 = tokens.next()
                .ok_or_else(|| anyhow::anyhow!("Missing input wire {} at line {}", i, line_number))?
                .parse()
                .map_err(|_| anyhow::anyhow!("Invalid input wire ID at line {}: '{}'", line_number, line))?;
                
            if wire_id >= num_wires {
                bail!("Invalid input wire ID {} exceeds num_wires {} at line {}", wire_id, num_wires, line_number);
            }
            wire_usage_counts[wire_id as usize] = wire_usage_counts[wire_id as usize].saturating_add(1);
        }
        
        // Process output wires directly (no intermediate allocation)
        for i in 0..num_outputs {
            let wire_id: u32 = tokens.next()
                .ok_or_else(|| anyhow::anyhow!("Missing output wire {} at line {}", i, line_number))?
                .parse()
                .map_err(|_| anyhow::anyhow!("Invalid output wire ID at line {}: '{}'", line_number, line))?;
                
            if wire_id >= num_wires {
                bail!("Invalid output wire ID {} exceeds num_wires {} at line {}", wire_id, num_wires, line_number);
            }
            wire_has_producer[wire_id as usize] = true;
        }
        
        // Validate we have the gate type token (but don't need to parse it)
        if tokens.next().is_none() {
            bail!("Missing gate type at line {}: '{}'", line_number, line);
        }
        
        // Validate no extra tokens
        if tokens.next().is_some() {
            bail!("Too many tokens at line {}: '{}'", line_number, line);
        }
        
        gates_processed += 1;
        
        // Update progress bar periodically for better performance
        if gates_processed % PROGRESS_UPDATE_INTERVAL == 0 {
            pb.set_position(gates_processed as u64);
        }
    }
    
    // Classify wires
    let mut primary_input_wires: Vec<u32> = Vec::new();
    let mut primary_output_wires: Vec<u32> = Vec::new();
    let mut intermediate_count: u32 = 0;
    let mut missing_wires_count: u32 = 0;
    
    for wire_id in 0..num_wires {
        let usage_count = wire_usage_counts[wire_id as usize];
        let has_producer = wire_has_producer[wire_id as usize];
        
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
    
    // Finish progress bar with final position
    pb.set_position(gates_processed as u64);
    pb.finish_with_message(format!("✓ Analyzed {} gates, found {} wires", gates_processed, num_wires));
    
    // Validate that we processed the expected number of gates
    if gates_processed != num_gates {
        eprintln!("Warning: Expected {} gates but processed {}", num_gates, gates_processed);
    }
    
    Ok(WireUsageReport {
        total_wires: num_wires,
        primary_inputs: primary_input_wires.len() as u32,
        intermediate_wires: intermediate_count,
        primary_outputs: primary_output_wires.len() as u32,
        missing_wires_count,
        wire_usage_counts,
        primary_input_wires,
        primary_output_wires,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::fs::File;

    fn create_test_file(content: &str) -> Result<tempfile::NamedTempFile> {
        let mut temp_file = tempfile::NamedTempFile::new()?;
        temp_file.write_all(content.as_bytes())?;
        temp_file.flush()?;
        Ok(temp_file)
    }

    #[test]
    fn test_analyze_wire_usage_basic() -> Result<()> {
        let circuit_data = "3 6\n2 1 0 1 2 XOR\n2 1 2 3 4 AND\n2 1 3 4 5 XOR\n";
        let temp_file = create_test_file(circuit_data)?;
        let file = File::open(temp_file.path())?;
        let mut stream = BufferedLineStream::new(file);
        
        let report = analyze_wire_usage(&mut stream)?;
        
        assert_eq!(report.total_wires, 6);
        assert_eq!(report.primary_inputs, 3);  // wires 0, 1, 3
        assert_eq!(report.intermediate_wires, 2);  // wires 2, 4
        assert_eq!(report.primary_outputs, 1);  // wire 5
        assert_eq!(report.missing_wires_count, 0);
        assert_eq!(report.primary_input_wires, vec![0, 1, 3]);
        assert_eq!(report.primary_output_wires, vec![5]);
        assert_eq!(report.wire_usage_counts.len(), 6);
        
        Ok(())
    }

    #[test]
    fn test_analyze_wire_usage_single_gate() -> Result<()> {
        let circuit_data = "1 3\n2 1 0 1 2 XOR\n";
        let temp_file = create_test_file(circuit_data)?;
        let file = File::open(temp_file.path())?;
        let mut stream = BufferedLineStream::new(file);
        
        let report = analyze_wire_usage(&mut stream)?;
        
        assert_eq!(report.total_wires, 3);
        assert_eq!(report.primary_inputs, 2);  // wires 0, 1
        assert_eq!(report.intermediate_wires, 0);
        assert_eq!(report.primary_outputs, 1);  // wire 2
        assert_eq!(report.missing_wires_count, 0);
        assert_eq!(report.primary_input_wires, vec![0, 1]);
        assert_eq!(report.primary_output_wires, vec![2]);
        
        Ok(())
    }

    #[test]
    fn test_analyze_wire_usage_empty_circuit() -> Result<()> {
        let circuit_data = "0 0\n";
        let temp_file = create_test_file(circuit_data)?;
        let file = File::open(temp_file.path())?;
        let mut stream = BufferedLineStream::new(file);
        
        let report = analyze_wire_usage(&mut stream)?;
        
        assert_eq!(report.total_wires, 0);
        assert_eq!(report.primary_inputs, 0);
        assert_eq!(report.intermediate_wires, 0);
        assert_eq!(report.primary_outputs, 0);
        assert_eq!(report.missing_wires_count, 0);
        assert_eq!(report.wire_usage_counts.len(), 0);
        
        Ok(())
    }

    #[test]
    fn test_analyze_wire_usage_with_missing_wires() -> Result<()> {
        // Circuit declares 10 wires but only uses some of them
        let circuit_data = "2 10\n2 1 0 1 2 XOR\n2 1 5 6 7 AND\n";
        let temp_file = create_test_file(circuit_data)?;
        let file = File::open(temp_file.path())?;
        let mut stream = BufferedLineStream::new(file);
        
        let report = analyze_wire_usage(&mut stream)?;
        
        assert_eq!(report.total_wires, 10);
        assert_eq!(report.primary_inputs, 4);  // wires 0, 1, 5, 6
        assert_eq!(report.intermediate_wires, 0);
        assert_eq!(report.primary_outputs, 2);  // wires 2, 7
        assert_eq!(report.missing_wires_count, 4);  // wires 3, 4, 8, 9 never referenced
        
        Ok(())
    }

    #[test]
    fn test_analyze_wire_usage_invalid_header() {
        let circuit_data = "invalid header\n2 1 0 1 2 XOR\n";
        let temp_file = create_test_file(circuit_data).unwrap();
        let file = File::open(temp_file.path()).unwrap();
        let mut stream = BufferedLineStream::new(file);
        
        let result = analyze_wire_usage(&mut stream);
        
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Invalid num_gates: 'invalid'"));
    }

    #[test]
    fn test_analyze_wire_usage_missing_header() {
        let circuit_data = "";
        let temp_file = create_test_file(circuit_data).unwrap();
        let file = File::open(temp_file.path()).unwrap();
        let mut stream = BufferedLineStream::new(file);
        
        let result = analyze_wire_usage(&mut stream);
        
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Missing header line"));
    }

    #[test]
    fn test_analyze_wire_usage_invalid_wire_id() {
        // Wire ID 10 exceeds num_wires=5
        let circuit_data = "1 5\n2 1 0 10 2 XOR\n";
        let temp_file = create_test_file(circuit_data).unwrap();
        let file = File::open(temp_file.path()).unwrap();
        let mut stream = BufferedLineStream::new(file);
        
        let result = analyze_wire_usage(&mut stream);
        
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Invalid input wire ID 10 exceeds num_wires 5"));
    }

    #[test]
    fn test_analyze_wire_usage_empty_line_error() {
        let circuit_data = "2 5\n2 1 0 1 2 XOR\n\n2 1 2 3 4 AND\n";
        let temp_file = create_test_file(circuit_data).unwrap();
        let file = File::open(temp_file.path()).unwrap();
        let mut stream = BufferedLineStream::new(file);
        
        let result = analyze_wire_usage(&mut stream);
        
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Empty line at line number 3"));
    }

    #[test]
    fn test_analyze_wire_usage_malformed_gate() {
        let circuit_data = "1 3\ninvalid gate line\n";
        let temp_file = create_test_file(circuit_data).unwrap();
        let file = File::open(temp_file.path()).unwrap();
        let mut stream = BufferedLineStream::new(file);
        
        let result = analyze_wire_usage(&mut stream);
        
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Invalid num_inputs at line 2"));
    }

    #[test]
    fn test_analyze_wire_usage_usage_count_saturation() -> Result<()> {
        // Create a circuit where one wire is used many times to test saturation at 255
        let mut circuit_data = String::from("256 3\n");

        // Add 256 gates that all use wire 0 as input, output to wire 1 or 2 alternately
        for i in 0..256 {
            let output_wire = if i % 2 == 0 { 1 } else { 2 };
            circuit_data.push_str(&format!("1 1 0 {} NOT\n", output_wire));
        }
        
        let temp_file = create_test_file(&circuit_data)?;
        let file = File::open(temp_file.path())?;
        let mut stream = BufferedLineStream::new(file);
        
        let report = analyze_wire_usage(&mut stream)?;
        
        assert_eq!(report.total_wires, 3);
        assert_eq!(report.primary_inputs, 1);  // wire 0
        assert_eq!(report.primary_outputs, 2);  // wires 1, 2
        
        // Wire 0 usage should be saturated at 255 (u8::MAX)
        assert_eq!(report.wire_usage_counts[0], 255);
        
        Ok(())
    }

    #[test]
    fn test_wire_usage_report_export_functions() -> Result<()> {
        let circuit_data = "2 5\n2 1 0 1 2 XOR\n2 1 2 3 4 AND\n";
        let temp_file = create_test_file(circuit_data)?;
        let file = File::open(temp_file.path())?;
        let mut stream = BufferedLineStream::new(file);
        
        let report = analyze_wire_usage(&mut stream)?;
        
        // Test JSON export
        let json_file = tempfile::NamedTempFile::new()?;
        report.export_summary_json(json_file.path())?;
        
        // Test CSV export  
        let csv_file = tempfile::NamedTempFile::new()?;
        report.export_usage_distribution_csv(csv_file.path())?;
        
        // Test binary save/load
        let binary_file = tempfile::NamedTempFile::new()?;
        report.save_binary(binary_file.path())?;
        let loaded_report = WireUsageReport::load_binary(binary_file.path())?;
        
        // Verify loaded report matches original
        assert_eq!(loaded_report.total_wires, report.total_wires);
        assert_eq!(loaded_report.primary_inputs, report.primary_inputs);
        assert_eq!(loaded_report.wire_usage_counts, report.wire_usage_counts);
        
        Ok(())
    }
}