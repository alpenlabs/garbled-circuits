use std::collections::HashMap;
use anyhow::{Result, bail};

use crate::stream::BufferedLineStream;

/// Count gate types in a Bristol circuit file
/// 
/// Processes each line sequentially, extracting the gate type (last token)
/// and building a frequency count. Returns error for malformed lines.
/// 
/// # Arguments
/// * `stream` - The line stream to process
/// 
/// # Returns
/// * `Ok(HashMap<String, usize>)` - Gate type to count mapping
/// * `Err(anyhow::Error)` - IO error or malformed line error
/// 
/// # Example
/// ```
/// let mut stream = BufferedLineStream::new(file);
/// let counts = count_gate_types(&mut stream)?;
/// println!("XOR gates: {}", counts.get("XOR").unwrap_or(&0));
/// ```
pub fn count_gate_types(stream: &mut BufferedLineStream) -> Result<HashMap<String, usize>> {
    let mut counts = HashMap::new();
    let mut line_number = 0;

    while let Some(line_result) = stream.next_line() {
        line_number += 1;
        let line = line_result?;
        
        // Check for empty lines
        if line.trim().is_empty() {
            bail!("Empty line at line number {}", line_number);
        }
        
        // Extract gate type (last token)
        // Bristol format: "2 1 0 1 2 XOR" -> gate type is "XOR"
        let tokens: Vec<&str> = line.split_whitespace().collect();
        
        if tokens.is_empty() {
            bail!("Empty line at line number {}", line_number);
        }
        
        let gate_type = tokens.last()
            .ok_or_else(|| anyhow::anyhow!("No gate type found at line {}: '{}'", line_number, line))?;
        
        // Increment count for this gate type
        *counts.entry(gate_type.to_string()).or_insert(0) += 1;
    }

    Ok(counts)
}