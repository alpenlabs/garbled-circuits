use std::collections::HashMap;
use anyhow::{Result, bail};
use indicatif::{ProgressBar, ProgressStyle};

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
/// 
/// # Panics
/// If the stream contains an empty line or a line without a gate type, fails with an error.
/// 
/// # Note 
/// This function doesn't enforce any allowed set of gate types,
/// and will count any string which is at the end of a gate line as a gate type.
pub fn count_gate_types(stream: &mut BufferedLineStream) -> Result<HashMap<String, usize>> {
    let mut counts = HashMap::new();
    let mut line_number: u64 = 0;
    
    // Create a spinner progress bar
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} [{elapsed_precise}] {msg}")
            .unwrap()
    );
    pb.set_message("Counting gate types...");

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
        
        // Update spinner every 10000 lines
        if line_number % 10000 == 0 {
            pb.tick();
            pb.set_message(format!("Counting gate types... {} processed", line_number));
        }
    }
    
    // Finish progress bar
    pb.finish_with_message(format!("✓ Processed {} gates", line_number));

    Ok(counts)
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
    fn test_count_gate_types_basic() -> Result<()> {
        let circuit_data = "2 1 0 1 2 XOR\n2 1 3 4 5 AND\n2 1 6 7 8 XOR\n";
        let temp_file = create_test_file(circuit_data)?;
        let file = File::open(temp_file.path())?;
        let mut stream = BufferedLineStream::new(file);
        
        let counts = count_gate_types(&mut stream)?;
        
        assert_eq!(counts.get("XOR"), Some(&2));
        assert_eq!(counts.get("AND"), Some(&1));
        assert_eq!(counts.len(), 2);
        
        Ok(())
    }

    #[test]
    fn test_count_gate_types_single_gate() -> Result<()> {
        let circuit_data = "2 1 0 1 2 NAND\n";
        let temp_file = create_test_file(circuit_data)?;
        let file = File::open(temp_file.path())?;
        let mut stream = BufferedLineStream::new(file);
        
        let counts = count_gate_types(&mut stream)?;
        
        assert_eq!(counts.get("NAND"), Some(&1));
        assert_eq!(counts.len(), 1);
        
        Ok(())
    }

    #[test]
    fn test_count_gate_types_multiple_same_gates() -> Result<()> {
        let circuit_data = "2 1 0 1 2 OR\n2 1 3 4 5 OR\n2 1 6 7 8 OR\n2 1 9 10 11 OR\n";
        let temp_file = create_test_file(circuit_data)?;
        let file = File::open(temp_file.path())?;
        let mut stream = BufferedLineStream::new(file);
        
        let counts = count_gate_types(&mut stream)?;
        
        assert_eq!(counts.get("OR"), Some(&4));
        assert_eq!(counts.len(), 1);
        
        Ok(())
    }

    #[test]
    fn test_count_gate_types_empty_file() -> Result<()> {
        let circuit_data = "";
        let temp_file = create_test_file(circuit_data)?;
        let file = File::open(temp_file.path())?;
        let mut stream = BufferedLineStream::new(file);
        
        let counts = count_gate_types(&mut stream)?;
        
        assert_eq!(counts.len(), 0);
        
        Ok(())
    }

    #[test]
    fn test_count_gate_types_empty_line_error() {
        let circuit_data = "2 1 0 1 2 XOR\n\n2 1 3 4 5 AND\n";
        let temp_file = create_test_file(circuit_data).unwrap();
        let file = File::open(temp_file.path()).unwrap();
        let mut stream = BufferedLineStream::new(file);
        
        let result = count_gate_types(&mut stream);
        
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Empty line at line number 2"));
    }

    #[test]
    fn test_count_gate_types_whitespace_only_line_error() {
        let circuit_data = "2 1 0 1 2 XOR\n   \t  \n2 1 3 4 5 AND\n";
        let temp_file = create_test_file(circuit_data).unwrap();
        let file = File::open(temp_file.path()).unwrap();
        let mut stream = BufferedLineStream::new(file);
        
        let result = count_gate_types(&mut stream);
        
        assert!(result.is_err());
        let error_msg = result.unwrap_err().to_string();
        assert!(error_msg.contains("Empty line at line number 2"));
    }

    #[test]
    fn test_count_gate_types_various_gate_types() -> Result<()> {
        let circuit_data = concat!(
            "2 1 0 1 2 XOR\n",
            "2 1 3 4 5 AND\n", 
            "2 1 6 7 8 OR\n",
            "2 1 9 10 11 NAND\n",
            "2 1 12 13 14 NOR\n",
            "1 1 15 16 NOT\n",
            "2 1 17 18 19 XOR\n"
        );
        let temp_file = create_test_file(circuit_data)?;
        let file = File::open(temp_file.path())?;
        let mut stream = BufferedLineStream::new(file);
        
        let counts = count_gate_types(&mut stream)?;
        
        assert_eq!(counts.get("XOR"), Some(&2));
        assert_eq!(counts.get("AND"), Some(&1));
        assert_eq!(counts.get("OR"), Some(&1));
        assert_eq!(counts.get("NAND"), Some(&1));
        assert_eq!(counts.get("NOR"), Some(&1));
        assert_eq!(counts.get("NOT"), Some(&1));
        assert_eq!(counts.len(), 6);
        
        Ok(())
    }
}