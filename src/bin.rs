use crate::stream::BufferedLineStream;
use anyhow::{Result, bail};
use indicatif::{ProgressBar, ProgressStyle};
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::Path;
use zstd::{Decoder, Encoder};

/// Individual gate representation (12 bytes, little endian)
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct CompactGate {
    pub input1: u32, // 4 bytes
    pub input2: u32, // 4 bytes
    pub output: u32, // 4 bytes
}

impl CompactGate {
    /// Convert to little endian bytes
    pub fn to_bytes(&self) -> [u8; 12] {
        let mut bytes = [0u8; 12];
        bytes[0..4].copy_from_slice(&self.input1.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.input2.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.output.to_le_bytes());
        bytes
    }

    /// Create from little endian bytes
    pub fn from_bytes(bytes: &[u8; 12]) -> Self {
        let input1 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let input2 = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let output = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);

        Self {
            input1,
            input2,
            output,
        }
    }
}

/// Batch of 8 gates with their types (97 bytes total)
#[derive(Debug)]
pub struct GateBatch {
    /// Up to 8 gates (96 bytes)
    pub gates: [CompactGate; 8],
    /// Gate types packed in 1 byte: bit 0=gate0, bit 1=gate1, etc.
    /// 0 = XOR, 1 = AND
    pub gate_types: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateType {
    XOR,
    AND,
}

impl GateBatch {
    /// Create a new empty batch
    pub fn new() -> Self {
        Self {
            gates: [CompactGate {
                input1: 0,
                input2: 0,
                output: 0,
            }; 8],
            gate_types: 0,
        }
    }

    /// Set gate at given index (0-7)
    pub fn set_gate(&mut self, index: usize, gate: CompactGate, gate_type: GateType) {
        assert!(index < 8, "Gate index must be 0-7");
        self.gates[index] = gate;

        match gate_type {
            GateType::XOR => self.gate_types &= !(1 << index),
            GateType::AND => self.gate_types |= 1 << index,
        }
    }

    /// Get gate type at given index
    pub fn gate_type(&self, index: usize) -> GateType {
        assert!(index < 8, "Gate index must be 0-7");
        if (self.gate_types >> index) & 1 == 1 {
            GateType::AND
        } else {
            GateType::XOR
        }
    }

    /// Get gate at given index with its type
    pub fn get_gate(&self, index: usize) -> (CompactGate, GateType) {
        assert!(index < 8, "Gate index must be 0-7");
        (self.gates[index], self.gate_type(index))
    }

    /// Get the number of valid gates in this batch
    pub fn gate_count(&self) -> usize {
        // Find the last gate that has non-zero output (assuming gates are added sequentially)
        for i in (0..8).rev() {
            if self.gates[i].output != 0 || self.gates[i].input1 != 0 || self.gates[i].input2 != 0 {
                return i + 1;
            }
        }
        1 // At least one gate if we have a batch
    }

    /// Get the number of valid gates in this batch with expected count
    pub fn gate_count_with_expected(&self, expected: usize) -> usize {
        std::cmp::min(expected, 8)
    }

    /// Convert batch to 97 bytes in little endian format
    pub fn to_bytes(&self) -> [u8; 97] {
        let mut bytes = [0u8; 97];

        // Write 8 gates (96 bytes)
        for i in 0..8 {
            let gate_bytes = self.gates[i].to_bytes();
            let start = i * 12;
            bytes[start..start + 12].copy_from_slice(&gate_bytes);
        }

        // Write gate types (1 byte)
        bytes[96] = self.gate_types;

        bytes
    }

    /// Create batch from 97 bytes in little endian format
    pub fn from_bytes(bytes: &[u8; 97]) -> Self {
        let mut gates = [CompactGate {
            input1: 0,
            input2: 0,
            output: 0,
        }; 8];

        // Read 8 gates (96 bytes)
        for i in 0..8 {
            let start = i * 12;
            let gate_bytes: [u8; 12] = bytes[start..start + 12].try_into().unwrap();
            gates[i] = CompactGate::from_bytes(&gate_bytes);
        }

        // Read gate types (1 byte)
        let gate_types = bytes[96];

        Self { gates, gate_types }
    }
}

/// Compressed Binary Circuit Writer using zstd compression
pub struct CompressedBinaryCircuitWriter {
    file: Option<File>,
    encoder: Option<Encoder<'static, File>>,
    current_batch: GateBatch,
    gates_in_batch: usize,
    total_gates_written: usize,
    header_written: bool,
}

impl CompressedBinaryCircuitWriter {
    /// Create a new compressed writer
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = File::create(path)?;

        Ok(Self {
            file: Some(file),
            encoder: None,
            current_batch: GateBatch::new(),
            gates_in_batch: 0,
            total_gates_written: 0,
            header_written: false,
        })
    }

    /// Write a single gate
    pub fn write_gate(
        &mut self,
        input1: u32,
        input2: u32,
        output: u32,
        gate_type: GateType,
    ) -> Result<()> {
        let gate = CompactGate {
            input1,
            input2,
            output,
        };
        self.current_batch
            .set_gate(self.gates_in_batch, gate, gate_type);
        self.gates_in_batch += 1;
        self.total_gates_written += 1;

        // If batch is full, flush it
        if self.gates_in_batch == 8 {
            self.flush_batch()?;
        }

        Ok(())
    }

    /// Write the header with total gate count
    pub fn write_header(&mut self, total_gates: u32) -> Result<()> {
        if !self.header_written {
            if let Some(mut file) = self.file.take() {
                // Write header uncompressed
                file.write_all(&total_gates.to_le_bytes())?;
                file.flush()?;

                // Now create the encoder for compressed data
                self.encoder = Some(Encoder::new(file, 3)?);
            }
            self.header_written = true;
        }
        Ok(())
    }

    /// Flush current batch to file
    fn flush_batch(&mut self) -> Result<()> {
        if self.gates_in_batch > 0 {
            if let Some(encoder) = &mut self.encoder {
                // Write exactly 97 bytes
                let batch_bytes = self.current_batch.to_bytes();
                encoder.write_all(&batch_bytes)?;

                // Reset batch
                self.current_batch = GateBatch::new();
                self.gates_in_batch = 0;
            }
        }
        Ok(())
    }

    /// Finish writing and close file
    pub fn finish(mut self, total_gates: u32) -> Result<usize> {
        // Write header first if not already written
        self.write_header(total_gates)?;
        // Flush any remaining gates
        self.flush_batch()?;
        if let Some(encoder) = self.encoder {
            encoder.finish()?;
        }
        Ok(self.total_gates_written)
    }

    /// Finish writing without writing header (header already written)
    pub fn finish_without_header(mut self) -> Result<usize> {
        // Flush any remaining gates
        self.flush_batch()?;
        if let Some(encoder) = self.encoder {
            encoder.finish()?;
        }
        Ok(self.total_gates_written)
    }
}

/// Compressed Binary Circuit Reader using zstd decompression
pub struct CompressedBinaryCircuitReader {
    file: Option<File>,
    decoder: Option<Decoder<'static, BufReader<File>>>,
    buffer: Vec<u8>,
    buffer_position: usize,
    buffer_valid_bytes: usize,
    current_batch: Option<GateBatch>,
    current_gate_index: usize,
    total_gates_read: usize,
    total_gates_expected: u32,
    header_read: bool,
}

impl CompressedBinaryCircuitReader {
    /// Create a new compressed reader
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = File::open(path)?;

        // Buffer size: 20000 batches * 97 bytes = 1,940,000 bytes (~1.85MB)
        // This reduces syscalls dramatically while staying reasonable for memory
        const BATCHES_PER_READ: usize = 20000;
        const BUFFER_SIZE: usize = BATCHES_PER_READ * 97;

        Ok(Self {
            file: Some(file),
            decoder: None,
            buffer: vec![0u8; BUFFER_SIZE],
            buffer_position: 0,
            buffer_valid_bytes: 0,
            current_batch: None,
            current_gate_index: 0,
            total_gates_read: 0,
            total_gates_expected: 0,
            header_read: false,
        })
    }

    /// Read the header with total gate count
    pub fn read_header(&mut self) -> Result<()> {
        if !self.header_read {
            if let Some(mut file) = self.file.take() {
                // Read header uncompressed
                let mut header_bytes = [0u8; 4];
                file.read_exact(&mut header_bytes)?;
                self.total_gates_expected = u32::from_le_bytes(header_bytes);

                // Now create decoder for compressed data
                self.decoder = Some(Decoder::new(file)?);
            }
            self.header_read = true;
        }
        Ok(())
    }

    /// Read next gate from stream
    pub fn next_gate(&mut self) -> Result<Option<(CompactGate, GateType)>> {
        // Read header if not already read
        if !self.header_read {
            self.read_header()?;
        }

        // Check if we've read all expected gates
        if self.total_gates_read >= self.total_gates_expected as usize {
            return Ok(None);
        }

        // Calculate remaining gates needed
        let remaining_gates = self.total_gates_expected as usize - self.total_gates_read;

        // If we need a new batch
        if self.current_batch.is_none() {
            if !self.load_next_batch()? {
                return Ok(None); // End of file
            }
        } else {
            // Check if current batch is exhausted
            let current_batch_gate_count = self.get_current_batch_gate_count(remaining_gates);

            if self.current_gate_index >= current_batch_gate_count {
                if !self.load_next_batch()? {
                    return Ok(None); // End of file
                }
            }
        }

        if let Some(batch) = &self.current_batch {
            let (gate, gate_type) = batch.get_gate(self.current_gate_index);

            self.current_gate_index += 1;
            self.total_gates_read += 1;
            Ok(Some((gate, gate_type)))
        } else {
            Ok(None)
        }
    }

    /// Load next batch from file
    fn load_next_batch(&mut self) -> Result<bool> {
        // Check if we need to refill the buffer
        if self.buffer_position + 97 > self.buffer_valid_bytes {
            // Move any remaining bytes to the start of buffer
            if self.buffer_position < self.buffer_valid_bytes {
                let remaining = self.buffer_valid_bytes - self.buffer_position;
                self.buffer
                    .copy_within(self.buffer_position..self.buffer_valid_bytes, 0);
                self.buffer_valid_bytes = remaining;
            } else {
                self.buffer_valid_bytes = 0;
            }
            self.buffer_position = 0;

            // Fill the rest of the buffer
            let _bytes_to_read = self.buffer.len() - self.buffer_valid_bytes;
            if let Some(decoder) = &mut self.decoder {
                match decoder.read(&mut self.buffer[self.buffer_valid_bytes..]) {
                    Ok(0) => {
                        // EOF - check if we have a complete batch remaining
                        if self.buffer_valid_bytes >= 97 {
                            // We have at least one complete batch
                        } else {
                            return Ok(false); // No more complete batches
                        }
                    }
                    Ok(bytes_read) => {
                        self.buffer_valid_bytes += bytes_read;
                    }
                    Err(e) => {
                        bail!("Failed to read from file: {}", e);
                    }
                }
            } else {
                return Ok(false); // No decoder available
            }
        }

        // Check if we have a complete batch available
        if self.buffer_position + 97 <= self.buffer_valid_bytes {
            let batch_bytes: [u8; 97] = self.buffer
                [self.buffer_position..self.buffer_position + 97]
                .try_into()
                .unwrap();

            let batch = GateBatch::from_bytes(&batch_bytes);
            self.current_batch = Some(batch);
            self.current_gate_index = 0;
            self.buffer_position += 97;
            Ok(true)
        } else {
            // Not enough bytes for a complete batch
            Ok(false)
        }
    }

    /// Get the gate count for the current batch considering expected gates
    fn get_current_batch_gate_count(&self, _remaining_gates: usize) -> usize {
        if let Some(_batch) = &self.current_batch {
            // Calculate which batch we're in based on total gates read
            let batch_index = self.total_gates_read / 8;
            let gates_before_this_batch = batch_index * 8;
            let gates_remaining_for_all_batches =
                self.total_gates_expected as usize - gates_before_this_batch;

            let count = if gates_remaining_for_all_batches <= 8 {
                // This is the last batch, it may have fewer than 8 gates
                gates_remaining_for_all_batches
            } else {
                // Regular batch, should have 8 gates
                8
            };

            count
        } else {
            0
        }
    }

    /// Get total gates read so far
    pub fn gates_read(&self) -> usize {
        self.total_gates_read
    }

    /// Get total gates expected from header
    pub fn total_gates_expected(&self) -> u32 {
        self.total_gates_expected
    }
}

/// Format a number with underscores for readability
fn format_number(n: usize) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push('_');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}

/// Parse a Bristol format gate line
fn parse_bristol_gate_line(line: &str) -> Result<(u32, u32, u32, GateType)> {
    let tokens: Vec<&str> = line.split_whitespace().collect();

    if tokens.len() != 6 {
        bail!(
            "Invalid Bristol gate line: expected 6 tokens, got {}: '{}'",
            tokens.len(),
            line
        );
    }

    // Parse format: "2 1 input1 input2 output GATE_TYPE"
    let num_inputs: usize = tokens[0]
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid number of inputs: '{}'", tokens[0]))?;
    let num_outputs: usize = tokens[1]
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid number of outputs: '{}'", tokens[1]))?;

    if num_inputs != 2 || num_outputs != 1 {
        bail!(
            "Only 2-input, 1-output gates supported, got {}-input, {}-output",
            num_inputs,
            num_outputs
        );
    }

    let input1: u32 = tokens[2]
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid input1 wire ID: '{}'", tokens[2]))?;
    let input2: u32 = tokens[3]
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid input2 wire ID: '{}'", tokens[3]))?;
    let output: u32 = tokens[4]
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid output wire ID: '{}'", tokens[4]))?;

    let gate_type = tokens[5];
    let gate_type = match gate_type {
        "XOR" => GateType::XOR,
        "AND" => GateType::AND,
        _ => bail!(
            "Unsupported gate type: '{}'. Only XOR and AND are supported.",
            gate_type
        ),
    };

    Ok((input1, input2, output, gate_type))
}

/// Convert Bristol format to compressed binary format using zstd compression
pub fn convert_bristol_to_compressed_binary<P: AsRef<Path>>(
    bristol_path: P,
    binary_path: P,
) -> Result<ConversionStats> {
    // Single pass: write with placeholder header, then update
    let bristol_file = File::open(&bristol_path)?;
    let mut bristol_stream = BufferedLineStream::new(bristol_file);

    let mut binary_writer = CompressedBinaryCircuitWriter::new(&binary_path)?;

    // Write placeholder header (will update at end)
    binary_writer.write_header(0)?;

    // Progress tracking with spinner
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} [{elapsed_precise}] {msg}")
            .unwrap(),
    );
    pb.set_message("Converting Bristol to compressed binary...");

    let start_time = std::time::Instant::now();

    let mut stats = ConversionStats::new();
    let mut _line_number = 0;

    while let Some(line_result) = bristol_stream.next_line() {
        _line_number += 1;
        let line = line_result?;

        // Skip empty lines
        if line.trim().is_empty() {
            continue;
        }

        // Parse Bristol gate
        let (input1, input2, output, gate_type) = parse_bristol_gate_line(&line)?;

        // Write to compressed binary format
        binary_writer.write_gate(input1, input2, output, gate_type)?;

        // Update stats
        match gate_type {
            GateType::AND => stats.and_gates += 1,
            GateType::XOR => stats.xor_gates += 1,
        }
        stats.total_gates += 1;

        // Progress update
        if stats.total_gates % 1_000_000 == 0 {
            let elapsed = start_time.elapsed().as_secs_f64();
            let rate = if elapsed > 0.0 {
                format!(
                    "{}/s",
                    format_number((stats.total_gates as f64 / elapsed) as usize)
                )
            } else {
                "calculating...".to_string()
            };
            pb.set_message(format!(
                "Converted {} gates ({} XOR, {} AND) [{}]",
                format_number(stats.total_gates),
                format_number(stats.xor_gates),
                format_number(stats.and_gates),
                rate
            ));
        }
    }

    // Finish writing (no header needed since already written)
    let gates_written = binary_writer.finish_without_header()?;

    // Update header with actual gate count
    let mut file = std::fs::OpenOptions::new().write(true).open(&binary_path)?;
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&(gates_written as u32).to_le_bytes())?;

    let elapsed = start_time.elapsed().as_secs_f64();
    let final_rate = if elapsed > 0.0 {
        format!(
            "[{}/s]",
            format_number((gates_written as f64 / elapsed) as usize)
        )
    } else {
        "".to_string()
    };
    pb.finish_with_message(format!(
        "✓ Converted {} gates to compressed binary format ({} XOR, {} AND) {}",
        format_number(gates_written),
        format_number(stats.xor_gates),
        format_number(stats.and_gates),
        final_rate
    ));

    // Calculate file sizes
    let bristol_size = std::fs::metadata(&bristol_path)?.len();
    let binary_size = std::fs::metadata(&binary_path)?.len();

    stats.bristol_file_size = bristol_size;
    stats.binary_file_size = binary_size;
    stats.compression_ratio = bristol_size as f64 / binary_size as f64;

    Ok(stats)
}

/// Verify compressed binary format circuit file and show statistics
pub fn verify_compressed_binary_circuit<P: AsRef<Path>>(
    binary_path: P,
) -> Result<VerificationStats> {
    let mut reader = CompressedBinaryCircuitReader::new(&binary_path)?;

    // Read header to get total count for progress bar
    reader.read_header()?;
    let total_gates = reader.total_gates_expected();

    // Progress tracking with known total
    let pb = ProgressBar::new(total_gates as u64);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{bar:40.cyan/blue} {pos:>7}/{len:7} [{elapsed_precise}] {msg} [{per_sec}]")
            .unwrap(),
    );
    pb.set_message("Verifying compressed binary circuit...");

    let mut stats = VerificationStats::new();

    while let Some((_gate, gate_type)) = reader.next_gate()? {
        match gate_type {
            GateType::AND => stats.and_gates += 1,
            GateType::XOR => stats.xor_gates += 1,
        }
        stats.total_gates += 1;

        // Progress update
        if stats.total_gates % 1_000_000 == 0 {
            pb.set_position(stats.total_gates as u64);
            pb.set_message(format!(
                "Verified {} gates ({} XOR, {} AND)",
                format_number(stats.total_gates),
                format_number(stats.xor_gates),
                format_number(stats.and_gates)
            ));
        }
    }

    pb.set_position(stats.total_gates as u64);
    pb.finish_with_message(format!(
        "✓ Verified {} gates ({} XOR, {} AND)",
        format_number(stats.total_gates),
        format_number(stats.xor_gates),
        format_number(stats.and_gates)
    ));

    // Calculate file size
    stats.file_size = std::fs::metadata(&binary_path)?.len();

    Ok(stats)
}

pub fn verify_bristol_circuit<P: AsRef<Path>>(bristol_path: P) -> Result<VerificationStats> {
    let bristol_file = File::open(&bristol_path)?;
    let mut bristol_stream = BufferedLineStream::new(bristol_file);

    // Progress tracking with spinner
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} [{elapsed_precise}] {msg}")
            .unwrap(),
    );
    pb.set_message("Verifying Bristol circuit...");

    let start_time = std::time::Instant::now();
    let mut stats = VerificationStats::new();

    while let Some(line_result) = bristol_stream.next_line() {
        let line = line_result?;

        // Skip empty lines
        if line.trim().is_empty() {
            continue;
        }

        // Parse Bristol gate
        let (_input1, _input2, _output, gate_type) = parse_bristol_gate_line(&line)?;

        // Update stats
        match gate_type {
            GateType::AND => stats.and_gates += 1,
            GateType::XOR => stats.xor_gates += 1,
        }
        stats.total_gates += 1;

        // Progress update
        if stats.total_gates % 1_000_000 == 0 {
            let elapsed = start_time.elapsed().as_secs_f64();
            let rate = if elapsed > 0.0 {
                format!(
                    "{}/s",
                    format_number((stats.total_gates as f64 / elapsed) as usize)
                )
            } else {
                "calculating...".to_string()
            };
            pb.set_message(format!(
                "Verified {} gates ({} XOR, {} AND) [{}]",
                format_number(stats.total_gates),
                format_number(stats.xor_gates),
                format_number(stats.and_gates),
                rate
            ));
        }
    }

    let elapsed = start_time.elapsed().as_secs_f64();
    let final_rate = if elapsed > 0.0 {
        format!(
            "[{}/s]",
            format_number((stats.total_gates as f64 / elapsed) as usize)
        )
    } else {
        "".to_string()
    };
    pb.finish_with_message(format!(
        "✓ Verified {} gates ({} XOR, {} AND) {}",
        format_number(stats.total_gates),
        format_number(stats.xor_gates),
        format_number(stats.and_gates),
        final_rate
    ));

    // Calculate file size
    stats.file_size = std::fs::metadata(&bristol_path)?.len();

    Ok(stats)
}

/// Statistics from verification process
#[derive(Debug)]
pub struct VerificationStats {
    pub total_gates: usize,
    pub xor_gates: usize,
    pub and_gates: usize,
    pub file_size: u64,
}

impl VerificationStats {
    fn new() -> Self {
        Self {
            total_gates: 0,
            xor_gates: 0,
            and_gates: 0,
            file_size: 0,
        }
    }

    pub fn print_summary(&self) {
        println!("Verification Summary:");
        println!("  Total gates: {}", format_number(self.total_gates));
        println!(
            "  XOR gates: {} ({:.1}%)",
            format_number(self.xor_gates),
            (self.xor_gates as f64 / self.total_gates as f64) * 100.0
        );
        println!(
            "  AND gates: {} ({:.1}%)",
            format_number(self.and_gates),
            (self.and_gates as f64 / self.total_gates as f64) * 100.0
        );
        println!(
            "  File size: {:.2} GB",
            self.file_size as f64 / 1_000_000_000.0
        );
        println!(
            "  Average bytes per gate: {:.2}",
            self.file_size as f64 / self.total_gates as f64
        );
    }
}

/// Statistics from conversion process
#[derive(Debug)]
pub struct ConversionStats {
    pub total_gates: usize,
    pub xor_gates: usize,
    pub and_gates: usize,
    pub bristol_file_size: u64,
    pub binary_file_size: u64,
    pub compression_ratio: f64,
}

impl ConversionStats {
    fn new() -> Self {
        Self {
            total_gates: 0,
            xor_gates: 0,
            and_gates: 0,
            bristol_file_size: 0,
            binary_file_size: 0,
            compression_ratio: 0.0,
        }
    }

    pub fn print_summary(&self) {
        println!("Conversion Summary:");
        println!("  Total gates: {}", format_number(self.total_gates));
        println!(
            "  XOR gates: {} ({:.1}%)",
            format_number(self.xor_gates),
            (self.xor_gates as f64 / self.total_gates as f64) * 100.0
        );
        println!(
            "  AND gates: {} ({:.1}%)",
            format_number(self.and_gates),
            (self.and_gates as f64 / self.total_gates as f64) * 100.0
        );
        println!(
            "  Bristol file size: {:.2} GB",
            self.bristol_file_size as f64 / 1_000_000_000.0
        );
        println!(
            "  Binary file size: {:.2} GB",
            self.binary_file_size as f64 / 1_000_000_000.0
        );
        println!("  Compression ratio: {:.2}x", self.compression_ratio);
        println!(
            "  Space saved: {:.1}%",
            (1.0 - 1.0 / self.compression_ratio) * 100.0
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn create_test_bristol_file(content: &str) -> Result<NamedTempFile> {
        let mut temp_file = NamedTempFile::new()?;
        temp_file.write_all(content.as_bytes())?;
        temp_file.flush()?;
        Ok(temp_file)
    }

    #[test]
    fn test_compact_gate_serialization() {
        let gate = CompactGate {
            input1: 0x12345678,
            input2: 0x9ABCDEF0,
            output: 0x11223344,
        };

        let bytes = gate.to_bytes();
        let restored = CompactGate::from_bytes(&bytes);

        assert_eq!(gate.input1, restored.input1);
        assert_eq!(gate.input2, restored.input2);
        assert_eq!(gate.output, restored.output);
    }

    #[test]
    fn test_gate_batch_operations() {
        let mut batch = GateBatch::new();

        // Set some gates
        let gate1 = CompactGate {
            input1: 10,
            input2: 20,
            output: 30,
        };
        let gate2 = CompactGate {
            input1: 40,
            input2: 50,
            output: 60,
        };

        batch.set_gate(0, gate1, GateType::XOR); // XOR
        batch.set_gate(1, gate2, GateType::AND); // AND

        // Test retrieval
        let (retrieved_gate1, gate_type1) = batch.get_gate(0);
        assert_eq!(retrieved_gate1.input1, 10);
        assert_eq!(retrieved_gate1.input2, 20);
        assert_eq!(retrieved_gate1.output, 30);
        assert_eq!(gate_type1, GateType::XOR);

        let (retrieved_gate2, gate_type2) = batch.get_gate(1);
        assert_eq!(retrieved_gate2.input1, 40);
        assert_eq!(retrieved_gate2.input2, 50);
        assert_eq!(retrieved_gate2.output, 60);
        assert_eq!(gate_type2, GateType::AND);
    }

    #[test]
    fn test_batch_serialization() {
        let mut batch = GateBatch::new();

        batch.set_gate(
            0,
            CompactGate {
                input1: 100,
                input2: 200,
                output: 300,
            },
            GateType::XOR,
        );
        batch.set_gate(
            1,
            CompactGate {
                input1: 400,
                input2: 500,
                output: 600,
            },
            GateType::AND,
        );

        let bytes = batch.to_bytes();
        assert_eq!(bytes.len(), 97);

        let restored = GateBatch::from_bytes(&bytes);

        let (gate0, gate_type0) = restored.get_gate(0);
        assert_eq!(gate0.input1, 100);
        assert_eq!(gate0.input2, 200);
        assert_eq!(gate0.output, 300);
        assert_eq!(gate_type0, GateType::XOR);

        let (gate1, gate_type1) = restored.get_gate(1);
        assert_eq!(gate1.input1, 400);
        assert_eq!(gate1.input2, 500);
        assert_eq!(gate1.output, 600);
        assert_eq!(gate_type1, GateType::AND);
    }

    #[test]
    fn test_bristol_parsing() -> Result<()> {
        let line = "2 1 100 200 300 XOR";
        let (input1, input2, output, gate_type) = parse_bristol_gate_line(line)?;

        assert_eq!(input1, 100);
        assert_eq!(input2, 200);
        assert_eq!(output, 300);
        assert_eq!(gate_type, GateType::XOR);

        let line = "2 1 400 500 600 AND";
        let (input1, input2, output, gate_type) = parse_bristol_gate_line(line)?;

        assert_eq!(input1, 400);
        assert_eq!(input2, 500);
        assert_eq!(output, 600);
        assert_eq!(gate_type, GateType::AND);

        Ok(())
    }

    #[test]
    fn test_round_trip_conversion() -> Result<()> {
        // Create test Bristol circuit
        let bristol_content = "2 1 0 1 2 XOR\n2 1 3 4 5 AND\n2 1 6 7 8 XOR\n";
        let bristol_file = create_test_bristol_file(bristol_content)?;

        // Convert to binary
        let binary_file = NamedTempFile::new()?;
        let stats = convert_bristol_to_compressed_binary(bristol_file.path(), binary_file.path())?;

        // Verify stats
        assert_eq!(stats.total_gates, 3);
        assert_eq!(stats.xor_gates, 2);
        assert_eq!(stats.and_gates, 1);

        // Read back and verify
        let mut reader = CompressedBinaryCircuitReader::new(binary_file.path())?;

        // First gate: XOR
        let (gate, gate_type) = reader.next_gate()?.unwrap();
        assert_eq!(gate.input1, 0);
        assert_eq!(gate.input2, 1);
        assert_eq!(gate.output, 2);
        assert_eq!(gate_type, GateType::XOR);

        // Second gate: AND
        let (gate, gate_type) = reader.next_gate()?.unwrap();
        assert_eq!(gate.input1, 3);
        assert_eq!(gate.input2, 4);
        assert_eq!(gate.output, 5);
        assert_eq!(gate_type, GateType::AND);

        // Third gate: XOR
        let (gate, gate_type) = reader.next_gate()?.unwrap();
        assert_eq!(gate.input1, 6);
        assert_eq!(gate.input2, 7);
        assert_eq!(gate.output, 8);
        assert_eq!(gate_type, GateType::XOR);

        // Should be end of file
        assert!(reader.next_gate()?.is_none());

        // Verify total gates read matches expected
        assert_eq!(reader.gates_read(), 3);

        Ok(())
    }

    #[test]
    fn test_verify_bristol_circuit() -> Result<()> {
        use std::io::Write;
        use tempfile::NamedTempFile;

        // Create a test Bristol file with known content
        let mut temp_file = NamedTempFile::new()?;
        writeln!(temp_file, "2 1 0 1 2 XOR")?; // XOR gate
        writeln!(temp_file, "2 1 2 3 4 AND")?; // AND gate
        writeln!(temp_file, "2 1 4 5 6 XOR")?; // XOR gate
        writeln!(temp_file, "2 1 6 7 8 AND")?; // AND gate
        writeln!(temp_file, "2 1 8 9 10 AND")?; // AND gate
        temp_file.flush()?;

        // Verify the Bristol circuit
        let stats = verify_bristol_circuit(temp_file.path())?;

        // Check statistics
        assert_eq!(stats.total_gates, 5);
        assert_eq!(stats.xor_gates, 2);
        assert_eq!(stats.and_gates, 3);
        assert!(stats.file_size > 0);

        Ok(())
    }
}
