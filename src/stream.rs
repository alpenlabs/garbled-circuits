use std::fs::File;
use std::io::{self, BufRead, BufReader};

/// Default buffer size optimized for SSD sequential reads (256MB)
const DEFAULT_BUFFER_SIZE: usize = 256 * 1024 * 1024;

/// High-performance line streaming for large Bristol circuit files
/// 
/// Uses large internal buffers to minimize syscalls and returns string slices
/// to avoid allocations. Designed for sequential read-only processing of very
/// large files (50-100GB).
pub struct BufferedLineStream {
    /// Buffered reader with large buffer for efficient IO
    reader: BufReader<File>,
    /// Reused string buffer to avoid allocations per line
    line_buffer: String,
}

impl BufferedLineStream {
    /// Create a new stream with default 64MB buffer size
    pub fn new(file: File) -> Self {
        Self::with_buffer_size(file, DEFAULT_BUFFER_SIZE)
    }

    /// Create a new stream with custom buffer size
    /// 
    /// For SSDs, larger buffers (64-256MB) typically perform better
    /// due to reduced syscall overhead
    pub fn with_buffer_size(file: File, buffer_size: usize) -> Self {
        Self {
            reader: BufReader::with_capacity(buffer_size, file),
            // Pre-allocate reasonable line buffer (most Bristol lines < 1KB)
            line_buffer: String::with_capacity(1024),
        }
    }

    /// Get the next line as a string slice (zero-copy)
    /// 
    /// Returns None at EOF, or Some(Result) for each line.
    /// The returned &str is valid until the next call to next_line().
    /// 
    /// # Performance
    /// - Zero allocations - returns reference to internal buffer
    /// - Newlines are stripped from returned string
    /// - Internal buffer is reused for each line
    pub fn next_line(&mut self) -> Option<Result<&str, io::Error>> {
        // Clear buffer but keep allocated capacity
        self.line_buffer.clear();
        
        match self.reader.read_line(&mut self.line_buffer) {
            // EOF reached
            Ok(0) => None,
            
            // Line read successfully
            Ok(_) => {
                // Remove trailing newline characters (\n and \r\n)
                let line = self.line_buffer.trim_end();
                Some(Ok(line))
            }
            
            // IO error occurred
            Err(e) => Some(Err(e)),
        }
    }
}