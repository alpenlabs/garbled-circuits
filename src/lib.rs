//! High-performance Rust implementation of Yao's garbled circuits protocol with free XOR optimization.

/// Shared constants used across the library
pub mod constants;
/// Circuit gate counting utilities
pub mod counter;
/// Garbled circuit evaluation functionality
pub mod evaluator;
/// Circuit garbling using Yao's protocol with free XOR
pub mod garbler;
/// Oblivious transfer (OT) protocol simulation
pub mod ot_simulation;
/// High-performance streaming file reader
pub mod stream;
/// Wire usage analysis for memory optimization
pub mod wire_analyzer;
// pub mod single_use_analyzer;
// pub mod memory_simulation;
