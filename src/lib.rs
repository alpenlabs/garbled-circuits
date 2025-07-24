use std::io;

pub trait LineStream: Iterator<Item = Result<String, io::Error>> {}

pub mod stream;
pub mod counter;
pub mod wire_analyzer;
pub mod single_use_analyzer;
pub mod memory_simulation;
pub mod garbler;
pub mod ot_simulation;
pub mod evaluator;