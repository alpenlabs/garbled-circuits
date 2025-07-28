use std::io;

pub trait LineStream: Iterator<Item = Result<String, io::Error>> {}

pub mod bin;
pub mod counter;
pub mod evaluator;
pub mod garbler;
pub mod memory_simulation;
pub mod ot_simulation;
pub mod single_use_analyzer;
pub mod stream;
pub mod wire_analyzer;
