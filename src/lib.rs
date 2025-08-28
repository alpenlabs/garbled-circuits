//! High-performance Rust implementation of Yao's garbled circuits protocol with free XOR optimization.

/// Shared constants used across the library
pub mod constants;
/// Circuit gate counting utilities
pub mod counter;
/// Garbled circuit evaluation functionality
pub mod evaluator;
/// Circuit garbling using Yao's protocol with free XOR
pub mod garbler;
/// Simulate the memory usage to store active wires
pub mod memory_simulation;
/// Oblivious transfer (OT) protocol simulation
pub mod ot_simulation;
/// Count number of single-use gates
pub mod single_use_analyzer;
/// High-performance streaming file reader
pub mod stream;
/// Wire usage analysis for memory optimization
pub mod wire_analyzer;

/// A helper function to serialize a [`std::collections::HashMap`] with sorted keys.
pub(crate) fn serialize_sorted_map<S, K, V>(
    map: &std::collections::HashMap<K, V>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
    K: serde::Serialize + Ord + Copy + std::hash::Hash,
    V: serde::Serialize,
{
    let mut keys: Vec<&K> = map.keys().collect();
    keys.sort();

    let mut map_ser = serializer.serialize_map(Some(keys.len()))?;
    for &key in &keys {
        let value = &map[key];
        serde::ser::SerializeMap::serialize_entry(&mut map_ser, key, value)?;
    }
    serde::ser::SerializeMap::end(map_ser)
}
