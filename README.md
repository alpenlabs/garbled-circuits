# Alpen Labs Rust Template

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache-blue.svg)](https://opensource.org/licenses/apache-2-0)
[![ci](https://github.com/alpenlabs/rust-template/actions/workflows/lint.yml/badge.svg?event=push)](https://github.com/alpenlabs/rust-template/actions)
[![docs](https://img.shields.io/badge/docs-docs.rs-orange)](https://docs.rs/rust-template)


## Features

### Gate Count

### Wire Analysis

  This also checks the circuit for any malformed gates. incorrect number of input, output etc

### Memory Simulation

### Garbling

  Garbles Bristol circuits using Yao's protocol with free XOR optimization. Generates wire labels and garbled truth tables for AND gates.

### OT Simulation

  Simulates oblivious transfer by randomly selecting input wire labels for circuit evaluation.

### Circuit Evaluation

  Evaluates garbled circuits using OT-selected input labels, producing output wire labels and their bit values.

## PSM Circuit

Total Gates: 1607596410
AND Gates: 5012858
XOR Gates: 1602583552
Total wires: 1607597577
Primary inputs: 1167
Intermediate wires: 1607249081
Primary outputs: 347329
Missing/unused wires: 0

## Usage

### Complete Garbled Circuit Workflow

```bash
# 1. Analyze wire usage patterns (required for garbling/evaluation)
gc wire-analysis circuit.bristol -o circuit.wire_analysis

# 2. Garble the circuit
gc garble circuit.bristol -w circuit.wire_analysis -s seed.bin

# 3. Simulate OT to select input labels  
gc ot-simulate -w circuit.labels.json -s seed2.bin -o circuit.ot.json

# 4. Evaluate the garbled circuit
gc evaluate circuit.bristol -w circuit.wire_analysis -t circuit.ot.json -g circuit.garbled -o circuit.eval.json
```

### Additional Commands

```bash
# Count gate types
gc count circuit.bristol

# Run memory simulation
gc memory-simulation circuit.bristol -w circuit.wire_analysis -o circuit.memory_sim.csv
```

### Plotting Memory Results

```bash
# Create venv and install dependencies
python3 -m venv plot_venv && source plot_venv/bin/activate
pip install pandas matplotlib

# Generate memory usage plot
python plot_memory_sim.py circuit.memory_sim.csv --output memory_plot.png
```

## Contributing

Contributions are generally welcome.
If you intend to make larger changes please discuss them in an issue
before opening a PR to avoid duplicate work and architectural mismatches.

For more information please see [`CONTRIBUTING.md`](/CONTRIBUTING.md).

## License

This work is dual-licensed under MIT and Apache 2.0.
You can choose between one of them if you use this work.
