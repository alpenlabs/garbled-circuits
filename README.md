# Garbled Circuits

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache-blue.svg)](https://opensource.org/licenses/apache-2-0)
[![ci](https://github.com/alpenlabs/rust-template/actions/workflows/lint.yml/badge.svg?event=push)](https://github.com/alpenlabs/garbled-circuits/actions)

## Features

### Gate Count

  This provides the total gate count along with the distribution of different type of gates.

  ```bash
  ./target/release/gc count dv.bristol
  ```

### Wire Analysis

  This performs wire usage analysis to optimize for memory allocation during garbling and evaluation. This also checks the circuit for any malformed gates. incorrect number of input, output etc.
  
  ```bash
  ./target/release/gc wire-analysis dv.bristol
  ```

  The summary of wire-analysis is displayed to stdout and the detailed analysis info is serialized as stored in file dv.wire_analysis

### Memory Simulation

  This is used to simulate memory utilization to ensure that we donot run out of memory storing the intermediate values.

  ```bash
  ./target/release/gc 
  ```

  The details are saved to dv.memory_sim.csv which can be plotted using the script `plot_memory_sim.py`

  ```bash
  python3 plot_memory_sim.py dv.memory_sim.csv --output dv.memory_sim.png
  ```

For our dv snark verifier circuit, we have the following plot
![alt text](images/dv-memory-sim.png)

It shows that atmost 761k out of 3.24 billion gates needs to be kept active. This is only about 0.021% of total wires which is great since at most these many intermediate wire labels needs to be kept in memory.

### Garbling

  Garbles Bristol circuits using Yao's protocol with free XOR optimization. Generates wire labels and garbled truth tables for AND gates.

### OT Simulation

  Simulates oblivious transfer by randomly selecting input wire labels for circuit evaluation.
  This has to be done by a proper OT protocol, It is currently used in this form since we want to get input labels for only one of the two possible bit values for the input wires.

### Circuit Evaluation

  Evaluates garbled circuits using OT-selected input labels, producing output wire labels and their bit values.

## DV Circuit

SHA256 hash: 17446f86cec9a4971dc09cb51359b532e9f48bc003c8e32c098c478df0110ca6
Total Gates: 3286564142
AND Gates: 12328132
XOR Gates: 3274236010
Total wires: 3286566319
Primary inputs: 2177
Intermediate wires: 3285848915
Primary outputs: 715227
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
