#!/usr/bin/env python3
"""
Plot memory simulation results from CSV file.

Usage:
    python plot_memory_sim.py <csv_file> [--output <output_file>]
"""

import pandas as pd
import matplotlib.pyplot as plt
import argparse
import sys
from pathlib import Path

def plot_memory_simulation(csv_file: str, output_file: str = None):
    """
    Plot memory simulation data showing live wire count over gate processing.
    
    Args:
        csv_file: Path to the CSV file with columns: gate_number, live_wire_count
        output_file: Optional output file path for saving the plot
    """
    try:
        # Read CSV data
        print(f"Loading data from: {csv_file}")
        df = pd.read_csv(csv_file)
        
        # Validate CSV format
        required_columns = ['gate_number', 'live_wire_count']
        if not all(col in df.columns for col in required_columns):
            print(f"Error: CSV must contain columns: {required_columns}")
            print(f"Found columns: {list(df.columns)}")
            return False
            
        # Print summary statistics
        print(f"Data points: {len(df)}")
        print(f"Gate range: {df['gate_number'].min():,} - {df['gate_number'].max():,}")
        print(f"Live wire range: {df['live_wire_count'].min():,} - {df['live_wire_count'].max():,}")
        print(f"Peak memory: {df['live_wire_count'].max():,} live wires")
        
        # Create the plot
        plt.figure(figsize=(12, 8))
        
        # Plot line chart
        plt.plot(df['gate_number'], df['live_wire_count'], 
                linewidth=1.5, color='#2E86AB', alpha=0.8)
        
        # Fill area under the curve for better visualization
        plt.fill_between(df['gate_number'], df['live_wire_count'], 
                        alpha=0.3, color='#A23B72')
        
        # Formatting
        plt.xlabel('Gate Number', fontsize=12)
        plt.ylabel('Live Wire Count', fontsize=12)
        plt.title('Memory Usage During Garbled Circuit Processing', fontsize=14, fontweight='bold')
        plt.grid(True, alpha=0.3)
        
        # Format axes with comma separators for large numbers
        ax = plt.gca()
        ax.xaxis.set_major_formatter(plt.FuncFormatter(lambda x, p: f'{int(x):,}'))
        ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda x, p: f'{int(x):,}'))
        
        # Add peak annotation
        peak_idx = df['live_wire_count'].idxmax()
        peak_gate = df.loc[peak_idx, 'gate_number']
        peak_wires = df.loc[peak_idx, 'live_wire_count']
        
        plt.annotate(f'Peak: {peak_wires:,} wires\n@ gate {peak_gate:,}',
                    xy=(peak_gate, peak_wires),
                    xytext=(peak_gate * 1.1, peak_wires * 0.9),
                    arrowprops=dict(arrowstyle='->', color='red', alpha=0.7),
                    fontsize=10,
                    bbox=dict(boxstyle="round,pad=0.3", facecolor="yellow", alpha=0.7))
        
        # Tight layout
        plt.tight_layout()
        
        # Save or show
        if output_file:
            plt.savefig(output_file, dpi=300, bbox_inches='tight')
            print(f"Plot saved to: {output_file}")
        else:
            plt.show()
            
        return True
        
    except FileNotFoundError:
        print(f"Error: File not found: {csv_file}")
        return False
    except pd.errors.EmptyDataError:
        print(f"Error: CSV file is empty: {csv_file}")
        return False
    except Exception as e:
        print(f"Error processing file: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(
        description="Plot memory simulation results from CSV file",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python plot_memory_sim.py circuit.memory_sim.csv
    python plot_memory_sim.py data.csv --output memory_plot.png
    python plot_memory_sim.py data.csv --output memory_plot.pdf
        """
    )
    
    parser.add_argument('csv_file', 
                       help='CSV file with memory simulation data')
    parser.add_argument('--output', '-o',
                       help='Output file for saving the plot (PNG, PDF, SVG, etc.)')
    
    args = parser.parse_args()
    
    # Validate input file
    if not Path(args.csv_file).exists():
        print(f"Error: File does not exist: {args.csv_file}")
        sys.exit(1)
    
    # Check if output directory exists
    if args.output:
        output_path = Path(args.output)
        if not output_path.parent.exists():
            print(f"Error: Output directory does not exist: {output_path.parent}")
            sys.exit(1)
    
    # Generate plot
    success = plot_memory_simulation(args.csv_file, args.output)
    
    if not success:
        sys.exit(1)
        
    print("✓ Memory simulation plot completed successfully!")

if __name__ == "__main__":
    main()