#!/usr/bin/env python3
"""
Plot wire usage count distribution from CSV file.

Usage:
    python plot_usage_distribution.py <csv_file> [--output <output_file>]
"""

import pandas as pd
import matplotlib.pyplot as plt
import argparse
import sys
from pathlib import Path

def plot_usage_distribution(csv_file: str, output_file: str = None):
    """
    Plot wire usage count distribution showing how many wires have each usage count.
    
    Args:
        csv_file: Path to the CSV file with columns: usage_count, wire_count
        output_file: Optional output file path for saving the plot
    """
    try:
        # Read CSV data
        print(f"Loading data from: {csv_file}")
        df = pd.read_csv(csv_file)
        
        # Validate CSV format
        required_columns = ['usage_count', 'wire_count']
        if not all(col in df.columns for col in required_columns):
            print(f"Error: CSV must contain columns: {required_columns}")
            print(f"Found columns: {list(df.columns)}")
            return False
            
        # Create buckets for usage counts
        def get_bucket(usage_count):
            if usage_count == 0:
                return "0 (unused)"
            elif usage_count == 1:
                return "1 (used once)"
            elif 2 <= usage_count <= 10:
                return "2-10"
            elif 11 <= usage_count <= 100:
                return "11-100"
            elif 101 <= usage_count <= 254:
                return "101-254"
            else:
                return "255+"
        
        # Group data into buckets
        df['bucket'] = df['usage_count'].apply(get_bucket)
        bucketed_data = df.groupby('bucket')['wire_count'].sum().reset_index()
        
        # Define bucket order for plotting
        bucket_order = ["0 (unused)", "1 (used once)", "2-10", "11-100", "101-254", "255+"]
        bucketed_data['bucket'] = pd.Categorical(bucketed_data['bucket'], categories=bucket_order, ordered=True)
        bucketed_data = bucketed_data.sort_values('bucket')
        
        # Print summary statistics
        total_wires = df['wire_count'].sum()
        max_usage = df['usage_count'].max()
        most_common_usage = df.loc[df['wire_count'].idxmax(), 'usage_count']
        most_common_count = df['wire_count'].max()
        
        print(f"Data points: {len(df)} different usage counts")
        print(f"Total wires: {total_wires:,}")
        print(f"Usage count range: 0 - {max_usage}")
        print(f"Most common usage: {most_common_usage} ({most_common_count:,} wires)")
        print("\nBucketed distribution:")
        for _, row in bucketed_data.iterrows():
            percentage = (row['wire_count'] / total_wires) * 100
            print(f"  {row['bucket']}: {row['wire_count']:,} wires ({percentage:.1f}%)")
        
        # Create the plot
        fig, ax1 = plt.subplots(1, 1, figsize=(12, 8))
        
        # Color scheme for buckets
        colors = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4', '#FFEAA7', '#DDA0DD']
        
        # Single bar chart
        bars1 = ax1.bar(range(len(bucketed_data)), bucketed_data['wire_count'], 
                       color=colors[:len(bucketed_data)], alpha=0.8, width=0.6)
        ax1.set_xlabel('Usage Count Bucket', fontsize=12)
        ax1.set_ylabel('Number of Wires', fontsize=12)
        ax1.set_title('Wire Usage Count Distribution - Bucketed', fontsize=14, fontweight='bold')
        ax1.set_xticks(range(len(bucketed_data)))
        ax1.set_xticklabels(bucketed_data['bucket'], rotation=45, ha='right')
        ax1.grid(True, alpha=0.3, axis='y')
        
        # Format y-axis with comma separators
        ax1.yaxis.set_major_formatter(plt.FuncFormatter(lambda x, p: f'{int(x):,}'))
        
        # Add count and percentage labels on bars
        for i, (bar, row) in enumerate(zip(bars1, bucketed_data.itertuples())):
            height = bar.get_height()
            percentage = (height / total_wires) * 100
            
            # Format the count for readability
            if height >= 1_000_000_000:
                count_str = f'{height/1_000_000_000:.1f}B'
            elif height >= 1_000_000:
                count_str = f'{height/1_000_000:.1f}M'
            elif height >= 1_000:
                count_str = f'{height/1_000:.1f}K'
            else:
                count_str = f'{int(height)}'
            
            label = f'{count_str}\n({percentage:.1f}%)'
            ax1.text(bar.get_x() + bar.get_width()/2., height + height*0.01,
                    label, ha='center', va='bottom', fontsize=9)
        
        # Add info about the two highest usage count values (excluded from plot scale)
        extreme_values = df.nlargest(2, 'usage_count')
        outlier_text = "Extreme outliers:\n"
        for _, row in extreme_values.iterrows():
            count_formatted = f"{int(row['usage_count']):,}"
            outlier_text += f"{count_formatted} uses: {int(row['wire_count'])} wires\n"
        
        ax1.text(0.98, 0.98, outlier_text.strip(), 
                transform=ax1.transAxes, fontsize=9,
                verticalalignment='top', horizontalalignment='right',
                bbox=dict(boxstyle="round,pad=0.3", facecolor="lightyellow", alpha=0.8))
        
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
        description="Plot wire usage count distribution from CSV file",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python plot_usage_distribution.py psm3_usage_distribution.csv
    python plot_usage_distribution.py usage_dist.csv --output usage_plot.png
    python plot_usage_distribution.py usage_dist.csv --output usage_plot.pdf
        """
    )
    
    parser.add_argument('csv_file', 
                       help='CSV file with wire usage distribution data')
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
    success = plot_usage_distribution(args.csv_file, args.output)
    
    if not success:
        sys.exit(1)
        
    print("✓ Wire usage distribution plot completed successfully!")

if __name__ == "__main__":
    main()