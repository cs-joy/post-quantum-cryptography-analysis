import json
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import numpy as np
from pathlib import Path

class PQCVisualizer:
    def __init__(self, results_path='results/pqc_blockchain_benchmarks.json'):
        with open(results_path) as f:
            self.results = json.load(f)
            
        plt.style.use('seaborn-v0_8-paper')
        sns.set_context("paper", font_scale=1.5)
        self.colors = sns.color_palette("deep")
        
    def _format_size(self, size_bytes):
        for unit in ['B', 'KB', 'MB']:
            if size_bytes < 1024:
                return f"{size_bytes:.0f}{unit}"
            size_bytes /= 1024
        return f"{size_bytes:.0f}MB"

    def create_comparison_plot(self):
        plt.figure(figsize=(12, 6))
        scheme_names = list(self.results.keys())
        
        # Prepare data
        pure_times = []
        blockchain_times = []
        message_sizes = []
        schemes = []
        
        # Ensure consistent order for message sizes if needed, e.g., by sorting keys
        all_sizes = set()
        for scheme_data in self.results.values():
            for key in scheme_data['measurements'].keys():
                size = int(key.split('_')[-1])
                all_sizes.add(size)
        
        sorted_sizes = sorted(list(all_sizes))
        size_map = {size: self._format_size(size) for size in sorted_sizes}
        ordered_size_labels = [size_map[size] for size in sorted_sizes]

        for scheme_name, scheme_data in self.results.items():
            # Sort measurements by size to ensure consistency
            sorted_measurements = sorted(scheme_data['measurements'].items(), key=lambda item: int(item[0].split('_')[-1]))
            for key, measurement in sorted_measurements:
                size = int(key.split('_')[-1])
                pure_times.append(measurement['pure_crypto']['pure_verification_time_ms'])
                blockchain_times.append(measurement['blockchain_overhead']['blockchain_verification_time_ms'])
                message_sizes.append(size_map[size]) # Use formatted size
                schemes.append(scheme_name)
        
        df = pd.DataFrame({
            'Message Size': message_sizes,
            'Scheme': schemes,
            'Pure Verification (ms)': pure_times,
            'Blockchain Verification (ms)': blockchain_times
        })
        
        # Ensure the plot uses the sorted order of message sizes
        df['Message Size'] = pd.Categorical(df['Message Size'], categories=ordered_size_labels, ordered=True)

        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
        
        sns.barplot(data=df, x='Message Size', y='Pure Verification (ms)', 
                   hue='Scheme', ax=ax1, order=ordered_size_labels) # Specify order
        ax1.set_title('Pure Verification Time')
        ax1.tick_params(axis='x', rotation=45)
        
        sns.barplot(data=df, x='Message Size', y='Blockchain Verification (ms)', 
                   hue='Scheme', ax=ax2, order=ordered_size_labels) # Specify order
        ax2.set_title('Blockchain Verification Time')
        ax2.tick_params(axis='x', rotation=45)
        
        plt.tight_layout()
        plt.savefig('results/verification_comparison.pdf', dpi=300, bbox_inches='tight')
        plt.close()

    def create_gas_analysis_plot(self):
        scheme_names = []
        base_gas = []
        verify_gas = []
        sig_sizes = []
        
        # Use a specific, common message size for comparison (e.g., 1024 bytes)
        target_size_key = 'message_size_1024' 

        for scheme_name, scheme_data in self.results.items():
            if target_size_key in scheme_data['measurements']:
                measurement = scheme_data['measurements'][target_size_key]
                
                scheme_names.append(scheme_name)
                base_gas.append(measurement['blockchain_overhead']['base_transaction_gas'])
                verify_gas.append(measurement['blockchain_overhead']['verification_gas'])
                sig_sizes.append(measurement['pure_crypto']['signature_size'])
            else:
                print(f"Warning: Data for message size 1024 not found for scheme {scheme_name}. Skipping in gas analysis plot.")

        if not scheme_names: # Check if any data was found
             print("Error: No data found for message size 1024 for any scheme. Cannot generate gas analysis plot.")
             return

        fig, ax1 = plt.subplots(figsize=(10, 6))
        
        # Plot stacked bars
        x = np.arange(len(scheme_names))
        width = 0.35
        
        ax1.bar(x, base_gas, width, label='Base Gas', color='lightblue')
        ax1.bar(x, verify_gas, width, bottom=base_gas, label='Verification Gas', color='darkblue')
        
        # Add signature size on secondary axis
        ax2 = ax1.twinx()
        ax2.plot(x, sig_sizes, 'r--', marker='o', label='Signature Size')
        
        # Set labels and legend
        ax1.set_xlabel('Scheme')
        ax1.set_ylabel('Gas Used')
        ax2.set_ylabel('Signature Size (bytes)')
        
        ax1.set_xticks(x)
        ax1.set_xticklabels(scheme_names)
        
        # Combine legends
        handles1, labels1 = ax1.get_legend_handles_labels()
        handles2, labels2 = ax2.get_legend_handles_labels()
        ax1.legend(handles1 + handles2, labels1 + labels2, loc='upper left')
        
        plt.title('Gas Usage and Signature Size Comparison (Message Size: 1KB)')
        plt.tight_layout()
        plt.savefig('results/gas_analysis.pdf', dpi=300, bbox_inches='tight')
        plt.close()

    def create_latex_tables(self):
        # Use a specific, common message size for comparison (e.g., 1024 bytes)
        target_size_key = 'message_size_1024' 
        
        # Table 1: Core Cryptographic Performance
        crypto_table = f"""\\begin{{table}}[h]
\\centering
\\caption{{Core Cryptographic Performance Metrics (Message Size: 1KB)}} % Updated Caption
\\label{{tab:crypto_perf}}
\\begin{{tabular}}{{lcccc}}
\\toprule
Scheme & Key Gen (ms) & Sign (ms) & Verify (ms) & Sig Size (B) \\\\
\\midrule
"""
        
        for scheme_name, scheme_data in self.results.items():
            # Keygen is independent of message size, take from any measurement if available
            keygen_time = "N/A" 
            if scheme_data['measurements']:
                 # Find the first available measurement for keygen time (should be consistent)
                 first_measurement = next(iter(scheme_data['measurements'].values()))
                 keygen_time = f"{first_measurement['pure_crypto']['key_generation_time_ms']:.2f}"

            if target_size_key in scheme_data['measurements']:
                measurement = scheme_data['measurements'][target_size_key]['pure_crypto']
                crypto_table += f"{scheme_name} & "
                crypto_table += f"{keygen_time} & " # Use fetched keygen time
                crypto_table += f"{measurement['signing_time_ms']:.2f} & "
                crypto_table += f"{measurement['pure_verification_time_ms']:.2f} & "
                crypto_table += f"{measurement['signature_size']} \\\\\n"
            else:
                 print(f"Warning: Data for message size 1024 not found for scheme {scheme_name}. Skipping in crypto table.")

        crypto_table += """\\bottomrule
\\end{tabular}
\\end{table}
"""

        # Table 2: Blockchain Integration Overhead
        overhead_table = f"""\\begin{{table}}[h]
\\centering
\\caption{{Simulated Blockchain Integration Overhead (Message Size: 1KB)}} % Updated Caption
\\label{{tab:blockchain_overhead}}
\\begin{{tabular}}{{lcccc}}
\\toprule
Scheme & Verification & Gas & Gas/Byte & Overhead \\\\
& Time (ms) & Used & Ratio & Ratio \\\\
\\midrule
"""
        
        for scheme_name, scheme_data in self.results.items():
             if target_size_key in scheme_data['measurements']:
                measurement = scheme_data['measurements'][target_size_key]
                overhead_data = measurement['blockchain_overhead']
                crypto_data = measurement['pure_crypto']
                
                # Calculate ratios safely, handle potential division by zero
                overhead_ratio = "N/A"
                if crypto_data['pure_verification_time_ms'] > 0:
                    overhead_ratio = f"{overhead_data['blockchain_verification_time_ms'] / crypto_data['pure_verification_time_ms']:.2f}x"

                gas_per_byte = "N/A"
                if crypto_data['signature_size'] > 0:
                     gas_per_byte = f"{overhead_data['total_gas'] / crypto_data['signature_size']:.1f}"

                overhead_table += f"{scheme_name} & "
                overhead_table += f"{overhead_data['blockchain_verification_time_ms']:.2f} & "
                overhead_table += f"{int(overhead_data['total_gas']):,} & "
                overhead_table += f"{gas_per_byte} & " # Use calculated gas/byte
                overhead_table += f"{overhead_ratio} \\\\\n" # Use calculated overhead ratio
             else:
                 print(f"Warning: Data for message size 1024 not found for scheme {scheme_name}. Skipping in overhead table.")

        overhead_table += """\\bottomrule
\\end{tabular}
\\end{table}
"""

        # Save tables
        results_dir = Path('results')
        results_dir.mkdir(exist_ok=True) # Ensure results dir exists
        with open(results_dir / 'tables.tex', 'w') as f:
            f.write(crypto_table)
            f.write('\n')
            f.write(overhead_table)

def main():
    visualizer = PQCVisualizer()
    visualizer.create_comparison_plot()
    visualizer.create_gas_analysis_plot()
    visualizer.create_latex_tables()

if __name__ == "__main__":
    main()