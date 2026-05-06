import struct
import numpy as np
import os

def analyze_measurements(filename):
    if not os.path.exists(filename):
        print(f"Error: {filename} not found.")
        return

    # 1. Read the binary file
    with open(filename, 'rb') as f:
        binary_data = f.read()

    # Unpack binary data into a Python tuple
    raw_measurements = struct.unpack('<500d', binary_data)

    # Convert to a numpy array
    data = np.array(raw_measurements)

    # 2. Sort the array
    sorted_data = np.sort(data)

    # 3. Compute Q1, Q3, and IQR
    q1 = np.percentile(sorted_data, 25)
    q3 = np.percentile(sorted_data, 75)
    iqr = q3 - q1

    # 4. Define the "Fences" for outliers
    lower_fence = q1 - 1.5 * iqr
    upper_fence = q3 + 1.5 * iqr

    # 5. Filter the data
    valid_measurements = sorted_data[
        (sorted_data >= lower_fence) & (sorted_data <= upper_fence)
    ]

    # 6. Calculate statistics
    raw_avg = np.mean(data)
    stable_avg = np.mean(valid_measurements)
    outliers_removed = len(data) - len(valid_measurements)

    # --- MODIFICATION START ---
    # 7. Append the Stable Average to the output file
    output_filename = "/home/hypervisor123/tmp/repos/Rosetta-Secure-Texting/performance-analysis/STABILIZED_AVERAGES.dat"
    try:
        with open(output_filename, 'a') as out_f:
            # Format to 4 decimal places, add a trailing space
            out_f.write(f"{stable_avg:.2f} ")
    except Exception as e:
        print(f"Error writing to {output_filename}: {e}")
    # --- MODIFICATION END ---

    # Output Results to Console
    print(f"--- Analysis for {filename} ---")
    print(f"Total Samples:      {len(data)}")
    print(f"Outliers Removed:   {outliers_removed}")
    print(f"Q1 (25th %):        {q1:.2f} us")
    print(f"Q3 (75th %):        {q3:.2f} us")
    print(f"IQR:                {iqr:.2f} us")
    print("-" * 30)
    print(f"Raw Average:        {raw_avg:.4f} us")
    print(f"Stable Average:     {stable_avg:.4f} us")
    print(f"Precision Gain:     {abs(raw_avg - stable_avg):.4f} us shift")
    print(f"Appended stable average to {output_filename}")

if __name__ == "__main__":
    analyze_measurements("/home/hypervisor123/tmp/repos/Rosetta-Secure-Texting/performance-analysis/last-measurements.dat")
