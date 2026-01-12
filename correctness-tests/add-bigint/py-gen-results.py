import os

def generate_and_add_large_ints(initial_kick, count, nr_operand_bits):
    
    # Calculate how many bytes are needed to store the result
    # Addition can produce a result with 1 more bit than the bigger operand's.
    # In this case both operands have the same bitlength.
    result_bytelen = nr_operand_bits + 1
    base_filename_str = "../calc-results/add-test-0-result-py-"
    base_filename_ext = ".dat"

    while result_bytelen % 8 != 0:
        result_bytelen += 1
    result_bytelen = result_bytelen // 8

    operands_1 = [0] * count
    operands_2 = [0] * count
    results    = [0] * count

    for i in range(count):
        operands_1[i] = initial_kick + (17_000_000 * pow(i, 90))
        operands_2[i] = initial_kick + (12_111_222 * pow(i, 90))

    full_filename_str = f"{base_filename_str}{0}{base_filename_ext}"
    os.makedirs(os.path.dirname(full_filename_str), exist_ok=True)
    with open(full_filename_str, 'wb') as f:
        f.truncate()

    for i in range(count):
        results[i] = operands_1[i] + operands_2[i]
        raw_bytes = results[i].to_bytes(result_bytelen, byteorder='little')

        # Track the progress and change file to write results to occasionally.
        if i % 1000000 == 0 and i > 0:
            batch = i//1000000
            full_filename_str = f"{base_filename_str}{batch}{base_filename_ext}"
            os.makedirs(os.path.dirname(full_filename_str), exist_ok=True)
            with open(full_filename_str, 'wb') as f:
                f.truncate()
            print(f"Batch {batch} with 1,000,000 bigint python ADDs done!")
            print(f"New file for results starting: {full_filename_str}")

        with open(full_filename_str, 'ab') as f:
            f.write(raw_bytes)

        if i == 0:
            with open('./FIRST-NUM.dat','wb') as f:
                f.write(raw_bytes)

        if i == count - 1:
            with open('./LAST-NUM.dat','wb') as f:
                f.write(raw_bytes)

    print("Done. Each python bigint ADD result is in DAT files.")
    print(f"Each number is stored in {result_bytelen} bytes.")
    return

print("START: Generating initial kick bigint.")

start_bigint   = 0xFF000000
multiplier     = 0xFF000000
operand_bits   = 32
nr_add_results = 10000000

# Will make 100 * 32 ~= 3200-bit starting BigInt.
for _ in range(100):
    start_bigint *= multiplier
    operand_bits += 32

print(f"Operand BigInt's bits are now: {operand_bits} - Starting calculations.")

generate_and_add_large_ints(start_bigint, nr_add_results, operand_bits)
