#!/bin/bash

# input file w ips from scan
INPUT_FILE="input.txt"

# output file (just IPs)
OUTPUT_FILE="ips_only.txt"

# extract ips
awk '{print $1}' "$INPUT_FILE" > "$OUTPUT_FILE"

echo "Extracted IPs into $OUTPUT_FILE"

