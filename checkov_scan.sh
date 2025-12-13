#!/bin/bash

# -----------------------------
# Variables
# -----------------------------
TERRAFORM_CODE_DIR="./"                  # Directory containing Terraform files
CHECKOV_OUTPUT_FILE="checkov_output.json" # File to save Checkov scan output

# -----------------------------
# Run Checkov scan
# -----------------------------
echo "Running Checkov scan on directory: $TERRAFORM_CODE_DIR"
checkov -d "$TERRAFORM_CODE_DIR" -o json > "$CHECKOV_OUTPUT_FILE"
CHECKOV_EXIT_CODE=$?

# -----------------------------
# Evaluate scan result
# -----------------------------
if [ $CHECKOV_EXIT_CODE -ne 0 ]; then
    echo "Checkov scan completed with findings. Issues are recorded in $CHECKOV_OUTPUT_FILE."
    echo "Terraform execution will continue despite findings."
else
    echo "Checkov scan completed successfully. No issues found."
fi

# Exit with success so Terraform continues
exit 0



#!/bin/bash
 # Set variables
# TERRAFORM_CODE_DIR="./"                   # Directory containing Terraform files
# CHECKOV_OUTPUT_FILE="checkov_output.JSON"  # File to save Checkov scan output

#  Run Checkov scan and save output in a file
# checkov -d "$TERRAFORM_CODE_DIR" > "$CHECKOV_OUTPUT_FILE"

#  Check if the Checkov scan succeeded (exit code 0 = success)
# if [ $? -ne 0 ]; then
#   echo "Checkov scan completed but discovered issues. Check output file for detail"
#   exit 1  # Exit the script with a failure status
# else
#   echo "Checkov scan completed with no issues."
# fi
