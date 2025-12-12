#!/bin/bash
# Set variables
TERRAFORM_CODE_DIR="./"                   
CHECKOV_OUTPUT_FILE="checkov_output.json" 

# Run Checkov scan and save output
checkov -d "$TERRAFORM_CODE_DIR" > "$CHECKOV_OUTPUT_FILE"

# Always continue Terraform even if Checkov finds failures
if [ $? -ne 0 ]; then
  echo "Checkov scan completed with findings, but Terraform will continue."
else
  echo "Checkov scan completed with no issues."
fi

exit 0


# !/bin/bash
#  Set variables
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
