# CVM Tool

A CLI tool to generate Confidential VM (CVM) reports/quotes using Linux TSM and verify them.

## Usage

### Generate a Report

To generate a TSM report/quote, use the `report` subcommand. You can optionally provide a nonce (hex string) and an output file path.

```bash
# Generate report without nonce, print to stdout
cvmtool -- report

# Generate report with a nonce, print to stdout
cvmtool -- report --nonce 0102030405060708

# Generate report and write to a file
cvmtool -- report --output cvm_report.bin

# Generate report with a nonce and write to a file
cvmtool -- report --nonce 0102030405060708 --output cvm_report_with_nonce.bin
```

The output is the raw report in **binary format**. When `--output` is used, a message indicating successful writing will be printed to stderr.

To view the binary report, you can use tools like `xxd` (e.g., `xxd cvm_report.bin`).

### Verify a Report

To verify (parse and inspect) a report, use the `verify` subcommand with the path to the report file.

```bash
cvmtool -- -p sev_guest verify cvm_report.bin --certs-dir .
```

This will parse the binary report file and print its header and body details (e.g., version, TEE type, RTMRs, Report Data).

It returns a success status code if the report is valid, or an error code if it is invalid.

## Requirements

This tool requires:
- A Linux environment with `configfs` enabled.
- The `tsm` (Trusted Security Module) subsystem enabled in the kernel.
- Running inside a supported Confidential VM (e.g., Intel TDX, AMD SEV-SNP) that exposes the TSM interface via configfs.
