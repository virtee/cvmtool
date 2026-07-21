# CVM Tool

A CLI tool to generate Confidential VM (CVM) reports/quotes and verify them. Supports Linux TSM (configfs) and Azure vTPM.

## Usage

### Generate a Report

To generate a TSM report/quote, use the `report` subcommand. You can optionally provide a nonce (hex string) and an output file path.

```bash
# Generate report (with randomly-generated nonce), print to stdout
cvmtool report -

# Generate report with a nonce and write to a file
cvmtool report --report-data 0102030405060708 cvm_report_with_nonce.bin

# Generate report with a digest of a unique companion document and write to a file
DIGEST=$(sha256sum cvm_report.json)
cvmtool report --report-data $(DIGEST) cvm_report_with_digest.bin
```

The output is the raw report in **binary format**. The output target is a file, a message indicating successful writing will be printed to stdout.

To view the binary report, you can use tools like `xxd` (e.g., `xxd cvm_report.bin`).

### Verify a Report

To verify (parse and inspect) a report, use the `verify` subcommand with the path to the report file.

```bash
cvmtool verify -f sev cvm_report.bin --certs-dir certs/
```

This will parse the binary report file and print its header and body details (e.g., version, TEE type, RTMRs, Report Data).

It returns a success status code if the report is valid, or an error code if it is invalid.

To verify a report acquired from a remote machine, chain together commands over ssh

```bash
ssh user@remote-vm cvmtool report - | cvmtool verify -f tdx -
```

NB, the remote VM must have been configured to accept a trusted SSH public key
or other form of password-less credential. It is unsafe to respond to any remote
interactive password prompt prior to successfully verifying the attestion report.

#### Required certificates

To validate an attestation report and its measurements, the report's signature must be verified to the TEE manufacturer's root-of-trust.
These certificates are specific to the TEE architecture and must be submitted alongside the report. For each TEE architecture, the required
certificate(s) are as follows:

- AMD SEV-SNP: AMD Root Key (ARK), AMD Signing Key (ASK), Versioned Chip Endorsement Key (VCEK).
```
{certs-dir} \
    ark.{der, pem}
    ask.{der, pem}
    vcek.{der, pem}
    crl.{der, pem} (optional)
```
The `fetch-vcek` and `fetch-crl` subcommands can be used to fetch these certificates from AMD's Key Distribution Service (KDS).
- Intel TDX: Provisioning Certification Key (PCK), PCK Issuer Chain\*.
```
{certs-dir} \
   pck.pem
   pck_issuer_chain.pem
```

\* User-provided TDX certificate chains are optional. If the certificate chain is not provided, it will be fetched from the TDX quote (if available).
The `fetch-pck` subcommand can be used to fetch the certificate chain from the Intel Provisioning Certification Service.

### Fetch Certificates

To fetch the required certificates for verification, use the appropriate fetch subcommand from within the CVM:

```bash
# Fetch VCEK and CA chain from AMD KDS (for SEV-SNP)
cvmtool fetch-vcek --certs-dir certs/

# Fetch PCK certificate from Intel PCS (for TDX)
cvmtool fetch-pck --certs-dir certs/
```

### Fetch Revocation List (SEV-SNP only, optional)

To fetch the certificate revocation list for verification, use the `fetch-crl` command from within the CVM:

```bash
# Fetch CRL from AMD KDS
cvmtool fetch-crl --certs-dir certs/
```

## Azure CVM Support

When built with the `azure` feature, cvmtool can retrieve attestation reports from Azure Confidential VMs via the vTPM (Virtual TPM). This works on Azure CVMs using either SNP or TDX isolation.

```bash
# Build with Azure support
cargo build --features azure

# The tool automatically detects Azure environment and uses vTPM
cvmtool report cvm_report.bin
```

Azure detection is automatic via CPUID - if running in a Hyper-V isolated CVM, the tool reads the HCL attestation report from the vTPM NV index. Otherwise, it falls back to the standard configfs TSM interface.

## Requirements

**Standard (configfs TSM):**
- A Linux environment with `configfs` enabled
- The `tsm` (Trusted Security Module) subsystem enabled in the kernel
- Running inside a supported Confidential VM (e.g., Intel TDX, AMD SEV-SNP) that exposes the TSM interface via configfs

**Azure (`--features azure`):**
- Running inside an Azure Confidential VM (SNP or TDX isolation)
- Access to the vTPM device (`/dev/tpm0`)
- The `tss-esapi` library and its dependencies (tpm2-tss)
