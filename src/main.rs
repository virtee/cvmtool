// SPDX-License-Identifier: AGPL-3.0-or-later

use anyhow::{Context, Error, Result, bail};
use clap::{Parser, Subcommand};
use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;

#[cfg(feature = "azure")]
mod azure;
mod pck;
mod sev;
mod tdx;
mod vcek;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Don't display any status messages, only error messages
    #[arg(short, long)]
    quiet: bool,

    /// Display verbose information about operations
    #[arg(short, long)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a report
    Report {
        /// Path to the report file to create ('-' for stdout)
        #[arg(value_name = "FILE")]
        path: PathBuf,

        /// The report format ('sev', 'tdx')
        #[arg(short, long)]
        format: Option<String>,

        /// Report data (hex string). Will be padded with zeros or truncated to 64 bytes.
        #[arg(long)]
        report_data: Option<String>,
    },
    /// Verify a report
    Verify {
        /// Path to the report file to verify ('-' for stdin)
        #[arg(value_name = "FILE")]
        path: PathBuf,

        /// The report format ('sev', 'tdx')
        #[arg(short, long)]
        format: Option<String>,

        /// Path to directory containing certificate chain
        #[arg(short, long, value_name = "DIR")]
        certs_dir: Option<PathBuf>,

        /// Expected report data (hex string). Will be padded with zeros or truncated to 64 bytes.
        #[arg(long)]
        report_data: Option<String>,

        /// Expected launch measurement (hex string, 48 bytes for SEV/TDX MRTD)
        #[arg(long)]
        measurement: Option<String>,

        /// Expected host data (hex string, 32 bytes, SEV only)
        #[arg(long)]
        sev_host_data: Option<String>,

        /// Expected ID key digest (hex string, 48 bytes, SEV only)
        #[arg(long)]
        sev_id_key_digest: Option<String>,

        /// Minimum TCB versions as bootloader:tee:snp:microcode (e.g., "3:0:8:209", SEV only)
        #[arg(long, value_parser = parse_min_tcb)]
        sev_min_tcb: Option<(u8, u8, u8, u8)>,

        /// Expected RTMR0 value (hex string, 48 bytes, TDX only)
        #[arg(long)]
        tdx_rtmr0: Option<String>,

        /// Expected RTMR1 value (hex string, 48 bytes, TDX only)
        #[arg(long)]
        tdx_rtmr1: Option<String>,

        /// Expected RTMR2 value (hex string, 48 bytes, TDX only)
        #[arg(long)]
        tdx_rtmr2: Option<String>,

        /// Expected RTMR3 value (hex string, 48 bytes, TDX only)
        #[arg(long)]
        tdx_rtmr3: Option<String>,

        /// Require debug mode to be disabled
        #[arg(long)]
        policy_no_debug: bool,

        /// Require migration to be disabled (SEV only)
        #[arg(long)]
        policy_no_migration: bool,
    },
    /// Fetch PCK certificate from Intel PCS (for TDX hosts)
    FetchPck {
        /// Output directory for certificates
        #[arg(short, long, default_value = ".")]
        certs_dir: PathBuf,
    },
    /// Fetch VCEK and CA certificates from AMD KDS (for SEV-SNP)
    FetchVcek {
        /// Output directory for certificates
        #[arg(short, long, default_value = ".")]
        certs_dir: PathBuf,
    },
}

/// Options for attestation verification beyond cryptographic checks
#[derive(Debug, Default, Clone)]
pub struct VerifyOptions {
    /// Verbose output
    pub verbose: bool,
    /// Don't print messages
    pub quiet: bool,
    /// Expected report data (hex string). Will be padded with zeros or truncated to 64 bytes.
    pub report_data: Option<String>,
    /// Expected launch measurement (hex string, SEV: 48 bytes, TDX MRTD: 48 bytes)
    pub measurement: Option<String>,
    /// Expected host data (hex string, SEV only, 32 bytes)
    pub sev_host_data: Option<String>,
    /// Expected ID key digest (hex string, SEV only, 48 bytes)
    pub sev_id_key_digest: Option<String>,
    /// Minimum TCB versions (SEV only): (bootloader, tee, snp, microcode)
    pub sev_min_tcb: Option<(u8, u8, u8, u8)>,
    /// Expected RTMR values (hex string, TDX only, 48 bytes each)
    pub tdx_rtmr0: Option<String>,
    pub tdx_rtmr1: Option<String>,
    pub tdx_rtmr2: Option<String>,
    pub tdx_rtmr3: Option<String>,
    /// Require debug mode to be disabled
    pub policy_no_debug: bool,
    /// Require migration to be disabled (SEV only)
    pub policy_no_migration: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Report {
            path,
            format,
            report_data,
        } => {
            let mut input = [0u8; 64];
            match report_data {
                Some(n) => {
                    let n = hex::decode(&n).context("Invalid hex string for report data")?;
                    let len = n.len().min(64);
                    input[..len].copy_from_slice(&n[..len]);
                }
                None => rand::fill(&mut input[..]), // Randomly generate the report data.
            }

            let report = report(format.as_deref(), input).context("Failed to get report")?;
            if path.to_str() == Some("-") {
                io::stdout()
                    .write_all(&report)
                    .context("Failed to write report to stdout")?;
            } else {
                fs::write(&path, &report)
                    .context(format!("Failed to write report to {}", path.display()))?;
                if !cli.quiet {
                    println!(
                        "Report successfully written to {} in binary format",
                        path.display()
                    )
                }
            }
        }
        Commands::Verify {
            path,
            format,
            certs_dir,
            report_data,
            measurement,
            sev_host_data,
            sev_id_key_digest,
            sev_min_tcb,
            tdx_rtmr0,
            tdx_rtmr1,
            tdx_rtmr2,
            tdx_rtmr3,
            policy_no_debug,
            policy_no_migration,
        } => {
            let report_bytes = if path.to_str() == Some("-") {
                let mut buf = Vec::new();
                io::stdin()
                    .read_to_end(&mut buf)
                    .context("Failed to read report from stdin")?;
                buf
            } else {
                fs::read(&path).context(format!("Failed to read report file {}", path.display()))?
            };

            let opts = VerifyOptions {
                verbose: cli.verbose,
                quiet: cli.quiet,
                report_data,
                measurement,
                sev_host_data,
                sev_id_key_digest,
                sev_min_tcb,
                tdx_rtmr0,
                tdx_rtmr1,
                tdx_rtmr2,
                tdx_rtmr3,
                policy_no_debug,
                policy_no_migration,
            };

            verify(format, certs_dir, report_bytes, opts)?;
        }
        Commands::FetchPck { certs_dir } => {
            if cli.verbose {
                println!("Retrieving platform information...");
            }
            let platform_info = pck::get_platform_info()?;
            if cli.verbose {
                println!("Platform info retrieved:");
                println!(
                    "  PPID: {}...",
                    &platform_info.encrypted_ppid[..32.min(platform_info.encrypted_ppid.len())]
                );
                println!("  PCE ID: {}", platform_info.pce_id);
                println!("  CPU SVN: {}", platform_info.cpu_svn);
                println!("  PCE SVN: {}", platform_info.pce_svn);
                println!("  QE ID: {}", platform_info.qe_id);
            }

            if cli.verbose {
                println!("\nFetching PCK certificate from Intel PCS...");
            }
            let response = pck::fetch_pck_certificate(&platform_info)?;
            if cli.verbose {
                println!("Certificate retrieved:");
                println!("  FMSPC: {}", response.fmspc);
                println!("  TCBm: {}", response.tcbm);
                println!("  CA Type: {}", response.ca_type);

                println!("\nSaving certificates...");
            }
            pck::save_certificates(&response, &certs_dir, cli.verbose)?;
            if !cli.quiet {
                println!("Saved certificates to {:?}", certs_dir);
            }
        }
        Commands::FetchVcek { certs_dir } => {
            if cli.verbose {
                println!("Generating SEV attestation report...");
            }

            let report = report(Some("sev"), [0; 64])?;
            let report = sev::parse_report(&report)?;

            let processor = vcek::get_processor_model(&report)?;
            if cli.verbose {
                println!("Detected processor: {processor}");
            }

            if cli.verbose {
                println!("Fetching VCEK certificate from AMD KDS...");
            }
            let vcek_der = vcek::fetch_vcek_certificate(&report, &processor)?;
            if cli.verbose {
                println!("VCEK certificate retrieved ({} bytes)", vcek_der.len());
            }

            if cli.verbose {
                println!("Fetching CA chain (ARK + ASK) from AMD KDS...");
            }
            let chain = vcek::fetch_ca_chain(&processor)?;
            if cli.verbose {
                println!("CA chain retrieved");
            }

            vcek::save_certificates(&vcek_der, &chain, &certs_dir, cli.verbose)?;
            if !cli.quiet {
                println!("Saved certificates to {:?}", certs_dir);
            }
        }
    }

    Ok(())
}

fn verify(
    format: Option<String>,
    certs_dir: Option<PathBuf>,
    report_bytes: Vec<u8>,
    opts: VerifyOptions,
) -> Result<()> {
    if format.is_none() || format == Some("sev".to_string()) {
        match sev::parse_report(&report_bytes) {
            Ok(report) => {
                if opts.verbose {
                    println!("{:#?}", report);
                }
                let certs_dir = certs_dir
                    .ok_or_else(|| anyhow::anyhow!("Certificates directory not provided"))?;
                sev::verify_report(&report, &certs_dir, &opts)?;
                if !opts.quiet {
                    println!("Verified SEV attestation report");
                }
                return Ok(());
            }

            Err(err) => {
                if format.is_some() {
                    return Err(err);
                }
            }
        }
    }
    if format.is_none() || format == Some("tdx".to_string()) {
        match tdx::parse_quote(&report_bytes) {
            Ok(quote) => {
                if opts.verbose {
                    println!("{:#?}", quote);
                }
                tdx::verify_quote(&quote, certs_dir.as_deref(), &opts)?;
                if !opts.quiet {
                    println!("Verified TDX attestation report");
                }
                return Ok(());
            }
            Err(err) => {
                if format.is_some() {
                    return Err(err);
                }
            }
        }
    }

    if let Some(format) = format {
        bail!("Unsupported format: {format}")
    }

    bail!("Unable to detect report format")
}

fn report(format: Option<&str>, input: [u8; 64]) -> Result<Vec<u8>> {
    #[cfg(feature = "azure")]
    if azure::get_isolation_type().is_some() {
        // TODO add input data in NV 0x01400002
        let report = azure::read_report()?;
        match report.isolation_type {
            azure::IsolationType::Snp => {
                if format == Some("tdx") {
                    return Err(anyhow::anyhow!(
                        "Requested TDX format but Azure vTPM contains SNP report"
                    ));
                }
            }
            azure::IsolationType::Tdx => {
                if format == Some("sev") {
                    return Err(anyhow::anyhow!(
                        "Requested SEV format but Azure vTPM contains TDX report"
                    ));
                }
            }
        }
        return Ok(report.hw_report);
    }

    let report = if let Some(format) = format {
        match format {
            "sev" => configfs_tsm::create_quote_with_providers(input, vec![&"sev-guest"]),
            "tdx" => configfs_tsm::create_quote_with_providers(input, vec![&"tdx-guest"]),
            _ => bail!("Unsupported format: {format}"),
        }
    } else {
        configfs_tsm::create_quote(input)
    };

    report.map_err(Error::msg)
}

fn parse_min_tcb(s: &str) -> Result<(u8, u8, u8, u8), String> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 4 {
        return Err("Expected format: bootloader:tee:snp:microcode (e.g., 3:0:8:209)".to_string());
    }
    let bootloader = parts[0]
        .parse::<u8>()
        .map_err(|_| "Invalid bootloader version")?;
    let tee = parts[1].parse::<u8>().map_err(|_| "Invalid tee version")?;
    let snp = parts[2].parse::<u8>().map_err(|_| "Invalid snp version")?;
    let microcode = parts[3]
        .parse::<u8>()
        .map_err(|_| "Invalid microcode version")?;
    Ok((bootloader, tee, snp, microcode))
}
