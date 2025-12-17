use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

mod pck;
mod sev;
mod tdx;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Specify the provider
    #[arg(short, long)]
    provider: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a report/quote
    Report {
        /// Nonce (hex string). Will be padded with zeros or truncated to 64 bytes.
        #[arg(long, value_parser = parse_hex)]
        nonce: Option<Vec<u8>>,

        /// Output file path. If not specified, the report is printed to stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Verify a report
    Verify {
        /// Path to the report file to verify
        #[arg(value_name = "FILE")]
        path: PathBuf,

        /// Path to directory containing certificate chain (ark.pem, ask.pem, vcek.pem)
        #[arg(short, long, value_name = "DIR")]
        certs_dir: Option<PathBuf>,
    },
    /// Fetch PCK certificate from Intel PCS (for TDX hosts)
    FetchPck {
        /// Output directory for certificates
        #[arg(short, long, default_value = ".")]
        output: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let provider = cli.provider;

    match cli.command {
        Commands::Report { nonce, output } => {
            let mut input = [0u8; 64];
            if let Some(n) = nonce {
                let len = n.len().min(64);
                input[..len].copy_from_slice(&n[..len]);
            }

            let quote = if let Some(provider) = provider {
                configfs_tsm::create_quote_with_providers(input, vec![&provider])
            } else {
                configfs_tsm::create_quote(input)
            };
            let quote = quote.map_err(|e| anyhow::anyhow!("Quote generation failed: {:?}", e))?;

            if let Some(path) = output {
                fs::write(&path, &quote)
                    .context(format!("Failed to write report to {}", path.display()))?;
                eprintln!(
                    "Report successfully written to {} in binary format",
                    path.display()
                );
            } else {
                io::stdout()
                    .write_all(&quote)
                    .context("Failed to write report to stdout")?;
            }
        }
        Commands::Verify { path, certs_dir } => {
            let report_bytes = fs::read(&path)
                .context(format!("Failed to read report file {}", path.display()))?;

            let provider =
                provider.ok_or_else(|| anyhow::anyhow!("The provider must be specified"))?;

            match provider.as_str() {
                "sev_guest" => {
                    let report = sev::parse_report(&report_bytes)?;
                    println!("{:#?}", report);
                    if let Some(certs_dir) = certs_dir {
                        sev::verify_report(&report, &certs_dir)?;
                        println!("Verification successful!");
                    }
                }
                "tdx_guest" => {
                    let quote = tdx::parse_quote(&report_bytes)?;
                    println!("{:#?}", quote);
                    tdx::verify_quote(&quote, certs_dir.as_deref())?;
                    println!("Verification successful!");
                }
                _ => {
                    return Err(anyhow::anyhow!("Unsupported provider: {}", provider));
                }
            }
        }
        Commands::FetchPck { output } => {
            eprintln!("Retrieving platform information...");
            let platform_info = pck::get_platform_info()?;
            eprintln!("Platform info retrieved:");
            eprintln!(
                "  PPID: {}...",
                &platform_info.encrypted_ppid[..32.min(platform_info.encrypted_ppid.len())]
            );
            eprintln!("  PCE ID: {}", platform_info.pce_id);
            eprintln!("  CPU SVN: {}", platform_info.cpu_svn);
            eprintln!("  PCE SVN: {}", platform_info.pce_svn);
            eprintln!("  QE ID: {}", platform_info.qe_id);

            eprintln!("\nFetching PCK certificate from Intel PCS...");
            let response = pck::fetch_pck_certificate(&platform_info)?;
            eprintln!("Certificate retrieved:");
            eprintln!("  FMSPC: {}", response.fmspc);
            eprintln!("  TCBm: {}", response.tcbm);
            eprintln!("  CA Type: {}", response.ca_type);

            eprintln!("\nSaving certificates...");
            pck::save_certificates(&response, &output)?;
            eprintln!("\nDone!");
        }
    }

    Ok(())
}

fn parse_hex(s: &str) -> Result<Vec<u8>, hex::FromHexError> {
    hex::decode(s)
}
