// SPDX-License-Identifier: AGPL-3.0-or-later

// based from snpguest

use anyhow::{Context, Result};
use sev::certs::snp::ca::Chain;
use sev::firmware::guest::AttestationReport;
use std::fmt;
use std::fs;
use std::path::Path;
use std::str::FromStr;

const KDS_BASE_URL: &str = "https://kdsintf.amd.com";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcType {
    Milan,
    Genoa,
    Bergamo,
    Siena,
    Turin,
    Venice,
}

impl ProcType {
    pub fn to_kds_url(&self) -> &'static str {
        match self {
            ProcType::Genoa | ProcType::Bergamo | ProcType::Siena => "Genoa",
            ProcType::Milan => "Milan",
            ProcType::Turin => "Turin",
            ProcType::Venice => "Venice",
        }
    }
}

impl fmt::Display for ProcType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ProcType::Milan => write!(f, "Milan"),
            ProcType::Genoa => write!(f, "Genoa"),
            ProcType::Bergamo => write!(f, "Bergamo"),
            ProcType::Siena => write!(f, "Siena"),
            ProcType::Turin => write!(f, "Turin"),
            ProcType::Venice => write!(f, "Venice"),
        }
    }
}

impl FromStr for ProcType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "milan" => Ok(ProcType::Milan),
            "genoa" => Ok(ProcType::Genoa),
            "bergamo" => Ok(ProcType::Bergamo),
            "siena" => Ok(ProcType::Siena),
            "turin" => Ok(ProcType::Turin),
            "venice" => Ok(ProcType::Venice),
            _ => Err(anyhow::anyhow!(
                "Unknown processor model: {}. Valid options: milan, genoa, bergamo, siena, turin, venice",
                s
            )),
        }
    }
}

pub fn get_processor_model(report: &AttestationReport) -> Result<ProcType> {
    if report.version < 3 {
        if report.chip_id == [0u8; 64] {
            return Err(anyhow::anyhow!(
                "Attestation report version is lower than 3 and Chip ID is all 0s. \
                 Make sure MASK_CHIP_ID is set to 0 or update firmware."
            ));
        }

        if report.chip_id[8..64] == [0; 56] {
            return Ok(ProcType::Turin);
        }

        return Err(anyhow::anyhow!(
            "Attestation report could be either Milan or Genoa. \
             Update firmware to get a new version of the report."
        ));
    }

    let cpu_family = report
        .cpuid_fam_id
        .ok_or_else(|| anyhow::anyhow!("Attestation report version 3+ is missing CPU family ID"))?;

    let cpu_model = report
        .cpuid_mod_id
        .ok_or_else(|| anyhow::anyhow!("Attestation report version 3+ is missing CPU model ID"))?;

    match cpu_family {
        0x19 => match cpu_model {
            0x0..=0xF => Ok(ProcType::Milan),
            0x10..=0x1F | 0xA0..=0xAF => Ok(ProcType::Genoa),
            _ => Err(anyhow::anyhow!("Processor model not supported")),
        },
        0x1A => match cpu_model {
            0x0..=0x11 => Ok(ProcType::Turin),
            0x50..=0x57 | 0x90..=0x9F | 0xA0..=0xAF | 0xC0..=0xC7 => Ok(ProcType::Venice),
            _ => Err(anyhow::anyhow!("Processor model not supported")),
        },
        _ => Err(anyhow::anyhow!("Processor family not supported")),
    }
}

pub fn fetch_vcek_certificate(report: &AttestationReport, processor: &ProcType) -> Result<Vec<u8>> {
    if report.chip_id == [0u8; 64] {
        return Err(anyhow::anyhow!(
            "Hardware ID is all zeros in attestation report."
        ));
    }

    let hardware_id = match processor {
        ProcType::Turin | ProcType::Venice => hex::encode(&report.chip_id[0..8]),
        _ => hex::encode(report.chip_id),
    };

    let url = match processor {
        ProcType::Turin | ProcType::Venice => {
            let fmc = report.reported_tcb.fmc.ok_or_else(|| {
                anyhow::anyhow!(
                    "Turin or Venice processor attestation report must have an fmc value"
                )
            })?;
            format!(
                "{}/vcek/v1/{}/{}?fmcSPL={:02}&blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
                KDS_BASE_URL,
                processor.to_kds_url(),
                hardware_id,
                fmc,
                report.reported_tcb.bootloader,
                report.reported_tcb.tee,
                report.reported_tcb.snp,
                report.reported_tcb.microcode
            )
        }
        _ => {
            format!(
                "{}/vcek/v1/{}/{}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
                KDS_BASE_URL,
                processor.to_kds_url(),
                hardware_id,
                report.reported_tcb.bootloader,
                report.reported_tcb.tee,
                report.reported_tcb.snp,
                report.reported_tcb.microcode
            )
        }
    };

    let client = reqwest::blocking::Client::new();
    let response = client
        .get(&url)
        .send()
        .context("Failed to send request to AMD KDS for VCEK")?;

    response
        .error_for_status_ref()
        .context("AMD KDS returned error for VCEK request")?;

    let vcek_bytes = response
        .bytes()
        .context("Failed to read VCEK certificate from response")?
        .to_vec();

    Ok(vcek_bytes)
}

pub fn fetch_ca_chain(processor: &ProcType) -> Result<Chain> {
    let url = format!(
        "{}/vcek/v1/{}/cert_chain",
        KDS_BASE_URL,
        processor.to_kds_url()
    );

    let client = reqwest::blocking::Client::new();
    let response = client
        .get(&url)
        .send()
        .context("Failed to send request to AMD KDS for CA chain")?;

    response
        .error_for_status_ref()
        .context("AMD KDS returned error for CA chain request")?;

    let body = response
        .bytes()
        .context("Failed to read CA chain from response")?
        .to_vec();

    let chain = Chain::from_pem_bytes(&body).context("Failed to parse CA chain PEM")?;

    Ok(chain)
}

pub fn save_certificates(
    vcek_der: &[u8],
    chain: &Chain,
    output_dir: &Path,
    verbose: bool,
) -> Result<()> {
    fs::create_dir_all(output_dir).context(format!(
        "Failed to create output directory {}",
        output_dir.display()
    ))?;

    let ark_pem = chain.ark.to_pem().context("Failed to convert ARK to PEM")?;
    let ark_path = output_dir.join("ark.pem");
    fs::write(&ark_path, &ark_pem).context(format!(
        "Failed to write ARK certificate to {}",
        ark_path.display()
    ))?;
    if verbose {
        println!("Saved ARK certificate to {}", ark_path.display());
    }

    let ask_pem = chain.ask.to_pem().context("Failed to convert ASK to PEM")?;
    let ask_path = output_dir.join("ask.pem");
    fs::write(&ask_path, &ask_pem).context(format!(
        "Failed to write ASK certificate to {}",
        ask_path.display()
    ))?;
    if verbose {
        println!("Saved ASK certificate to {}", ask_path.display());
    }

    let vcek_cert =
        openssl::x509::X509::from_der(vcek_der).context("Failed to parse VCEK DER certificate")?;
    let vcek_pem = vcek_cert
        .to_pem()
        .context("Failed to convert VCEK to PEM")?;
    let vcek_path = output_dir.join("vcek.pem");
    fs::write(&vcek_path, &vcek_pem).context(format!(
        "Failed to write VCEK certificate to {}",
        vcek_path.display()
    ))?;
    if verbose {
        println!("Saved VCEK certificate to {}", vcek_path.display());
    }

    Ok(())
}
