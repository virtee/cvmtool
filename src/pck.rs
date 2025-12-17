use anyhow::{Context, Result};
use percent_encoding::percent_decode_str;
use std::fs;
use std::path::Path;
use std::process::Command;

const INTEL_PCS_URL: &str = "https://api.trustedservices.intel.com/sgx/certification/v4/pckcert";

#[derive(Debug)]
pub struct PlatformInfo {
    pub encrypted_ppid: String,
    pub pce_id: String,
    pub cpu_svn: String,
    pub pce_svn: String,
    pub qe_id: String,
}

#[derive(Debug)]
pub struct PckCertificateResponse {
    pub pck_cert: String,
    pub issuer_chain: String,
    pub fmspc: String,
    pub tcbm: String,
    pub ca_type: String,
}

pub fn get_platform_info() -> Result<PlatformInfo> {
    let output = Command::new("PCKIDRetrievalTool")
        .args(["-f", "/dev/stdout"])
        .output()
        .context("Failed to run PCKIDRetrievalTool. Is it installed?")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!("PCKIDRetrievalTool failed: {}", stderr));
    }

    let stdout =
        String::from_utf8(output.stdout).context("PCKIDRetrievalTool output is not valid UTF-8")?;

    parse_pckid_csv(&stdout)
}

fn parse_pckid_csv(csv_data: &str) -> Result<PlatformInfo> {
    let line = csv_data
        .lines()
        .find(|line| !line.is_empty() && !line.starts_with('#'))
        .context("No data found in PCKIDRetrievalTool output")?;

    let parts: Vec<&str> = line.split(',').collect();
    if parts.len() < 5 {
        return Err(anyhow::anyhow!(
            "Invalid PCKIDRetrievalTool output format: expected 5 fields, got {}",
            parts.len()
        ));
    }

    Ok(PlatformInfo {
        encrypted_ppid: parts[0].to_string(),
        pce_id: parts[1].to_string(),
        cpu_svn: parts[2].to_string(),
        pce_svn: parts[3].to_string(),
        qe_id: parts[4].to_string(),
    })
}

pub fn fetch_pck_certificate(platform_info: &PlatformInfo) -> Result<PckCertificateResponse> {
    let url = format!(
        "{}?encrypted_ppid={}&cpusvn={}&pcesvn={}&pceid={}",
        INTEL_PCS_URL,
        platform_info.encrypted_ppid,
        platform_info.cpu_svn,
        platform_info.pce_svn,
        platform_info.pce_id
    );

    let client = reqwest::blocking::Client::new();
    let response = client
        .get(&url)
        .send()
        .context("Failed to send request to Intel PCS")?;

    response
        .error_for_status_ref()
        .context("Intel PCS returned error")?;

    let issuer_chain_encoded = response
        .headers()
        .get("SGX-PCK-Certificate-Issuer-Chain")
        .context("Missing SGX-PCK-Certificate-Issuer-Chain header")?
        .to_str()
        .context("Invalid SGX-PCK-Certificate-Issuer-Chain header")?;

    let issuer_chain = percent_decode_str(issuer_chain_encoded)
        .decode_utf8()
        .context("Failed to URL-decode issuer chain")?
        .to_string();

    let fmspc = response
        .headers()
        .get("SGX-FMSPC")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let tcbm = response
        .headers()
        .get("SGX-TCBm")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let ca_type = response
        .headers()
        .get("SGX-PCK-Certificate-CA-Type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let pck_cert = response
        .text()
        .context("Failed to read PCK certificate from response")?;

    Ok(PckCertificateResponse {
        pck_cert,
        issuer_chain,
        fmspc,
        tcbm,
        ca_type,
    })
}

pub fn save_certificates(response: &PckCertificateResponse, output_dir: &Path) -> Result<()> {
    fs::create_dir_all(output_dir).context(format!(
        "Failed to create output directory {}",
        output_dir.display()
    ))?;

    let pck_path = output_dir.join("pck.pem");
    fs::write(&pck_path, &response.pck_cert).context(format!(
        "Failed to write PCK certificate to {}",
        pck_path.display()
    ))?;
    eprintln!("Saved PCK certificate to {}", pck_path.display());

    let issuer_chain_path = output_dir.join("pck_issuer_chain.pem");
    fs::write(&issuer_chain_path, &response.issuer_chain).context(format!(
        "Failed to write issuer chain to {}",
        issuer_chain_path.display()
    ))?;
    eprintln!("Saved issuer chain to {}", issuer_chain_path.display());

    let metadata_path = output_dir.join("pck_metadata.txt");
    let metadata = format!(
        "FMSPC: {}\nTCBm: {}\nCA-Type: {}\n",
        response.fmspc, response.tcbm, response.ca_type
    );
    fs::write(&metadata_path, &metadata).context(format!(
        "Failed to write metadata to {}",
        metadata_path.display()
    ))?;
    eprintln!("Saved metadata to {}", metadata_path.display());

    Ok(())
}
