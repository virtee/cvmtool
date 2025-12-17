use anyhow::{Context, Result};
use std::fs;
use std::path::Path;
use tdx_quote::{Quote, VerifyingKey, pck};

pub fn parse_quote(bytes: &[u8]) -> Result<Quote> {
    Quote::from_bytes(bytes).map_err(|e| anyhow::anyhow!("Failed to parse TDX quote: {:?}", e))
}

pub fn verify_quote(quote: &Quote, certs_dir: Option<&Path>) -> Result<()> {
    let pck = if let Some(certs_dir) = certs_dir {
        verify_pck_from_dir(certs_dir)?
    } else if let Ok(pck_chain_pem) = quote.pck_cert_chain() {
        let pck = pck::verify_pck_certificate_chain_pem(pck_chain_pem)
            .map_err(|e| anyhow::anyhow!("PCK certificate chain verification failed: {:?}", e))?;
        println!("Embedded PCK certificate chain verified");
        pck
    } else {
        return Err(anyhow::anyhow!(
            "Quote has no embedded PCK certificate chain; provide certificates with --certs-dir"
        ));
    };

    quote
        .verify_with_pck(&pck)
        .map_err(|e| anyhow::anyhow!("Quote signature verification failed: {:?}", e))?;
    println!("Quote signature verified with PCK");

    Ok(())
}

fn verify_pck_from_dir(certs_dir: &Path) -> Result<VerifyingKey> {
    let pck_path = certs_dir.join("pck.pem");
    let pck_data =
        fs::read(&pck_path).with_context(|| format!("Failed to read {}", pck_path.display()))?;

    let pck_issuer_chain = certs_dir.join("pck_issuer_chain.pem");
    let pck_issuer_chain_data = fs::read(&pck_issuer_chain)
        .with_context(|| format!("Failed to read {}", pck_issuer_chain.display()))?;

    let mut chain_pem = pck_data;
    chain_pem.extend_from_slice(&pck_issuer_chain_data);

    let pck = pck::verify_pck_certificate_chain_pem(chain_pem)
        .map_err(|e| anyhow::anyhow!("PCK certificate chain verification failed: {:?}", e))?;

    println!(
        "PCK certificate chain verified from {}",
        certs_dir.display()
    );

    Ok(pck)
}
