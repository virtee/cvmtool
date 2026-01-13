// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::VerifyOptions;
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;
use tdx_quote::{Quote, VerifyingKey, pck};

pub fn parse_quote(bytes: &[u8]) -> Result<Quote> {
    Quote::from_bytes(bytes).map_err(|e| anyhow::anyhow!("Failed to parse TDX quote: {:?}", e))
}

pub fn verify_quote(quote: &Quote, certs_dir: Option<&Path>, opts: &VerifyOptions) -> Result<()> {
    let pck = if let Some(certs_dir) = certs_dir {
        verify_pck_from_dir(certs_dir, opts)?
    } else if let Ok(pck_chain_pem) = quote.pck_cert_chain() {
        let pck = pck::verify_pck_certificate_chain_pem(pck_chain_pem)
            .map_err(|e| anyhow::anyhow!("PCK certificate chain verification failed: {:?}", e))?;
        if !opts.quiet {
            println!("Embedded PCK certificate chain verified");
        }
        pck
    } else {
        return Err(anyhow::anyhow!(
            "Quote has no embedded PCK certificate chain; provide certificates with --certs-dir"
        ));
    };

    quote
        .verify_with_pck(&pck)
        .map_err(|e| anyhow::anyhow!("Quote signature verification failed: {:?}", e))?;
    if !opts.quiet {
        println!("Quote signature verified with PCK");
    }

    verify_attestation_content(quote, opts)?;

    Ok(())
}

fn verify_pck_from_dir(certs_dir: &Path, opts: &VerifyOptions) -> Result<VerifyingKey> {
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

    if !opts.quiet {
        println!(
            "PCK certificate chain verified from {}",
            certs_dir.display()
        );
    }

    Ok(pck)
}

fn verify_attestation_content(quote: &Quote, opts: &VerifyOptions) -> Result<()> {
    let body = &quote.body;

    if let Some(expected_hex) = &opts.measurement {
        let expected =
            hex::decode(expected_hex).context("Invalid hex string for expected_measurement")?;
        if expected.len() != 48 {
            return Err(anyhow::anyhow!(
                "Expected MRTD must be 48 bytes, got {}",
                expected.len()
            ));
        }
        if body.mrtd != expected.as_slice() {
            return Err(anyhow::anyhow!(
                "MRTD mismatch\n  Expected: {}\n  Got:      {}",
                hex::encode(&expected),
                hex::encode(body.mrtd)
            ));
        }
        if !opts.quiet {
            println!("MRTD matches expected value");
        }
    }

    if let Some(expected_hex) = &opts.report_data {
        let expected = hex::decode(expected_hex).context("Invalid hex string for expected_data")?;
        let expected_len = expected.len().min(64);
        let mut expected_padded = [0u8; 64];
        expected_padded[..expected_len].copy_from_slice(&expected[..expected_len]);

        if body.reportdata != expected_padded {
            return Err(anyhow::anyhow!(
                "Report data mismatch\n  Expected: {}\n  Got:      {}",
                hex::encode(expected_padded),
                hex::encode(body.reportdata)
            ));
        }
        if !opts.quiet {
            println!("Report data matches expected");
        }
    }

    if let Some(expected_hex) = &opts.tdx_rtmr0 {
        let expected =
            hex::decode(expected_hex).context("Invalid hex string for expected_rtmr0")?;
        if expected.len() != 48 {
            return Err(anyhow::anyhow!(
                "Expected RTMR0 must be 48 bytes, got {}",
                expected.len()
            ));
        }
        if body.rtmr0 != expected.as_slice() {
            return Err(anyhow::anyhow!(
                "RTMR0 mismatch\n  Expected: {}\n  Got:      {}",
                hex::encode(&expected),
                hex::encode(body.rtmr0)
            ));
        }
        if !opts.quiet {
            println!("RTMR0 matches expected value");
        }
    }

    if let Some(expected_hex) = &opts.tdx_rtmr1 {
        let expected =
            hex::decode(expected_hex).context("Invalid hex string for expected_rtmr1")?;
        if expected.len() != 48 {
            return Err(anyhow::anyhow!(
                "Expected RTMR1 must be 48 bytes, got {}",
                expected.len()
            ));
        }
        if body.rtmr1 != expected.as_slice() {
            return Err(anyhow::anyhow!(
                "RTMR1 mismatch\n  Expected: {}\n  Got:      {}",
                hex::encode(&expected),
                hex::encode(body.rtmr1)
            ));
        }
        if !opts.quiet {
            println!("RTMR1 matches expected value");
        }
    }

    if let Some(expected_hex) = &opts.tdx_rtmr2 {
        let expected =
            hex::decode(expected_hex).context("Invalid hex string for expected_rtmr2")?;
        if expected.len() != 48 {
            return Err(anyhow::anyhow!(
                "Expected RTMR2 must be 48 bytes, got {}",
                expected.len()
            ));
        }
        if body.rtmr2 != expected.as_slice() {
            return Err(anyhow::anyhow!(
                "RTMR2 mismatch\n  Expected: {}\n  Got:      {}",
                hex::encode(&expected),
                hex::encode(body.rtmr2)
            ));
        }
        if !opts.quiet {
            println!("RTMR2 matches expected value");
        }
    }

    if let Some(expected_hex) = &opts.tdx_rtmr3 {
        let expected =
            hex::decode(expected_hex).context("Invalid hex string for expected_rtmr3")?;
        if expected.len() != 48 {
            return Err(anyhow::anyhow!(
                "Expected RTMR3 must be 48 bytes, got {}",
                expected.len()
            ));
        }
        if body.rtmr3 != expected.as_slice() {
            return Err(anyhow::anyhow!(
                "RTMR3 mismatch\n  Expected: {}\n  Got:      {}",
                hex::encode(&expected),
                hex::encode(body.rtmr3)
            ));
        }
        if !opts.quiet {
            println!("RTMR3 matches expected value");
        }
    }

    if opts.policy_no_debug {
        // TDX tdattributes bit 0 is the DEBUG flag
        let debug_enabled = body.tdattributes[0] & 0x01 != 0;
        if debug_enabled {
            return Err(anyhow::anyhow!(
                "TD debug mode is enabled but --policy-no-debug was specified"
            ));
        }
        if !opts.quiet {
            println!("TD debug mode is disabled");
        }
    }

    Ok(())
}
