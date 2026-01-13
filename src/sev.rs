// SPDX-License-Identifier: AGPL-3.0-or-later

use crate::VerifyOptions;
use anyhow::{Context, Result};
use asn1_rs::{Oid, oid};
use openssl::{ecdsa::EcdsaSig, sha::Sha384};
use sev::certs::snp::{Certificate, Verifiable};
use sev::firmware::guest::AttestationReport;
use sev::parser::ByteParser;
use std::fs;
use std::path::{Path, PathBuf};
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::{FromDer, X509Extension};

enum SnpOid {
    BootLoader,
    Tee,
    Snp,
    Ucode,
    HwId,
}

impl SnpOid {
    fn oid(&self) -> Oid<'static> {
        match self {
            SnpOid::BootLoader => oid!(1.3.6.1.4.1.3704.1.3.1),
            SnpOid::Tee => oid!(1.3.6.1.4.1.3704.1.3.2),
            SnpOid::Snp => oid!(1.3.6.1.4.1.3704.1.3.3),
            SnpOid::Ucode => oid!(1.3.6.1.4.1.3704.1.3.8),
            SnpOid::HwId => oid!(1.3.6.1.4.1.3704.1.4),
        }
    }
}

pub fn parse_report(bytes: &[u8]) -> Result<AttestationReport> {
    AttestationReport::from_bytes(bytes)
        .map_err(|e| anyhow::anyhow!("Failed to parse SEV report: {:?}", e))
}

pub fn verify_report(
    report: &AttestationReport,
    certs_dir: &Path,
    opts: &VerifyOptions,
) -> Result<()> {
    let ark_path = find_cert_in_dir(certs_dir, "ark")?;
    let ask_path = find_cert_in_dir(certs_dir, "ask")?;
    let vcek_path = find_cert_in_dir(certs_dir, "vcek")?;

    let ark = load_certificate(&ark_path)?;
    let ask = load_certificate(&ask_path)?;
    let vcek = load_certificate(&vcek_path)?;

    (&ark, &ark)
        .verify()
        .map_err(|e| anyhow::anyhow!("ARK is not self-signed: {:?}", e))?;
    if !opts.quiet {
        println!("ARK is self-signed");
    }

    (&ark, &ask)
        .verify()
        .map_err(|e| anyhow::anyhow!("ASK was not signed by ARK: {:?}", e))?;
    if !opts.quiet {
        println!("ASK was signed by ARK");
    }

    (&ask, &vcek)
        .verify()
        .map_err(|e| anyhow::anyhow!("VCEK was not signed by ASK: {:?}", e))?;
    if !opts.quiet {
        println!("VCEK was signed by ASK");
    }

    let vcek_pubkey = vcek
        .public_key()
        .context("Failed to get public key from VCEK")?
        .ec_key()
        .context("Failed to convert VCEK public key to EC key")?;

    let signature = EcdsaSig::try_from(&report.signature)
        .context("Failed to get ECDSA signature from attestation report")?;

    let report_bytes = report.to_bytes()?;
    let signed_bytes = &report_bytes[0x0..0x2A0];

    let mut hasher = Sha384::new();
    hasher.update(signed_bytes);
    let digest = hasher.finish();

    if !signature
        .verify(&digest, vcek_pubkey.as_ref())
        .context("Failed to verify signature")?
    {
        return Err(anyhow::anyhow!("VCEK did not sign the attestation report"));
    }
    if !opts.quiet {
        println!("VCEK signed the attestation report");
    }

    verify_tcb(&vcek, report, opts)?;

    verify_attestation_content(report, opts)?;

    Ok(())
}

fn find_cert_in_dir(dir: &Path, name: &str) -> Result<PathBuf> {
    let pem_path = dir.join(format!("{name}.pem"));
    if pem_path.exists() {
        return Ok(pem_path);
    }
    let der_path = dir.join(format!("{name}.der"));
    if der_path.exists() {
        return Ok(der_path);
    }
    Err(anyhow::anyhow!(
        "{name} certificate not found in {}",
        dir.display()
    ))
}

fn load_certificate(path: &Path) -> Result<Certificate> {
    let data = fs::read(path).context(format!("Failed to read certificate {}", path.display()))?;

    let is_pem = path.extension().map(|ext| ext == "pem").unwrap_or(false);

    if is_pem {
        Certificate::from_pem(&data).context("Failed to parse PEM certificate")
    } else {
        Certificate::from_der(&data).context("Failed to parse DER certificate")
    }
}

fn check_cert_extension(extension: &X509Extension, expected: &[u8]) -> bool {
    let value = extension.value;
    match value.first() {
        Some(0x02) => {
            // ASN.1 Integer
            if value.len() < 3 {
                return false;
            }
            let length = value[1] as usize;
            if length != 1 && length != 2 {
                return false;
            }
            value.last() == expected.first()
        }
        Some(0x04) => {
            // ASN.1 Octet String
            if value.len() < 3 || value[1] != 0x40 {
                return false;
            }
            &value[2..] == expected
        }
        _ => {
            // Legacy format (raw bytes without ASN.1 encoding)
            if value.len() == 0x40 && expected.len() == 0x40 {
                value == expected
            } else {
                false
            }
        }
    }
}

fn verify_tcb(vcek: &Certificate, report: &AttestationReport, opts: &VerifyOptions) -> Result<()> {
    let vcek_der = vcek.to_der().context("Failed to convert VCEK to DER")?;
    let (_, vcek_x509) =
        X509Certificate::from_der(&vcek_der).context("Failed to parse VCEK as X509")?;

    let extensions = vcek_x509
        .extensions_map()
        .context("Failed to get VCEK extensions")?;

    if let Some(ext) = extensions.get(&SnpOid::BootLoader.oid()) {
        if !check_cert_extension(ext, &report.reported_tcb.bootloader.to_le_bytes()) {
            return Err(anyhow::anyhow!(
                "TCB bootloader mismatch: report={} vs certificate",
                report.reported_tcb.bootloader
            ));
        }
        if !opts.quiet {
            println!(
                "TCB bootloader matches ({})",
                report.reported_tcb.bootloader
            );
        }
    }

    if let Some(ext) = extensions.get(&SnpOid::Tee.oid()) {
        if !check_cert_extension(ext, &report.reported_tcb.tee.to_le_bytes()) {
            return Err(anyhow::anyhow!(
                "TCB TEE mismatch: report={} vs certificate",
                report.reported_tcb.tee
            ));
        }
        if !opts.quiet {
            println!("TCB TEE matches ({})", report.reported_tcb.tee);
        }
    }

    if let Some(ext) = extensions.get(&SnpOid::Snp.oid()) {
        if !check_cert_extension(ext, &report.reported_tcb.snp.to_le_bytes()) {
            return Err(anyhow::anyhow!(
                "TCB SNP mismatch: report={} vs certificate",
                report.reported_tcb.snp
            ));
        }
        if !opts.quiet {
            println!("TCB SNP matches ({})", report.reported_tcb.snp);
        }
    }

    if let Some(ext) = extensions.get(&SnpOid::Ucode.oid()) {
        if !check_cert_extension(ext, &report.reported_tcb.microcode.to_le_bytes()) {
            return Err(anyhow::anyhow!(
                "TCB microcode mismatch: report={} vs certificate",
                report.reported_tcb.microcode
            ));
        }
        if !opts.quiet {
            println!("TCB microcode matches ({})", report.reported_tcb.microcode);
        }
    }

    if let Some(ext) = extensions.get(&SnpOid::HwId.oid()) {
        if !check_cert_extension(ext, &report.chip_id) {
            return Err(anyhow::anyhow!("Chip ID mismatch between report and VCEK"));
        }
        if !opts.quiet {
            println!("Chip ID matches");
        }
    }

    Ok(())
}

fn verify_attestation_content(report: &AttestationReport, opts: &VerifyOptions) -> Result<()> {
    if let Some(expected_hex) = &opts.measurement {
        let expected =
            hex::decode(expected_hex).context("Invalid hex string for expected_measurement")?;
        if expected.len() != 48 {
            return Err(anyhow::anyhow!(
                "Expected measurement must be 48 bytes, got {}",
                expected.len()
            ));
        }
        if report.measurement != expected.as_slice() {
            return Err(anyhow::anyhow!(
                "Measurement mismatch\n  Expected: {}\n  Got:      {}",
                hex::encode(&expected),
                hex::encode(report.measurement)
            ));
        }
        if !opts.quiet {
            println!("Measurement matches expected value");
        }
    }

    if let Some(expected_hex) = &opts.report_data {
        let expected = hex::decode(expected_hex).context("Invalid hex string for expected_data")?;
        let expected_len = expected.len().min(64);
        let mut expected_padded = [0u8; 64];
        expected_padded[..expected_len].copy_from_slice(&expected[..expected_len]);

        if report.report_data != expected_padded {
            return Err(anyhow::anyhow!(
                "Report data mismatch\n  Expected: {}\n  Got:      {}",
                hex::encode(expected_padded),
                hex::encode(report.report_data)
            ));
        }
        if !opts.quiet {
            println!("Report data matches expected");
        }
    }

    if let Some(expected_hex) = &opts.sev_host_data {
        let expected =
            hex::decode(expected_hex).context("Invalid hex string for expected_host_data")?;
        if expected.len() != 32 {
            return Err(anyhow::anyhow!(
                "Expected host_data must be 32 bytes, got {}",
                expected.len()
            ));
        }
        if report.host_data != expected.as_slice() {
            return Err(anyhow::anyhow!(
                "Host data mismatch\n  Expected: {}\n  Got:      {}",
                hex::encode(&expected),
                hex::encode(report.host_data)
            ));
        }
        if !opts.quiet {
            println!("Host data matches expected value");
        }
    }

    if let Some(expected_hex) = &opts.sev_id_key_digest {
        let expected =
            hex::decode(expected_hex).context("Invalid hex string for expected_id_key_digest")?;
        if expected.len() != 48 {
            return Err(anyhow::anyhow!(
                "Expected id_key_digest must be 48 bytes, got {}",
                expected.len()
            ));
        }
        if report.id_key_digest != expected.as_slice() {
            return Err(anyhow::anyhow!(
                "ID key digest mismatch\n  Expected: {}\n  Got:      {}",
                hex::encode(&expected),
                hex::encode(report.id_key_digest)
            ));
        }
        if !opts.quiet {
            println!("ID key digest matches expected value");
        }
    }

    if opts.policy_no_debug && report.policy.debug_allowed() {
        return Err(anyhow::anyhow!(
            "Debug mode is enabled but --require-no-debug was specified"
        ));
    }
    if opts.policy_no_debug && !opts.quiet {
        println!("Debug mode is disabled");
    }

    if opts.policy_no_migration && report.policy.migrate_ma_allowed() {
        return Err(anyhow::anyhow!(
            "Migration is allowed but --require-no-migration was specified"
        ));
    }
    if opts.policy_no_migration && !opts.quiet {
        println!("Migration is disabled");
    }

    if let Some((min_bootloader, min_tee, min_snp, min_microcode)) = opts.sev_min_tcb {
        if report.reported_tcb.bootloader < min_bootloader {
            return Err(anyhow::anyhow!(
                "TCB bootloader version {} is below minimum {}",
                report.reported_tcb.bootloader,
                min_bootloader
            ));
        }
        if report.reported_tcb.tee < min_tee {
            return Err(anyhow::anyhow!(
                "TCB TEE version {} is below minimum {}",
                report.reported_tcb.tee,
                min_tee
            ));
        }
        if report.reported_tcb.snp < min_snp {
            return Err(anyhow::anyhow!(
                "TCB SNP version {} is below minimum {}",
                report.reported_tcb.snp,
                min_snp
            ));
        }
        if report.reported_tcb.microcode < min_microcode {
            return Err(anyhow::anyhow!(
                "TCB microcode version {} is below minimum {}",
                report.reported_tcb.microcode,
                min_microcode
            ));
        }
        if !opts.quiet {
            println!(
                "TCB versions meet minimum requirements ({}:{}:{}:{})",
                min_bootloader, min_tee, min_snp, min_microcode
            );
        }
    }

    Ok(())
}
