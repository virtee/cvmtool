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

pub fn verify_report(report: &AttestationReport, certs_dir: &Path) -> Result<()> {
    let ark_path = find_cert_in_dir(certs_dir, "ark")?;
    let ask_path = find_cert_in_dir(certs_dir, "ask")?;
    let vcek_path = find_cert_in_dir(certs_dir, "vcek")?;

    let ark = load_certificate(&ark_path)?;
    let ask = load_certificate(&ask_path)?;
    let vcek = load_certificate(&vcek_path)?;

    (&ark, &ark)
        .verify()
        .map_err(|e| anyhow::anyhow!("ARK is not self-signed: {:?}", e))?;
    println!("ARK is self-signed");

    (&ark, &ask)
        .verify()
        .map_err(|e| anyhow::anyhow!("ASK was not signed by ARK: {:?}", e))?;
    println!("ASK was signed by ARK");

    (&ask, &vcek)
        .verify()
        .map_err(|e| anyhow::anyhow!("VCEK was not signed by ASK: {:?}", e))?;
    println!("VCEK was signed by ASK");

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
    println!("VCEK signed the attestation report");

    verify_tcb(&vcek, report)?;

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

fn verify_tcb(vcek: &Certificate, report: &AttestationReport) -> Result<()> {
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
        println!(
            "TCB bootloader matches ({})",
            report.reported_tcb.bootloader
        );
    }

    if let Some(ext) = extensions.get(&SnpOid::Tee.oid()) {
        if !check_cert_extension(ext, &report.reported_tcb.tee.to_le_bytes()) {
            return Err(anyhow::anyhow!(
                "TCB TEE mismatch: report={} vs certificate",
                report.reported_tcb.tee
            ));
        }
        println!("TCB TEE matches ({})", report.reported_tcb.tee);
    }

    if let Some(ext) = extensions.get(&SnpOid::Snp.oid()) {
        if !check_cert_extension(ext, &report.reported_tcb.snp.to_le_bytes()) {
            return Err(anyhow::anyhow!(
                "TCB SNP mismatch: report={} vs certificate",
                report.reported_tcb.snp
            ));
        }
        println!("TCB SNP matches ({})", report.reported_tcb.snp);
    }

    if let Some(ext) = extensions.get(&SnpOid::Ucode.oid()) {
        if !check_cert_extension(ext, &report.reported_tcb.microcode.to_le_bytes()) {
            return Err(anyhow::anyhow!(
                "TCB microcode mismatch: report={} vs certificate",
                report.reported_tcb.microcode
            ));
        }
        println!("TCB microcode matches ({})", report.reported_tcb.microcode);
    }

    if let Some(ext) = extensions.get(&SnpOid::HwId.oid()) {
        if !check_cert_extension(ext, &report.chip_id) {
            return Err(anyhow::anyhow!("Chip ID mismatch between report and VCEK"));
        }
        println!("Chip ID matches");
    }

    Ok(())
}
