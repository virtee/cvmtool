// SPDX-License-Identifier: AGPL-3.0-or-later

use assert_cmd::{Command, cargo::cargo_bin_cmd};
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

mod verify {
    use super::*;

    #[test]
    fn sev_with_real_certs() {
        let certs_dir = std::path::Path::new("tests/fixtures/sev-certs");
        let report_path = std::path::Path::new("tests/fixtures/sev.report");

        cvmtool()
            .args(["verify", "-f", "sev"])
            .arg(report_path)
            .args(["--certs-dir"])
            .arg(certs_dir)
            .assert()
            .success()
            .stdout(predicate::str::contains("ARK is self-signed"))
            .stdout(predicate::str::contains("ASK was signed by ARK"))
            .stdout(predicate::str::contains("VCEK was signed by ASK"))
            .stdout(predicate::str::contains("TCB bootloader matches"))
            .stdout(predicate::str::contains("TCB TEE matches"))
            .stdout(predicate::str::contains("TCB SNP matches"))
            .stdout(predicate::str::contains("TCB microcode matches"))
            .stdout(predicate::str::contains(
                "VCEK signed the attestation report",
            ))
            .stdout(predicate::str::contains("Verified SEV attestation report"));
    }

    #[test]
    fn sev_with_fake_certs() {
        let certs_dir = std::path::Path::new("tests/fixtures/sev-fake-certs");
        let report_path = std::path::Path::new("tests/fixtures/sev.report");

        cvmtool()
            .args(["verify", "-f", "sev"])
            .arg(report_path)
            .args(["--certs-dir"])
            .arg(certs_dir)
            .assert()
            .failure()
            .stdout(predicate::str::contains("ARK is self-signed"))
            .stdout(predicate::str::contains("ASK was signed by ARK"))
            .stdout(predicate::str::contains("VCEK was signed by ASK"))
            .stderr(predicate::str::contains(
                "Error: VCEK did not sign the attestation report",
            ));
    }

    #[test]
    fn with_unsupported_format_fails() {
        let temp = TempDir::new().unwrap();
        let report_path = temp.path().join("report.bin");
        fs::write(&report_path, [0u8; 100]).unwrap();

        cvmtool()
            .args(["verify", "-f", "unsupported_format"])
            .arg(&report_path)
            .assert()
            .failure()
            .stderr(predicate::str::contains("Unsupported format"));
    }

    #[test]
    fn nonexistent_file_fails() {
        cvmtool()
            .args(["verify", "-f", "sev", "/nonexistent/path/to/report.bin"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("Failed to read report file"));
    }

    #[test]
    fn sev_invalid_report_fails() {
        let temp = TempDir::new().unwrap();
        let report_path = temp.path().join("report.bin");
        fs::write(&report_path, [0u8; 100]).unwrap();

        cvmtool()
            .args(["verify", "-f", "sev"])
            .arg(&report_path)
            .assert()
            .failure()
            .stderr(predicate::str::contains("Failed to parse SEV report"));
    }

    #[test]
    fn tdx_invalid_quote_fails() {
        let temp = TempDir::new().unwrap();
        let quote_path = temp.path().join("quote.bin");
        fs::write(&quote_path, [0u8; 100]).unwrap();

        cvmtool()
            .args(["verify", "-f", "tdx"])
            .arg(&quote_path)
            .assert()
            .failure()
            .stderr(predicate::str::contains("Failed to parse TDX quote"));
    }

    #[test]
    fn sev_missing_certs_fails() {
        let report_path = std::path::Path::new("tests/fixtures/sev.report");

        let temp = TempDir::new().unwrap();
        let certs_dir = temp.path().join("certs");
        fs::create_dir(&certs_dir).unwrap();

        cvmtool()
            .args(["verify", "-f", "sev"])
            .arg(report_path)
            .args(["--certs-dir"])
            .arg(&certs_dir)
            .assert()
            .failure()
            .stderr(predicate::str::contains("ark certificate not found"));
    }

    #[test]
    fn tdx_with_embedded_chain() {
        let quote_path = std::path::Path::new("tests/fixtures/tdx.report");

        cvmtool()
            .args(["verify", "-f", "tdx"])
            .arg(quote_path)
            .assert()
            .success()
            .stdout(predicate::str::contains(
                "Embedded PCK certificate chain verified",
            ))
            .stdout(predicate::str::contains(
                "Quote signature verified with PCK",
            ))
            .stdout(predicate::str::contains("Verified TDX attestation report"));
    }

    #[test]
    fn tdx_with_real_certs() {
        let certs_dir = std::path::Path::new("tests/fixtures/tdx-certs");
        let quote_path = std::path::Path::new("tests/fixtures/tdx.report");

        cvmtool()
            .args(["verify", "-f", "tdx"])
            .arg(quote_path)
            .args(["--certs-dir"])
            .arg(certs_dir)
            .assert()
            .success()
            .stdout(predicate::str::contains("PCK certificate chain verified"))
            .stdout(predicate::str::contains(
                "Quote signature verified with PCK",
            ))
            .stdout(predicate::str::contains("Verified TDX attestation report"));
    }

    // Unlike SEV, the tdx-quote library embeds Intel's real root CA and always
    // verifies the chain against it. Fake certificates will fail chain verification
    // (not signature verification) because they aren't signed by Intel's root CA.
    #[test]
    fn tdx_with_fake_certs() {
        let certs_dir = std::path::Path::new("tests/fixtures/tdx-fake-certs");
        let quote_path = std::path::Path::new("tests/fixtures/tdx.report");

        cvmtool()
            .args(["verify", "-f", "tdx"])
            .arg(quote_path)
            .args(["--certs-dir"])
            .arg(certs_dir)
            .assert()
            .failure()
            .stderr(predicate::str::contains(
                "PCK certificate chain verification failed",
            ));
    }

    #[test]
    fn tdx_missing_certs_fails() {
        let quote_path = std::path::Path::new("tests/fixtures/tdx.report");

        let temp = TempDir::new().unwrap();
        let certs_dir = temp.path().join("certs");
        fs::create_dir(&certs_dir).unwrap();

        cvmtool()
            .args(["verify", "-f", "tdx"])
            .arg(quote_path)
            .args(["--certs-dir"])
            .arg(&certs_dir)
            .assert()
            .failure()
            .stderr(predicate::str::contains("Failed to read"));
    }

    #[test]
    fn tdx_wrong_measurement_fails() {
        let quote_path = std::path::Path::new("tests/fixtures/tdx.report");
        // 48 bytes of zeros - almost certainly won't match real MRTD
        let wrong_measurement = "0".repeat(96);

        cvmtool()
            .args(["verify", "-f", "tdx"])
            .arg(quote_path)
            .args(["--measurement", &wrong_measurement])
            .assert()
            .failure()
            .stderr(predicate::str::contains("MRTD mismatch"));
    }

    #[test]
    fn tdx_wrong_nonce_fails() {
        let quote_path = std::path::Path::new("tests/fixtures/tdx.report");
        // Use a nonce that won't match
        let wrong_nonce = "deadbeef";

        cvmtool()
            .args(["verify", "-f", "tdx"])
            .arg(quote_path)
            .args(["--report-data", wrong_nonce])
            .assert()
            .failure()
            .stderr(predicate::str::contains("Report data mismatch"));
    }

    #[test]
    fn tdx_require_no_debug_passes() {
        let quote_path = std::path::Path::new("tests/fixtures/tdx.report");

        cvmtool()
            .args(["verify", "-f", "tdx"])
            .arg(quote_path)
            .args(["--policy-no-debug"])
            .assert()
            .success()
            .stdout(predicate::str::contains("TD debug mode is disabled"));
    }

    #[test]
    fn sev_wrong_measurement_fails() {
        let certs_dir = std::path::Path::new("tests/fixtures/sev-certs");
        let report_path = std::path::Path::new("tests/fixtures/sev.report");

        // 48 bytes of zeros - won't match real measurement
        let wrong_measurement = "0".repeat(96);

        cvmtool()
            .args(["verify", "-f", "sev"])
            .arg(report_path)
            .args(["--certs-dir"])
            .arg(certs_dir)
            .args(["--measurement", &wrong_measurement])
            .assert()
            .failure()
            .stderr(predicate::str::contains("Measurement mismatch"));
    }

    #[test]
    fn sev_require_no_debug_passes() {
        let certs_dir = std::path::Path::new("tests/fixtures/sev-certs");
        let report_path = std::path::Path::new("tests/fixtures/sev.report");

        cvmtool()
            .args(["verify", "-f", "sev"])
            .arg(report_path)
            .args(["--certs-dir"])
            .arg(certs_dir)
            .args(["--policy-no-debug"])
            .assert()
            .success()
            .stdout(predicate::str::contains("Debug mode is disabled"));
    }

    #[test]
    fn sev_min_tcb_too_high_fails() {
        let certs_dir = std::path::Path::new("tests/fixtures/sev-certs");
        let report_path = std::path::Path::new("tests/fixtures/sev.report");

        // Set minimum TCB versions very high - should fail
        cvmtool()
            .args(["verify", "-f", "sev"])
            .arg(report_path)
            .args(["--certs-dir"])
            .arg(certs_dir)
            .args(["--sev-min-tcb", "255:255:255:255"])
            .assert()
            .failure()
            .stderr(predicate::str::contains("is below minimum"));
    }

    #[test]
    fn sev_correct_measurement_passes() {
        let certs_dir = std::path::Path::new("tests/fixtures/sev-certs");
        let report_path = std::path::Path::new("tests/fixtures/sev.report");

        let measurement = "80422fe2dc2aa605d20ae4d74eaca02930281d59646a819cf8f11d9842d1c48f48df72439bcdf389cbe71ffa754ab3dc";

        cvmtool()
            .args(["verify", "-f", "sev"])
            .arg(report_path)
            .args(["--certs-dir"])
            .arg(certs_dir)
            .args(["--measurement", measurement])
            .assert()
            .success()
            .stdout(predicate::str::contains(
                "Measurement matches expected value",
            ));
    }

    #[test]
    fn tdx_correct_measurement_passes() {
        let quote_path = std::path::Path::new("tests/fixtures/tdx.report");

        let mrtd = "d2567292906f19471ed375e2c1f8eb836a719ceb3a8756b9ad21db01552ff0f9ac8e194dccb65a3dbda4c7ee2c4ded9f";

        cvmtool()
            .args(["verify", "-f", "tdx"])
            .arg(quote_path)
            .args(["--measurement", mrtd])
            .assert()
            .success()
            .stdout(predicate::str::contains("MRTD matches expected value"));
    }
}

fn cvmtool() -> Command {
    cargo_bin_cmd!("cvmtool")
}
