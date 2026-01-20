//! API test runner for testing against /test/... endpoints
//!
//! Run with: cargo run --example test_api --release

use l3::api::{ChallengeTestRunner, ChallengeType, CryptoApiClient};
use std::io::{self, Write};

type TestCase = (
    ChallengeType,
    &'static str,
    fn(&ChallengeTestRunner) -> l3::api::ChallengeTestResult,
);

fn main() {
    println!("================================================================================");
    println!("L3 - Crypto Challenge API Test (test endpoints only)");
    println!("================================================================================\n");
    println!("NOTE: Run with --release for much faster performance!\n");

    let client = CryptoApiClient::new();

    print!("Connecting to API... ");
    io::stdout().flush().unwrap();
    match client.test_connection() {
        Ok(resp) => println!("OK ({})", resp.status),
        Err(e) => {
            println!("FAILED: {}", e);
            std::process::exit(1);
        }
    }
    println!();

    let runner = ChallengeTestRunner::with_client(client);

    let tests: Vec<TestCase> = vec![
        (ChallengeType::Modp, "ModP (prime field DH)", |r| {
            r.run_modp_tests()
        }),
        (ChallengeType::F2m, "F2m (binary field DH)", |r| {
            r.run_f2m_tests()
        }),
        (ChallengeType::Fpk, "Fpk (extension field DH)", |r| {
            r.run_fpk_tests()
        }),
        (ChallengeType::Ecp, "ECP (EC over prime field)", |r| {
            r.run_ecp_tests()
        }),
        (ChallengeType::Ec2m, "EC2m (EC over binary field)", |r| {
            r.run_ec2m_tests()
        }),
        (ChallengeType::Ecpk, "ECPk (EC over extension field)", |r| {
            r.run_ecpk_tests()
        }),
    ];

    let mut results = Vec::new();

    for (challenge_type, name, test_fn) in &tests {
        println!(
            "--------------------------------------------------------------------------------"
        );
        println!("[{:?}] {}", challenge_type, name);
        println!(
            "--------------------------------------------------------------------------------"
        );

        let start = std::time::Instant::now();
        let result = test_fn(&runner);
        let elapsed = start.elapsed();

        let dh_sym = if result.dh_success { "PASS" } else { "FAIL" };
        let sig_sym = if result.signature_success {
            "PASS"
        } else {
            "FAIL"
        };

        println!(
            "  DH:  {} | Signature: {} | Time: {:.2}s",
            dh_sym,
            sig_sym,
            elapsed.as_secs_f64()
        );

        if let Some(ref e) = result.dh_error {
            println!("  DH Error: {}", e);
        }
        if let Some(ref e) = result.signature_error {
            println!("  Sig Error: {}", e);
        }
        println!();

        results.push(result);
    }

    // Summary
    println!("================================================================================");
    println!("SUMMARY");
    println!("================================================================================");

    let mut total_pass = 0;
    let mut total_fail = 0;

    for result in &results {
        let dh = if result.dh_success {
            total_pass += 1;
            "PASS"
        } else {
            total_fail += 1;
            "FAIL"
        };
        let sig = if result.signature_success {
            total_pass += 1;
            "PASS"
        } else {
            total_fail += 1;
            "FAIL"
        };
        println!("  {:?}: DH={}, Sig={}", result.challenge_type, dh, sig);
    }

    println!("--------------------------------------------------------------------------------");
    println!("Total: {} PASS, {} FAIL", total_pass, total_fail);
    println!("================================================================================");

    if total_fail > 0 {
        std::process::exit(1);
    }
}
