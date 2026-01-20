//! Submit Challenge Runner
//!
//! This program runs the submit challenge for all challenge types (modp, f2m, fpk, ecp, ec2m, ecpk)
//! and logs the results with timings to submit_results.json.
//!
//! Run with: cargo run --release
//!
//! The program will:
//! 1. Connect to the API
//! 2. For each challenge type:
//!    - Start a submit session
//!    - Verify the server's signature (skip if poisoned)
//!    - Generate own keys and compute shared secret
//!    - Submit the solution
//!    - Record the session ID and timing
//! 3. Save results to submit_results.json

use l3::api::{ChallengeType, CryptoApiClient, SubmitChallengeRunner};
use serde_json::json;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Write};
use std::path::Path;
type LoadResults = (
    HashMap<String, serde_json::Value>,
    HashMap<String, f64>,
    HashMap<String, String>,
    HashMap<String, f64>,
);

fn main() {
    println!("================================================================================");
    println!("L3 - Submit Challenge Runner");
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

    let runner = SubmitChallengeRunner::with_client(client);

    let challenge_types = vec![
        (ChallengeType::Modp, "ModP (prime field DH)"),
        (ChallengeType::F2m, "F2m (binary field DH)"),
        (ChallengeType::Fpk, "Fpk (extension field DH)"),
        (ChallengeType::Ecp, "ECP (EC over prime field)"),
        (ChallengeType::Ec2m, "EC2m (EC over binary field)"),
        (ChallengeType::Ecpk, "ECPk (EC over extension field)"),
    ];

    // Load existing results if available
    let (mut results, mut timings, mut fastest_sessions, mut min_times) = load_existing_results();

    let mut updated_any = false;

    for (challenge_type, name) in &challenge_types {
        println!(
            "--------------------------------------------------------------------------------"
        );
        println!("[{:?}] {}", challenge_type, name);
        println!(
            "--------------------------------------------------------------------------------"
        );

        let result = runner.run_submit(*challenge_type, 8); // Max 8 retries

        // Get the timing from the fastest successful attempt
        let attempt_time_secs = result.attempt_time.unwrap_or(0.0);

        println!(
            "  Status: {}",
            if result.success {
                "✓ SUCCESS"
            } else {
                "✗ FAILED"
            }
        );
        if let Some(ref session_id) = result.session_id {
            println!("  Session ID: {}", session_id);
        }
        if let Some(ref error) = result.error {
            println!("  Error Details: {}", error);
        }
        if result.success && result.attempt_time.is_some() {
            println!("  Fastest Attempt Time: {:.3}s", attempt_time_secs);
        }
        if result.poisoned {
            println!("  Poisoned: YES (signature verification failed)");
        }
        println!();

        // Record timing
        let challenge_key = format!("{:?}", challenge_type);

        // Only save successful attempts, and only if faster than existing
        if result.success
            && let Some(ref session_id) = result.session_id
        {
            let is_faster = !min_times.contains_key(&challenge_key)
                || attempt_time_secs < min_times[&challenge_key];

            if is_faster {
                println!(
                    "  ⚡ NEW FASTEST TIME! (previous: {:.3}s)",
                    min_times.get(&challenge_key).unwrap_or(&f64::MAX)
                );

                min_times.insert(challenge_key.clone(), attempt_time_secs);
                fastest_sessions.insert(challenge_key.clone(), session_id.clone());
                timings.insert(challenge_key.clone(), attempt_time_secs);

                results.insert(
                    challenge_key,
                    json!({
                        "success": true,
                        "session_id": session_id.clone(),
                        "time_seconds": attempt_time_secs,
                    }),
                );

                updated_any = true;
            } else {
                println!(
                    "  ⏱️  Not faster than existing record ({:.3}s)",
                    min_times[&challenge_key]
                );
            }
        }
    }

    // Summary
    println!("================================================================================");
    println!("SUMMARY");
    println!("================================================================================");

    let mut total_success = 0;
    let mut total_failed = 0;

    for (challenge_type, name) in &challenge_types {
        let key = format!("{:?}", challenge_type);
        if let Some(data) = results.get(&key) {
            if data["success"].as_bool().unwrap_or(false) {
                total_success += 1;
                let session_id = data["session_id"].as_str().unwrap_or("N/A").to_string();
                let time = data["time_seconds"].as_f64().unwrap_or(0.0);
                println!("  {:20} | SUCCESS | {} | {:.3}s", name, session_id, time);
            } else if data["poisoned"].as_bool().unwrap_or(false) {
                total_failed += 1;
                println!("  {:20} | POISONED (all retries)", name);
            } else {
                total_failed += 1;
                println!("  {:20} | FAILED", name);
            }
        }
    }

    println!("--------------------------------------------------------------------------------");
    println!("Total: {} SUCCESS, {} FAILED", total_success, total_failed);
    println!("================================================================================\n");

    // Save results to JSON file only if we have updates
    if updated_any || !Path::new("submit_results.json").exists() {
        println!("Writing results to submit_results.json...");

        let output = json!({
            "timestamp": chrono::Local::now().to_rfc3339(),
            "summary": {
                "total_success": total_success,
                "total_failed": total_failed,
                "fastest_sessions": fastest_sessions,
            },
            "results": results,
            "timings": timings,
        });

        if let Err(e) = write_results_file(&output) {
            eprintln!("Error writing results file: {}", e);
            std::process::exit(1);
        }

        println!("Results saved successfully!\n");
    } else {
        println!("No faster times found, keeping existing results.\n");
    }

    // Print session IDs to submit
    if !fastest_sessions.is_empty() {
        println!(
            "================================================================================"
        );
        println!("SUCCESSFUL SESSION IDs TO SUBMIT");
        println!(
            "================================================================================"
        );
        for (challenge_type, session_id) in &fastest_sessions {
            println!("  {}: {}", challenge_type, session_id);
        }
        println!(
            "================================================================================\n"
        );
    }
}

fn load_existing_results() -> LoadResults {
    if !Path::new("submit_results.json").exists() {
        return (
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
        );
    }

    match std::fs::read_to_string("submit_results.json") {
        Ok(content) => match serde_json::from_str::<serde_json::Value>(&content) {
            Ok(data) => {
                let mut results = HashMap::new();
                let mut timings = HashMap::new();
                let mut fastest_sessions = HashMap::new();
                let mut min_times = HashMap::new();

                if let Some(existing_results) = data["results"].as_object() {
                    for (key, value) in existing_results {
                        results.insert(key.clone(), value.clone());

                        if let Some(time) = value["time_seconds"].as_f64() {
                            timings.insert(key.clone(), time);
                            min_times.insert(key.clone(), time);
                        }

                        if let Some(session_id) = value["session_id"].as_str() {
                            fastest_sessions.insert(key.clone(), session_id.to_string());
                        }
                    }
                }

                println!(
                    "Loaded existing results with {} fastest times\n",
                    min_times.len()
                );
                (results, timings, fastest_sessions, min_times)
            }
            Err(_) => (
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
                HashMap::new(),
            ),
        },
        Err(_) => (
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
            HashMap::new(),
        ),
    }
}

fn write_results_file(data: &serde_json::Value) -> std::io::Result<()> {
    let mut file = File::create("submit_results.json")?;
    let json_str = serde_json::to_string_pretty(data)?;
    file.write_all(json_str.as_bytes())?;
    Ok(())
}
