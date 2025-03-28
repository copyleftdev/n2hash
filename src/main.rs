use clap::Parser;
use colored::*; // Import colored extension methods
use rpassword::prompt_password;
use std::io::{self, Write};
use std::process;
use std::env; // To check if env vars were the source

// Declare the module defined in src/ntlm_logic.rs
mod ntlm_logic;

/// Generate NetNTLMv2 hash strings for authentication challenges.
///
/// Reads username, domain, and password. Password can be provided via -p,
/// the N2HASH_PASSWORD environment variable, or an interactive prompt.
/// Username/Domain can be provided via args or N2HASH_USERNAME/N2HASH_DOMAIN env vars.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct CliArgs {
    /// Username
    #[arg(short, long, env = "N2HASH_USERNAME")] // Read from env var if flag not set
    username: Option<String>, // Make optional to check if set

    /// Domain or Workstation name
    #[arg(short, long, env = "N2HASH_DOMAIN")]   // Read from env var if flag not set
    domain: Option<String>,   // Make optional to check if set

    /// Password (reads from N2HASH_PASSWORD env var if flag not set; prompts if neither is present)
    /// Warning: Avoid using the -p flag in scripts or shared environments.
    #[arg(short, long, env = "N2HASH_PASSWORD")]
    password: Option<String>,

    /// Increase verbosity (e.g., show intermediate NTLM hash)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

fn main() {
    // Parse command-line arguments and environment variables via clap
    let args = CliArgs::parse();

    // --- Determine Username ---
    let username = args.username.unwrap_or_else(|| {
        eprintln!("{}", "Error: Username not provided via -u/--username or N2HASH_USERNAME env var.".red());
        process::exit(1);
    });

    // --- Determine Domain ---
    let domain = args.domain.unwrap_or_else(|| {
        eprintln!("{}", "Error: Domain not provided via -d/--domain or N2HASH_DOMAIN env var.".red());
        process::exit(1);
    });


    // --- Determine Password ---
    let password_source: String; // Keep track of where the password came from
    let password = match args.password {
        Some(p) => {
            // Check if the password came from ENV var or direct argument
            // This is a bit indirect, requires checking if the env var exists *and* matches
            let env_pass = env::var("N2HASH_PASSWORD").ok();
            if env_pass.as_deref() == Some(&p) {
                 password_source = "environment variable (N2HASH_PASSWORD)".to_string();
                 if args.verbose > 0 {
                     println!("[{}] {}", "Info".cyan(), "Using password from environment variable.");
                 }
            } else {
                 password_source = "command-line argument (-p)".to_string();
                 // Show warning only if explicitly passed via -p
                 eprintln!("{}", "Warning: Providing password directly via -p is insecure.".yellow());
            }
            p // Return the password
        },
        None => {
            // Neither -p nor N2HASH_PASSWORD env var was set, so prompt
             password_source = "interactive prompt".to_string();
             if args.verbose > 0 {
                 println!("[{}] {}", "Info".cyan(), "Password not found in args or env, prompting.");
             }
            match prompt_password(format!("{}: ", "Enter password".yellow())) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("{} {}", "Error reading password:".red(), e);
                    process::exit(1);
                }
            }
        }
    };

     if args.verbose > 0 {
         println!("[{}] Using username: '{}'", "Info".cyan(), username);
         println!("[{}] Using domain:   '{}'", "Info".cyan(), domain);
         println!("[{}] Using password from: {}", "Info".cyan(), password_source);
     }

     // --- Optional: Calculate and show NTLM hash if verbose ---
     if args.verbose > 0 {
         let ntlm_hash = ntlm_logic::ntlm(&password);
         println!("[{}] NTLM Hash:   {}", "Verbose".purple(), ntlm_hash.bright_black());
     }


    // --- Call the core logic function ---
    match ntlm_logic::net_ntlm_v2(&username, &domain, &password) {
        Ok(hash_string) => {
            // --- Colorize Output ---
            // Split the string for coloring (handle potential errors gracefully)
            let parts: Vec<&str> = hash_string.split(':').collect();
            if parts.len() == 5 {
                println!(
                    "{}{}{}{}{}{}{}{}{}",
                    parts[0].cyan(),        // User
                    "::".white().bold(),
                    parts[1].blue(),        // Domain
                    ":".white().bold(),
                    parts[2].green(),       // Server Challenge (hex)
                    ":".white().bold(),
                    parts[3].magenta(),     // NT Proof String (hex)
                    ":".white().bold(),
                    parts[4].bright_black() // Blob (hex)
                );
            } else {
                // Fallback if splitting failed unexpectedly
                eprintln!("{}", "Warning: Could not colorize output, format unexpected.".yellow());
                println!("{}", hash_string); // Print plain string
            }
            process::exit(0); // Exit successfully
        }
        Err(e) => {
            // Print error message to standard error, colored red
            eprintln!("{} {}", "Error generating NetNTLMv2 hash:".red().bold(), e);
             // Ensure error message is flushed before exiting
            let _ = io::stderr().flush();
            process::exit(1); // Exit with error code
        }
    }
}