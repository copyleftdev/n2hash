use clap::Parser;
use colored::*;
use rpassword::prompt_password;
use std::env;
use std::io::{self, Write};
use std::process;

mod ntlm_logic;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct CliArgs {
    #[arg(short, long, env = "N2HASH_USERNAME")]
    username: Option<String>,

    #[arg(short, long, env = "N2HASH_DOMAIN")]
    domain: Option<String>,

    #[arg(short, long, env = "N2HASH_PASSWORD")]
    password: Option<String>,

    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

fn main() {
    let args = CliArgs::parse();

    let username = args.username.unwrap_or_else(|| {
        eprintln!(
            "{}",
            "Error: Username not provided via -u/--username or N2HASH_USERNAME env var.".red()
        );
        process::exit(1);
    });

    let domain = args.domain.unwrap_or_else(|| {
        eprintln!(
            "{}",
            "Error: Domain not provided via -d/--domain or N2HASH_DOMAIN env var.".red()
        );
        process::exit(1);
    });

    let password_source: String;
    let password = match args.password {
        Some(p) => {
            let env_pass = env::var("N2HASH_PASSWORD").ok();
            if env_pass.as_deref() == Some(&p) {
                password_source = "environment variable (N2HASH_PASSWORD)".to_string();
                if args.verbose > 0 {
                    println!(
                        "[{}] Using password from environment variable.",
                        "Info".cyan()
                    );
                }
            } else {
                password_source = "command-line argument (-p)".to_string();
                eprintln!(
                    "{}",
                    "Warning: Providing password directly via -p is insecure.".yellow()
                );
            }
            p
        }
        None => {
            password_source = "interactive prompt".to_string();
            if args.verbose > 0 {
                println!(
                    "[{}] Password not found in args or env, prompting.",
                    "Info".cyan()
                );
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
        println!(
            "[{}] Using password from: {}",
            "Info".cyan(),
            password_source
        );
    }

    if args.verbose > 0 {
        let ntlm_hash = ntlm_logic::ntlm(&password);
        println!(
            "[{}] NTLM Hash:   {}",
            "Verbose".purple(),
            ntlm_hash.bright_black()
        );
    }

    match ntlm_logic::net_ntlm_v2(&username, &domain, &password) {
        Ok(hash_string) => {
            let parts: Vec<&str> = hash_string.split(':').collect();
            if parts.len() == 5 {
                println!(
                    "{}{}{}{}{}{}{}{}{}",
                    parts[0].cyan(),
                    "::".white().bold(),
                    parts[1].blue(),
                    ":".white().bold(),
                    parts[2].green(),
                    ":".white().bold(),
                    parts[3].magenta(),
                    ":".white().bold(),
                    parts[4].bright_black()
                );
            } else {
                eprintln!(
                    "{}",
                    "Warning: Could not colorize output, format unexpected.".yellow()
                );
                println!("{}", hash_string);
            }
            process::exit(0);
        }
        Err(e) => {
            eprintln!("{} {}", "Error generating NetNTLMv2 hash:".red().bold(), e);
            let _ = io::stderr().flush();
            process::exit(1);
        }
    }
}
