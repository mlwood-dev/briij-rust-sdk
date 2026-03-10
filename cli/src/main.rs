use clap::{ArgGroup, Args, Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(name = "briij-cli")]
#[command(version, about = "Briij Matrix + XRPL command-line client")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Authenticate with an XRPL address.
    LoginXrpl(LoginXrplArgs),
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum SignMethod {
    Xaman,
    Qr,
    LocalSign,
}

#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("sign-mode")
        .args(["xaman", "qr", "local_sign"])
        .multiple(false)
))]
struct LoginXrplArgs {
    /// XRPL classic address (r...)
    #[arg(long)]
    address: String,

    /// Open/authenticate with Xaman deep-link payload.
    #[arg(long)]
    xaman: bool,

    /// Display terminal QR code for signing payload.
    #[arg(long)]
    qr: bool,

    /// Sign challenge locally with an ephemeral in-memory wallet.
    #[arg(long = "local-sign")]
    local_sign: bool,

    /// Explicit sign method; equivalent to the boolean mode flags.
    #[arg(long, value_enum)]
    sign_method: Option<SignMethod>,
}

impl LoginXrplArgs {
    fn selected_sign_method(&self) -> SignMethod {
        if let Some(mode) = self.sign_method {
            return mode;
        }

        if self.local_sign {
            SignMethod::LocalSign
        } else if self.qr {
            SignMethod::Qr
        } else {
            SignMethod::Xaman
        }
    }
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::LoginXrpl(args) => {
            let method = args.selected_sign_method();
            println!(
                "Prepared XRPL login for address {} using {:?} signing flow.",
                args.address, method
            );

            if matches!(method, SignMethod::LocalSign) {
                eprintln!("WARNING: --local-sign uses a local wallet in memory only. Never persist private keys.");
            }
        }
    }
}
