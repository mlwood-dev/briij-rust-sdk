use std::{
    collections::{BTreeMap, BTreeSet},
    io::{self, Write},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use clap::{ArgGroup, Args, Parser, Subcommand, ValueEnum};
use rand::{Rng, distributions::Alphanumeric};
use reqwest::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use url::Url;
use xrpl_mithril::{
    client::{Client as XrplClient, JsonRpcClient},
    models::requests::transaction::TxRequest,
    tx::{autofill::autofill, builder::PaymentBuilder, sign_transaction, submit_and_wait},
    types::{Amount, XrpAmount},
    wallet::{Algorithm, Wallet},
};

const DEFAULT_SERVER_BASE_URL: &str = "https://test-server.textrp.io";
const DEFAULT_XRPL_RPC_URL: &str = "https://s.altnet.rippletest.net:51234";
const XRPL_LOGIN_TYPE: &str = "io.briij.login.xrpl";
const XRPL_NETWORK: &str = "xrpl";

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
    /// Build/sign/optionally submit a Payment transaction.
    Send(SendArgs),
    /// Trust-aware payment helper for Briij XRPL flows.
    Pay(PayArgs),
    /// Verify a transaction by hash using XRPL JSON-RPC.
    Verify(VerifyArgs),
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum SignMethod {
    Xaman,
    Qr,
    LocalSign,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum WalletAlgorithmArg {
    Ed25519,
    Secp256k1,
}

impl WalletAlgorithmArg {
    fn into_wallet_algorithm(self) -> Algorithm {
        match self {
            WalletAlgorithmArg::Ed25519 => Algorithm::Ed25519,
            WalletAlgorithmArg::Secp256k1 => Algorithm::Secp256k1,
        }
    }
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

    /// Base server URL used for Matrix discovery.
    #[arg(long, default_value = DEFAULT_SERVER_BASE_URL)]
    server: String,

    /// Explicit XRPL challenge endpoint path or absolute URL.
    #[arg(long)]
    challenge_endpoint: Option<String>,

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

#[derive(Debug, Args)]
struct SendArgs {
    /// Sender XRPL classic address (r...)
    #[arg(long)]
    from_address: String,

    /// Destination XRPL classic address (r...)
    #[arg(long)]
    to_address: String,

    /// Amount in drops (1 XRP = 1,000,000 drops)
    #[arg(long)]
    amount_drops: u64,

    /// Optional destination tag.
    #[arg(long)]
    destination_tag: Option<u32>,

    /// Optional sequence (if omitted and --submit used, autofill resolves it).
    #[arg(long)]
    sequence: Option<u32>,

    /// Optional last ledger sequence.
    #[arg(long)]
    last_ledger_sequence: Option<u32>,

    /// Optional fee in drops.
    #[arg(long)]
    fee_drops: Option<u64>,

    /// XRPL seed for signing. Keep this in env var in production.
    #[arg(long)]
    seed: Option<String>,

    /// Seed algorithm.
    #[arg(long, value_enum, default_value = "secp256k1")]
    algorithm: WalletAlgorithmArg,

    /// XRPL JSON-RPC endpoint.
    #[arg(long, default_value = DEFAULT_XRPL_RPC_URL)]
    rpc_url: String,

    /// Submit transaction and wait for validation (requires --seed).
    #[arg(long)]
    submit: bool,
}

#[derive(Debug, Args)]
struct PayArgs {
    /// Payer XRPL classic address (r...)
    #[arg(long)]
    payer: String,

    /// Payee XRPL classic address (r...)
    #[arg(long)]
    payee: String,

    /// Amount in drops (1 XRP = 1,000,000 drops)
    #[arg(long)]
    amount_drops: u64,

    /// Base server URL for trust verification.
    #[arg(long, default_value = DEFAULT_SERVER_BASE_URL)]
    server: String,

    /// Matrix access token for trust endpoint authorization.
    #[arg(long)]
    access_token: Option<String>,

    /// Skip trust endpoint check before building payment.
    #[arg(long)]
    skip_trust_check: bool,

    /// Optional destination tag.
    #[arg(long)]
    destination_tag: Option<u32>,

    /// Optional sequence.
    #[arg(long)]
    sequence: Option<u32>,

    /// Optional last ledger sequence.
    #[arg(long)]
    last_ledger_sequence: Option<u32>,

    /// Optional fee in drops.
    #[arg(long)]
    fee_drops: Option<u64>,

    /// XRPL seed for signing.
    #[arg(long)]
    seed: Option<String>,

    /// Seed algorithm.
    #[arg(long, value_enum, default_value = "secp256k1")]
    algorithm: WalletAlgorithmArg,

    /// XRPL JSON-RPC endpoint.
    #[arg(long, default_value = DEFAULT_XRPL_RPC_URL)]
    rpc_url: String,

    /// Submit transaction and wait for validation (requires --seed).
    #[arg(long)]
    submit: bool,
}

#[derive(Debug, Args)]
struct VerifyArgs {
    /// Transaction hash (64-char hex).
    #[arg(long)]
    tx_hash: String,

    /// XRPL JSON-RPC endpoint.
    #[arg(long, default_value = DEFAULT_XRPL_RPC_URL)]
    rpc_url: String,
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

#[derive(Debug, Deserialize)]
struct WellKnownMatrixClient {
    #[serde(rename = "m.homeserver")]
    homeserver: Option<WellKnownHomeServer>,
    #[serde(flatten)]
    extra: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize)]
struct WellKnownHomeServer {
    base_url: String,
}

#[derive(Debug, Deserialize)]
struct MatrixVersionsResponse {
    versions: Vec<String>,
    #[serde(default)]
    unstable_features: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize)]
struct LoginFlowResponse {
    #[serde(default)]
    flows: Vec<LoginFlow>,
}

#[derive(Debug, Deserialize)]
struct LoginFlow {
    #[serde(rename = "type")]
    flow_type: String,
}

#[derive(Debug)]
struct DiscoveryResult {
    input_base_url: String,
    homeserver_base_url: String,
    matrix_versions: Vec<String>,
    login_flow_types: Vec<String>,
    unstable_features: BTreeMap<String, Value>,
    xrpl_endpoint_hints: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ChallengeRequest<'a> {
    address: &'a str,
    wallet_address: &'a str,
    xrpl_address: &'a str,
}

#[derive(Debug)]
struct ChallengeProbe {
    method: Method,
    url: String,
    source: String,
}

#[derive(Debug)]
struct ChallengeProbeFailure {
    method: Method,
    url: String,
    status: StatusCode,
    body_preview: String,
}

#[derive(Debug)]
struct ChallengeResult {
    method: Method,
    url: String,
    source: String,
    payload: Value,
}

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("Error: {error:#}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let cli = Cli::parse();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .user_agent("briij-cli/0.1")
        .build()
        .context("failed to build HTTP client")?;

    match cli.command {
        Commands::LoginXrpl(args) => run_login_xrpl(&client, args).await,
        Commands::Send(args) => run_send(args).await,
        Commands::Pay(args) => run_pay(&client, args).await,
        Commands::Verify(args) => run_verify(args).await,
    }
}

async fn run_login_xrpl(client: &reqwest::Client, args: LoginXrplArgs) -> Result<()> {
    let method = args.selected_sign_method();
    println!("Starting XRPL login discovery for {}", args.address);

    let discovery = discover_server(client, &args.server).await?;
    println!(
        "Discovered homeserver: {} (from input {})",
        discovery.homeserver_base_url, discovery.input_base_url
    );
    println!("Server supports {} Matrix versions.", discovery.matrix_versions.len());
    if !discovery.login_flow_types.iter().any(|flow| flow == XRPL_LOGIN_TYPE) {
        eprintln!(
            "WARNING: server did not advertise {} in GET /login flows. Attempting anyway.",
            XRPL_LOGIN_TYPE
        );
    }

    let server_challenge =
        fetch_xrpl_challenge(client, &discovery, &args.address, args.challenge_endpoint.as_deref())
            .await;

    let mut challenge_payload = match &server_challenge {
        Ok(challenge) => {
            println!("Challenge endpoint: {} {}", challenge.method, challenge.url);
            println!("Challenge source: {}", challenge.source);
            println!(
                "Challenge payload:\n{}",
                serde_json::to_string_pretty(&challenge.payload)
                    .context("failed to format challenge payload")?
            );
            extract_wallet_challenge_from_payload(&challenge.payload).unwrap_or_else(|| {
                generate_local_wallet_challenge(&args.address, &discovery.homeserver_base_url)
            })
        }
        Err(error) => {
            eprintln!("Challenge fetch unavailable; falling back to local challenge generation.");
            eprintln!("Detail: {error:#}");
            generate_local_wallet_challenge(&args.address, &discovery.homeserver_base_url)
        }
    };

    match method {
        SignMethod::Xaman | SignMethod::Qr => {
            let xaman_uri = build_xaman_deeplink(
                server_challenge.as_ref().ok().map(|result| &result.payload),
                &challenge_payload,
            )?;
            println!("Xaman URI:\n{xaman_uri}");

            qrcode::QrCode::new(xaman_uri.as_bytes())
                .context("failed to encode Xaman URI as QR payload")?;
            qr2term::print_qr(&xaman_uri).context("failed to print terminal QR code")?;

            println!("Manual fallback: paste signing values below.");
            let pasted_public_key = prompt_required("Public key (hex): ")?;
            let pasted_signature = prompt_required("Signature (hex): ")?;
            let algorithm = algorithm_from_public_key(&pasted_public_key);
            upsert_challenge_signer_fields(&mut challenge_payload, &pasted_public_key, algorithm);
            let login_response = submit_wallet_login(
                client,
                &discovery,
                &args.address,
                challenge_payload,
                pasted_signature,
            )
            .await?;
            println!(
                "Login response:\n{}",
                serde_json::to_string_pretty(&login_response)
                    .context("failed to format login response")?
            );
        }
        SignMethod::LocalSign => {
            eprintln!("WARNING: --local-sign is for development use only.");
            eprintln!("WARNING: Never persist or commit XRPL seeds/private keys.");

            let (public_key_hex, signature_hex) =
                local_sign_challenge(&args.address, &challenge_payload)?;
            upsert_challenge_signer_fields(&mut challenge_payload, &public_key_hex, "ed25519");

            let login_response = submit_wallet_login(
                client,
                &discovery,
                &args.address,
                challenge_payload,
                signature_hex,
            )
            .await?;
            println!(
                "Login response:\n{}",
                serde_json::to_string_pretty(&login_response)
                    .context("failed to format login response")?
            );
        }
    }

    println!("Prepared XRPL login for address {} using {:?} signing flow.", args.address, method);
    Ok(())
}

async fn run_send(args: SendArgs) -> Result<()> {
    execute_payment_command(
        &args.from_address,
        &args.to_address,
        args.amount_drops,
        args.destination_tag,
        args.sequence,
        args.last_ledger_sequence,
        args.fee_drops,
        args.seed.as_deref(),
        args.algorithm,
        &args.rpc_url,
        args.submit,
    )
    .await
}

async fn run_pay(client: &reqwest::Client, args: PayArgs) -> Result<()> {
    if !args.skip_trust_check {
        let trust = check_trust(
            client,
            &args.server,
            args.access_token.as_deref(),
            &args.payer,
            &args.payee,
        )
        .await?;
        if !trust {
            bail!("trust check failed: payer {} does not trust payee {}", args.payer, args.payee);
        }
        println!("Trust check passed for {} -> {}.", args.payer, args.payee);
    } else {
        println!("Skipping trust check as requested.");
    }

    execute_payment_command(
        &args.payer,
        &args.payee,
        args.amount_drops,
        args.destination_tag,
        args.sequence,
        args.last_ledger_sequence,
        args.fee_drops,
        args.seed.as_deref(),
        args.algorithm,
        &args.rpc_url,
        args.submit,
    )
    .await
}

async fn run_verify(args: VerifyArgs) -> Result<()> {
    let client = JsonRpcClient::new(&args.rpc_url)
        .with_context(|| format!("failed to initialize XRPL JSON-RPC client {}", args.rpc_url))?;
    let response = client
        .request(TxRequest {
            transaction: args.tx_hash.to_ascii_uppercase(),
            binary: Some(false),
            min_ledger: None,
            max_ledger: None,
        })
        .await
        .context("failed to fetch transaction by hash")?;

    let payload = json!({
        "hash": response.hash.map(|hash| hash.to_string()),
        "ledger_index": response.ledger_index,
        "validated": response.validated,
        "meta": response.meta,
        "tx_data": response.tx_data,
    });
    println!(
        "Verify result:\n{}",
        serde_json::to_string_pretty(&payload).context("failed to render verify output")?
    );
    Ok(())
}

async fn execute_payment_command(
    from_address: &str,
    to_address: &str,
    amount_drops: u64,
    destination_tag: Option<u32>,
    sequence: Option<u32>,
    last_ledger_sequence: Option<u32>,
    fee_drops: Option<u64>,
    seed: Option<&str>,
    algorithm: WalletAlgorithmArg,
    rpc_url: &str,
    submit: bool,
) -> Result<()> {
    let mut builder = PaymentBuilder::new()
        .account(from_address.parse().context("invalid from/payer XRPL address")?)
        .destination(to_address.parse().context("invalid to/payee XRPL address")?)
        .amount(Amount::Xrp(
            XrpAmount::from_drops(amount_drops).context("invalid XRP drops amount")?,
        ));

    if let Some(tag) = destination_tag {
        builder = builder.destination_tag(tag);
    }
    if let Some(seq) = sequence {
        builder = builder.sequence(seq);
    }
    if let Some(lls) = last_ledger_sequence {
        builder = builder.last_ledger_sequence(lls);
    }
    if let Some(fee) = fee_drops {
        builder = builder
            .fee(Amount::Xrp(XrpAmount::from_drops(fee).context("invalid fee drops amount")?));
    }

    let unsigned = builder.build().context("failed to build unsigned payment transaction")?;
    let unsigned_json =
        Value::Object(unsigned.to_json_map().context("failed to serialize unsigned transaction")?);
    println!(
        "Unsigned payment transaction:\n{}",
        serde_json::to_string_pretty(&unsigned_json)
            .context("failed to render unsigned tx json")?
    );

    if submit && seed.is_none() {
        bail!("--submit requires --seed so the transaction can be signed");
    }

    if let Some(seed) = seed {
        let wallet =
            Wallet::from_seed_encoded_with_algorithm(seed, algorithm.into_wallet_algorithm())
                .context("failed to decode XRPL seed")?;
        if wallet.classic_address() != from_address {
            bail!(
                "seed address mismatch: expected {}, got {}",
                from_address,
                wallet.classic_address()
            );
        }

        if submit {
            let rpc_client = JsonRpcClient::new(rpc_url)
                .with_context(|| format!("failed to initialize XRPL JSON-RPC client {rpc_url}"))?;
            let mut tx_to_submit = unsigned.clone();
            autofill(&rpc_client, &mut tx_to_submit)
                .await
                .context("autofill failed before signing")?;

            let signed = sign_transaction(&tx_to_submit, &wallet)
                .context("failed to sign autofilled transaction")?;
            println!("Signed hash: {}", signed.hash());
            let submit_result =
                submit_and_wait(&rpc_client, &signed).await.context("submit_and_wait failed")?;
            println!(
                "Submission result: hash={} result_code={} ledger_index={}",
                submit_result.hash, submit_result.result_code, submit_result.ledger_index
            );
        } else {
            let signed =
                sign_transaction(&unsigned, &wallet).context("failed to sign transaction")?;
            println!("Signed hash: {}", signed.hash());
            println!("Signed tx blob: {}", signed.tx_blob());
            println!(
                "Signed tx json:\n{}",
                serde_json::to_string_pretty(&Value::Object(signed.tx_json().clone()))
                    .context("failed to render signed tx json")?
            );
        }
    } else {
        println!("No seed provided; transaction built only (unsigned).");
    }

    Ok(())
}

async fn check_trust(
    client: &reqwest::Client,
    server: &str,
    access_token: Option<&str>,
    payer: &str,
    payee: &str,
) -> Result<bool> {
    let server_base = normalize_base_url(server)?;
    let trust_url = join_url(&server_base, "/_matrix/client/v3/org.textrp.xrpl/trust")?;
    let request = client.get(&trust_url).query(&[("payer", payer), ("payee", payee)]);
    let request = if let Some(token) = access_token { request.bearer_auth(token) } else { request };

    let response = request
        .send()
        .await
        .with_context(|| format!("failed to call trust endpoint {trust_url}"))?;
    let status = response.status();
    let body_text = response.text().await.unwrap_or_default();
    if !status.is_success() {
        bail!(
            "trust endpoint failed at {} with {}: {}",
            trust_url,
            status,
            truncate_for_log(&body_text, 240)
        );
    }

    let body: Value = serde_json::from_str(&body_text).context("failed to parse trust response")?;
    println!(
        "Trust endpoint response:\n{}",
        serde_json::to_string_pretty(&body).context("failed to format trust response")?
    );

    let trusted = body
        .get("trusted")
        .and_then(Value::as_bool)
        .or_else(|| body.get("score").and_then(Value::as_i64).map(|score| score > 0))
        .unwrap_or(false);
    Ok(trusted)
}

fn extract_wallet_challenge_from_payload(payload: &Value) -> Option<Value> {
    let challenge = payload
        .as_object()
        .and_then(|obj| obj.get("challenge"))
        .cloned()
        .unwrap_or_else(|| payload.clone());

    let has_required_fields = challenge.get("nonce").is_some()
        && challenge.get("timestamp").is_some()
        && challenge.get("message").is_some();
    if has_required_fields { Some(challenge) } else { None }
}

fn generate_local_wallet_challenge(address: &str, server_base_url: &str) -> Value {
    let nonce: String =
        rand::thread_rng().sample_iter(&Alphanumeric).take(24).map(char::from).collect();
    let timestamp_ms =
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as i64;
    let message = format!(
        "Briij XRPL login\nwallet_address={address}\nnonce={nonce}\ntimestamp={timestamp_ms}\nserver={server_base_url}"
    );

    json!({
        "nonce": nonce,
        "timestamp": timestamp_ms,
        "message": message,
        "network": XRPL_NETWORK,
    })
}

fn build_xaman_deeplink(
    server_payload: Option<&Value>,
    challenge_payload: &Value,
) -> Result<String> {
    if let Some(token) = server_payload.and_then(extract_xaman_payload_token) {
        if token.starts_with("xaman://") {
            return Ok(token);
        }
        return Ok(format!("xaman://sign?payload={}", urlencoding::encode(&token)));
    }

    let challenge_json = serde_json::to_string(challenge_payload)
        .context("failed to serialize local challenge for Xaman deeplink")?;
    Ok(format!("xaman://sign?payload={}", urlencoding::encode(&challenge_json)))
}

fn extract_xaman_payload_token(payload: &Value) -> Option<String> {
    if let Some(token) = payload.get("payload").and_then(Value::as_str) {
        return Some(token.to_owned());
    }
    if let Some(token) = payload.get("payload_id").and_then(Value::as_str) {
        return Some(token.to_owned());
    }
    if let Some(token) = payload.get("uuid").and_then(Value::as_str) {
        return Some(token.to_owned());
    }
    if let Some(xaman) = payload.get("xaman") {
        if let Some(token) = xaman.get("payload").and_then(Value::as_str) {
            return Some(token.to_owned());
        }
        if let Some(token) = xaman.get("payload_id").and_then(Value::as_str) {
            return Some(token.to_owned());
        }
        if let Some(token) = xaman.get("uuid").and_then(Value::as_str) {
            return Some(token.to_owned());
        }
    }
    None
}

fn prompt_required(prompt: &str) -> Result<String> {
    print!("{prompt}");
    io::stdout().flush().context("failed to flush stdout prompt")?;

    let mut input = String::new();
    io::stdin().read_line(&mut input).context("failed to read terminal input")?;
    let trimmed = input.trim().to_owned();
    if trimmed.is_empty() {
        bail!("required value cannot be empty");
    }
    Ok(trimmed)
}

fn local_sign_challenge(address: &str, challenge_payload: &Value) -> Result<(String, String)> {
    let message = challenge_payload
        .get("message")
        .and_then(Value::as_str)
        .context("challenge payload is missing message field")?;

    let seed = match std::env::var("BRIIJ_XRPL_SEED") {
        Ok(seed) => seed,
        Err(_) => {
            let generated_wallet = Wallet::generate(Algorithm::Ed25519)
                .context("failed to generate ephemeral xrpl-mithril wallet")?;
            bail!(
                "BRIIJ_XRPL_SEED is required for --local-sign.\nGenerated ephemeral wallet address for testing: {}\nRerun with BRIIJ_XRPL_SEED set to your seed (not persisted).",
                generated_wallet.classic_address()
            );
        }
    };

    let wallet = Wallet::from_seed_encoded_with_algorithm(&seed, Algorithm::Ed25519)
        .context("failed to decode BRIIJ_XRPL_SEED")?;
    if wallet.classic_address() != address {
        bail!(
            "seed address mismatch: --address={} but seed resolves to {}",
            address,
            wallet.classic_address()
        );
    }

    let signature = wallet
        .keypair()
        .sign(message.as_bytes())
        .context("failed to sign challenge with local wallet")?;
    Ok((wallet.public_key_hex(), bytes_to_upper_hex(&signature)))
}

fn upsert_challenge_signer_fields(
    challenge_payload: &mut Value,
    public_key: &str,
    algorithm: &str,
) {
    if !challenge_payload.is_object() {
        *challenge_payload = json!({ "raw": challenge_payload.clone() });
    }
    if let Some(object) = challenge_payload.as_object_mut() {
        object.insert("public_key".to_owned(), Value::String(public_key.to_owned()));
        object.insert("algorithm".to_owned(), Value::String(algorithm.to_owned()));
    }
}

async fn submit_wallet_login(
    client: &reqwest::Client,
    discovery: &DiscoveryResult,
    wallet_address: &str,
    challenge_payload: Value,
    signature_hex: String,
) -> Result<Value> {
    let login_url = join_url(&discovery.homeserver_base_url, "/_matrix/client/v3/login")?;
    let username = fallback_username_from_address(wallet_address);
    let body = json!({
        "type": XRPL_LOGIN_TYPE,
        "identifier": {
            "type": "m.id.user",
            "user": username,
        },
        "user": username,
        "wallet_address": wallet_address,
        "network": XRPL_NETWORK,
        "challenge": challenge_payload,
        "signature": signature_hex,
    });

    let response = client
        .post(&login_url)
        .json(&body)
        .send()
        .await
        .with_context(|| format!("failed to call login endpoint {login_url}"))?;
    let status = response.status();
    let body_text = response.text().await.unwrap_or_default();
    if !status.is_success() {
        bail!(
            "wallet login failed at {} with {}: {}",
            login_url,
            status,
            truncate_for_log(&body_text, 360)
        );
    }

    let parsed =
        serde_json::from_str::<Value>(&body_text).unwrap_or_else(|_| json!({ "raw": body_text }));
    Ok(parsed)
}

fn fallback_username_from_address(address: &str) -> String {
    let suffix_start = address.len().saturating_sub(10);
    format!("wallet_{}", address[suffix_start..].to_ascii_lowercase())
}

fn bytes_to_upper_hex(input: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(input.len() * 2);
    for byte in input {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn algorithm_from_public_key(public_key: &str) -> &'static str {
    if public_key.to_ascii_uppercase().starts_with("ED") { "ed25519" } else { "secp256k1" }
}

async fn discover_server(client: &reqwest::Client, input_server: &str) -> Result<DiscoveryResult> {
    let input_base_url = normalize_base_url(input_server)?;
    let mut homeserver_base_url = input_base_url.clone();
    let mut well_known_extra = BTreeMap::new();

    let well_known_url = join_url(&input_base_url, "/.well-known/matrix/client")?;
    let well_known_response = client
        .get(&well_known_url)
        .send()
        .await
        .with_context(|| format!("failed to call discovery endpoint {well_known_url}"))?;

    if well_known_response.status().is_success() {
        let body: WellKnownMatrixClient = well_known_response
            .json()
            .await
            .with_context(|| format!("failed to parse discovery response from {well_known_url}"))?;
        if let Some(hs) = body.homeserver {
            homeserver_base_url = normalize_base_url(&hs.base_url)?;
        }
        well_known_extra = body.extra;
    }

    let versions_url = join_url(&homeserver_base_url, "/_matrix/client/versions")?;
    let versions_response: MatrixVersionsResponse = client
        .get(&versions_url)
        .send()
        .await
        .with_context(|| format!("failed to call Matrix versions endpoint {versions_url}"))?
        .error_for_status()
        .with_context(|| {
            format!("Matrix versions endpoint returned non-success at {versions_url}")
        })?
        .json()
        .await
        .with_context(|| format!("failed to parse Matrix versions response from {versions_url}"))?;

    let login_flows_url = join_url(&homeserver_base_url, "/_matrix/client/v3/login")?;
    let login_flow_types = match client.get(&login_flows_url).send().await {
        Ok(resp) if resp.status().is_success() => match resp.json::<LoginFlowResponse>().await {
            Ok(parsed) => parsed.flows.into_iter().map(|flow| flow.flow_type).collect(),
            Err(_) => Vec::new(),
        },
        _ => Vec::new(),
    };

    let mut xrpl_endpoint_hints = extract_xrpl_hints_from_well_known(&well_known_extra);
    for flow_type in &login_flow_types {
        if flow_type.to_ascii_lowercase().contains("xrpl") {
            xrpl_endpoint_hints.push(flow_type.to_owned());
        }
    }
    xrpl_endpoint_hints.sort();
    xrpl_endpoint_hints.dedup();

    Ok(DiscoveryResult {
        input_base_url,
        homeserver_base_url,
        matrix_versions: versions_response.versions,
        login_flow_types: login_flow_types.clone(),
        unstable_features: versions_response.unstable_features,
        xrpl_endpoint_hints,
    })
}

fn extract_xrpl_hints_from_well_known(extra: &BTreeMap<String, Value>) -> Vec<String> {
    let mut hints = Vec::new();

    for (key, value) in extra {
        let lower_key = key.to_ascii_lowercase();
        if !(lower_key.contains("xrpl")
            || lower_key.contains("xaman")
            || lower_key.contains("wallet")
            || lower_key.contains("challenge"))
        {
            continue;
        }

        if let Some(object) = value.as_object() {
            for field in [
                "challenge_endpoint",
                "challenge_url",
                "challenge_path",
                "xrpl_challenge_endpoint",
                "auth_challenge_endpoint",
                "url",
                "endpoint",
            ] {
                if let Some(endpoint) = object.get(field).and_then(Value::as_str) {
                    hints.push(endpoint.to_owned());
                }
            }
        } else if let Some(endpoint) = value.as_str() {
            hints.push(endpoint.to_owned());
        }
    }

    hints
}

async fn fetch_xrpl_challenge(
    client: &reqwest::Client,
    discovery: &DiscoveryResult,
    address: &str,
    explicit_endpoint: Option<&str>,
) -> Result<ChallengeResult> {
    let probes = build_challenge_probes(discovery, explicit_endpoint)?;
    let payload = ChallengeRequest { address, wallet_address: address, xrpl_address: address };
    let mut failures = Vec::new();

    for probe in probes {
        let request = match probe.method {
            Method::POST => client.post(&probe.url).json(&payload),
            Method::GET => client.get(&probe.url).query(&[
                ("address", address),
                ("wallet_address", address),
                ("xrpl_address", address),
            ]),
            _ => continue,
        };

        let response = match request.send().await {
            Ok(response) => response,
            Err(error) => {
                failures.push(ChallengeProbeFailure {
                    method: probe.method.clone(),
                    url: probe.url.clone(),
                    status: StatusCode::REQUEST_TIMEOUT,
                    body_preview: format!("request error: {error}"),
                });
                continue;
            }
        };

        let status = response.status();
        let body_text = response.text().await.unwrap_or_default();
        if status.is_success() {
            let payload =
                serde_json::from_str(&body_text).unwrap_or_else(|_| json!({ "raw": body_text }));
            return Ok(ChallengeResult {
                method: probe.method,
                url: probe.url,
                source: probe.source,
                payload,
            });
        }

        failures.push(ChallengeProbeFailure {
            method: probe.method,
            url: probe.url,
            status,
            body_preview: truncate_for_log(&body_text, 220),
        });
    }

    let mut failure_log = String::new();
    for failure in failures.into_iter().take(12) {
        let _ = std::fmt::write(
            &mut failure_log,
            format_args!(
                "\n- {} {} -> {} {}",
                failure.method, failure.url, failure.status, failure.body_preview
            ),
        );
    }

    bail!(
        "failed to fetch XRPL challenge from discovered server {}. Probe results:{}",
        discovery.homeserver_base_url,
        failure_log
    );
}

fn build_challenge_probes(
    discovery: &DiscoveryResult,
    explicit_endpoint: Option<&str>,
) -> Result<Vec<ChallengeProbe>> {
    let mut seen = BTreeSet::new();
    let mut probes = Vec::new();

    if let Some(endpoint) = explicit_endpoint {
        add_probe_pair(
            &mut probes,
            &mut seen,
            &discovery.homeserver_base_url,
            endpoint,
            "explicit-arg",
        )?;
    }

    for endpoint in &discovery.xrpl_endpoint_hints {
        add_probe_pair(
            &mut probes,
            &mut seen,
            &discovery.homeserver_base_url,
            endpoint,
            "well-known/login-flow-hint",
        )?;
    }

    for key in discovery.unstable_features.keys() {
        let lower = key.to_ascii_lowercase();
        if lower.contains("xrpl") || lower.contains("xaman") {
            let as_path = format!("/_matrix/client/unstable/{key}/challenge");
            add_probe_pair(
                &mut probes,
                &mut seen,
                &discovery.homeserver_base_url,
                &as_path,
                "unstable-feature-key",
            )?;
        }
    }

    for path in [
        "/_matrix/client/unstable/io.textrp.xrpl/challenge",
        "/_matrix/client/unstable/io.textrp.xrpl/login/challenge",
        "/_matrix/client/unstable/io.textrp.xrpl/auth/challenge",
        "/_matrix/client/unstable/org.textrp.xrpl/challenge",
        "/_matrix/client/unstable/com.textrp.xrpl/challenge",
        "/_matrix/client/unstable/textrp/xrpl/challenge",
        "/_matrix/client/v3/xrpl/challenge",
        "/_matrix/client/v3/login/xrpl/challenge",
        "/_matrix/client/v3/login/challenge",
        "/api/v1/xrpl/challenge",
        "/api/xrpl/challenge",
        "/xrpl/challenge",
    ] {
        add_probe_pair(&mut probes, &mut seen, &discovery.homeserver_base_url, path, "fallback")?;
    }

    Ok(probes)
}

fn add_probe_pair(
    probes: &mut Vec<ChallengeProbe>,
    seen: &mut BTreeSet<String>,
    base_url: &str,
    path_or_url: &str,
    source: &str,
) -> Result<()> {
    let full_url = if path_or_url.starts_with("http://") || path_or_url.starts_with("https://") {
        path_or_url.to_owned()
    } else {
        join_url(base_url, path_or_url)?
    };

    for method in [Method::POST, Method::GET] {
        let key = format!("{} {}", method, full_url);
        if seen.insert(key) {
            probes.push(ChallengeProbe {
                method,
                url: full_url.clone(),
                source: source.to_owned(),
            });
        }
    }

    Ok(())
}

fn normalize_base_url(input: &str) -> Result<String> {
    let with_scheme = if input.starts_with("http://") || input.starts_with("https://") {
        input.to_owned()
    } else {
        format!("https://{input}")
    };
    let parsed = Url::parse(&with_scheme).with_context(|| format!("invalid server URL {input}"))?;
    Ok(parsed.as_str().trim_end_matches('/').to_owned())
}

fn join_url(base: &str, path: &str) -> Result<String> {
    let mut base_url = base.trim_end_matches('/').to_owned();
    base_url.push('/');
    let base_url = Url::parse(&base_url).with_context(|| format!("invalid base URL {base}"))?;
    let joined = base_url
        .join(path.trim_start_matches('/'))
        .with_context(|| format!("failed to join URL {base} + {path}"))?;
    Ok(joined.as_str().trim_end_matches('/').to_owned())
}

fn truncate_for_log(input: &str, max_len: usize) -> String {
    if input.len() <= max_len {
        return input.replace('\n', " ");
    }

    let mut truncated = input[..max_len].replace('\n', " ");
    truncated.push_str("...");
    truncated
}
