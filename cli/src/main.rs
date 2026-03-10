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
use xrpl_mithril::wallet::{Algorithm, Wallet};

const DEFAULT_SERVER_BASE_URL: &str = "https://test-server.textrp.io";
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
