use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use clap::{ArgGroup, Args, Parser, Subcommand, ValueEnum};
use reqwest::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use url::Url;

const DEFAULT_SERVER_BASE_URL: &str = "https://test-server.textrp.io";

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

    let challenge =
        fetch_xrpl_challenge(client, &discovery, &args.address, args.challenge_endpoint.as_deref())
            .await?;
    println!("Challenge endpoint: {} {}", challenge.method, challenge.url);
    println!("Challenge source: {}", challenge.source);
    println!(
        "Challenge payload:\n{}",
        serde_json::to_string_pretty(&challenge.payload)
            .context("failed to format challenge payload")?
    );

    println!("Prepared XRPL login for address {} using {:?} signing flow.", args.address, method);

    if matches!(method, SignMethod::LocalSign) {
        eprintln!(
            "WARNING: --local-sign uses a local wallet in memory only. Never persist private keys."
        );
    }

    Ok(())
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
    for flow_type in login_flow_types {
        if flow_type.to_ascii_lowercase().contains("xrpl") {
            xrpl_endpoint_hints.push(flow_type);
        }
    }
    xrpl_endpoint_hints.sort();
    xrpl_endpoint_hints.dedup();

    Ok(DiscoveryResult {
        input_base_url,
        homeserver_base_url,
        matrix_versions: versions_response.versions,
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
