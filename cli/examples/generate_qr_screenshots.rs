use std::{fs, path::PathBuf};

use anyhow::{Context, Result};
use qrcode::{QrCode, render::svg};

fn main() -> Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let docs = root.join("docs");

    fs::create_dir_all(&docs).context("failed to create docs directory")?;

    let samples = [
        (
            "qr_xaman_deeplink_example.svg",
            "xaman://sign?payload=85f8b3c7-7e73-4d1f-8f08-5307f50f40dd",
        ),
        (
            "qr_xaman_challenge_fallback_example.svg",
            "xaman://sign?payload=%7B%22message%22%3A%22Briij%20XRPL%20login%22%2C%22nonce%22%3A%22EXAMPLE_NONCE_2026%22%2C%22timestamp%22%3A1773180959994%7D",
        ),
    ];

    for (file_name, payload) in samples {
        let code = QrCode::new(payload.as_bytes()).context("failed to generate QR code")?;
        let svg = code
            .render::<svg::Color<'_>>()
            .min_dimensions(512, 512)
            .dark_color(svg::Color("#000000"))
            .light_color(svg::Color("#ffffff"))
            .build();

        let output = docs.join(file_name);
        fs::write(&output, svg).with_context(|| format!("failed to write {}", output.display()))?;
        println!("wrote {}", output.display());
    }

    Ok(())
}
