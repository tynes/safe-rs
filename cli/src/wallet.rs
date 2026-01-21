use alloy::signers::local::PrivateKeySigner;
use color_eyre::eyre::{eyre, Result};

use crate::cli::WalletArgs;

pub fn create_signer(args: &WalletArgs) -> Result<PrivateKeySigner> {
    // Priority: interactive > keystore > private_key
    if args.interactive {
        let key = rpassword::prompt_password("Enter private key: ")?;
        parse_private_key(&key)
    } else if args.keystore.is_some() {
        Err(eyre!("Keystore support not yet implemented. Use --private-key or --interactive"))
    } else if let Some(private_key) = &args.private_key {
        parse_private_key(private_key)
    } else {
        Err(eyre!(
            "No wallet specified. Use --private-key or --interactive"
        ))
    }
}

fn parse_private_key(key: &str) -> Result<PrivateKeySigner> {
    let key = key.trim();
    // Strip 0x prefix if present
    let key = key.strip_prefix("0x").unwrap_or(key);

    key.parse::<PrivateKeySigner>()
        .map_err(|e| eyre!("Invalid private key: {}", e))
}
