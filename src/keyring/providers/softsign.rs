//! ed25519-dalek software-based signer
//!
//! This is mainly intended for testing/CI. Ideally real validators will use HSMs.

use crate::{
    chain,
    config::provider::{
        softsign::{KeyFormat, SoftsignConfig},
        KeyType,
    },
    error::{Error, ErrorKind::*},
    key_utils,
    keyring::{self, ed25519, SigningProvider},
    prelude::*,
};
use k256::ecdsa;
use sha2::Sha512;
use signature::Signer;
use tendermint::{PrivateKey, TendermintKey};
use tendermint_config::PrivValidatorKey;

use ed25519_dalek::hazmat::{raw_sign, ExpandedSecretKey};
use ed25519_dalek::{Signature as DalekSignature, VerifyingKey as DalekVerifyingKey};

struct ExpandedDalekSigner {
    expanded: ExpandedSecretKey,
    verifying_key: DalekVerifyingKey,
}

impl Signer<DalekSignature> for ExpandedDalekSigner {
    fn try_sign(&self, msg: &[u8]) -> Result<DalekSignature, signature::Error> {
        let signature = raw_sign::<Sha512>(&self.expanded, msg, &self.verifying_key);

        match self.verifying_key.verify_strict(msg, &signature) {
            Ok(()) => {
                info!("signature verification passed for message");
                Ok(signature)
            }
            Err(e) => {
                error!("signature verification failed for message: {}", e);
                Err(e)
            }
        }
    }
}

/// Create software-backed Ed25519 signer objects from the given configuration
pub fn init(chain_registry: &mut chain::Registry, configs: &[SoftsignConfig]) -> Result<(), Error> {
    if configs.is_empty() {
        return Ok(());
    }

    let mut loaded_consensus_key = false;

    for config in configs {
        match config.key_type {
            KeyType::Account => {
                let signer = load_secp256k1_key(config)?;
                let public_key = tendermint::PublicKey::from_raw_secp256k1(
                    &signer.verifying_key().to_sec1_bytes(),
                )
                .unwrap();

                let account_pubkey = TendermintKey::AccountKey(public_key);

                let signer = keyring::ecdsa::Signer::new(
                    SigningProvider::SoftSign,
                    account_pubkey,
                    Box::new(signer),
                );

                for chain_id in &config.chain_ids {
                    chain_registry.add_account_key(chain_id, signer.clone())?;
                }
            }
            KeyType::Consensus => {
                if loaded_consensus_key {
                    fail!(
                        ConfigError,
                        "only one [[providers.softsign]] consensus key allowed"
                    );
                }

                loaded_consensus_key = true;

                let (signer, verifying_key) = load_consensus_key(config)?;
                let consensus_pubkey = TendermintKey::ConsensusKey(verifying_key.into());

                let signer =
                    ed25519::Signer::new(SigningProvider::SoftSign, consensus_pubkey, signer);

                for chain_id in &config.chain_ids {
                    chain_registry.add_consensus_key(chain_id, signer.clone())?;
                }
            }
        }
    }

    Ok(())
}

/// Load an Ed25519 key according to the provided configuration
fn load_consensus_key(
    config: &SoftsignConfig,
) -> Result<
    (
        Box<dyn Signer<DalekSignature> + Send + Sync>,
        ed25519::VerifyingKey,
    ),
    Error,
> {
    let key_format = config.key_format.as_ref().cloned().unwrap_or_default();

    let (signer, public_key) = match key_format {
        KeyFormat::Base64 => {
            let sk = key_utils::load_base64_ed25519_key(&config.path)?;
            let vk = sk.verifying_key();
            (Box::new(sk) as Box<_>, vk)
        }
        KeyFormat::Json => {
            let private_key = PrivValidatorKey::load_json_file(&config.path)
                .map_err(|e| {
                    format_err!(
                        ConfigError,
                        "couldn't load `{}`: {}",
                        config.path.as_ref().display(),
                        e
                    )
                })?
                .priv_key;

            if let PrivateKey::Ed25519(pk) = private_key {
                let sk: ed25519::SigningKey = pk.into();
                let vk = sk.verifying_key();
                (Box::new(sk) as Box<_>, vk)
            } else {
                unreachable!("unsupported priv_validator.json algorithm");
            }
        }
        // todo: docs on how we got this expanded secret
        KeyFormat::Base64Expanded => {
            let mut key_bytes = key_utils::load_base64_secret(&config.path)?;

            const TOTAL_KEY_LENGTH: usize = 96;

            if key_bytes.len() != TOTAL_KEY_LENGTH {
                fail!(
                    ConfigError,
                    "invalid expanded key size for {}: expected {}, got {}",
                    config.path.as_ref().display(),
                    TOTAL_KEY_LENGTH,
                    key_bytes.len()
                );
            }

            key_bytes[0..32].reverse();

            let esk = ExpandedSecretKey::from_bytes(&key_bytes[0..64].try_into().unwrap());

            let vk_dalek = DalekVerifyingKey::from(&esk);

            let stored_public_bytes = &key_bytes[64..96];
            if vk_dalek.to_bytes() != stored_public_bytes {
                fail!(
                    InvalidKey,
                    "cannot verify public key from expanded secret key"
                );
            }

            info!(
                "Verified public key {}",
                base64::encode(vk_dalek.to_bytes())
            );

            let vk = ed25519::VerifyingKey::try_from(&stored_public_bytes[..])
                .map_err(|e| format_err!(ConfigError, "invalid public key: {}", e))?;

            let signer = ExpandedDalekSigner {
                expanded: esk,
                verifying_key: vk_dalek,
            };

            (Box::new(signer) as Box<_>, vk)
        }
    };

    Ok((signer, public_key))
}

/// Load a secp256k1 (ECDSA) key according to the provided configuration
fn load_secp256k1_key(config: &SoftsignConfig) -> Result<ecdsa::SigningKey, Error> {
    if config.key_format.unwrap_or_default() != KeyFormat::Base64 {
        fail!(
            ConfigError,
            "[[providers.softsign]] account keys must be `base64` encoded"
        );
    }

    let key_bytes = key_utils::load_base64_secret(&config.path)?;

    let secret_key = ecdsa::SigningKey::try_from(key_bytes.as_slice()).map_err(|e| {
        format_err!(
            ConfigError,
            "can't decode account key base64 from {}: {}",
            config.path.as_ref().display(),
            e
        )
    })?;

    Ok(secret_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain;
    use crate::config::KmsConfig;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::tempdir;

    #[test]
    fn compare_signatures() -> anyhow::Result<()> {
        let payload_str = "70080211981296010000000022480a20bb9d2c961d59dd6e8344b317da5c273315fe2ce8ebd46d96785faedafc2148a6122408011220e586a4576883e153a7252fa39a0becb8785e57762c98393fe0cf761a1e79db9d2a0c08e48fd3c30610a7c78ce602320b636f736d6f736875622d34";
        let mut payload = vec![0u8; payload_str.len() / 2];
        hex::decode_to_slice(payload_str, &mut payload)?;

        let crate_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let normal_config_path =
            crate_root.join("src/keyring/providers/test_data/tmkms_expanded_regular_key.toml");
        let expanded_config_path =
            crate_root.join("src/keyring/providers/test_data/tmkms_expanded_key_test.toml");

        let mut normal_config: KmsConfig =
            toml::from_str(&fs::read_to_string(&normal_config_path)?)?;

        let temp_home_normal = tempdir()?;
        normal_config.chain[0].state_file = Some(temp_home_normal.path().join("state-normal.json"));

        let mut normal_registry = chain::Registry::default();
        for chain_config in &normal_config.chain {
            normal_registry.register_chain(chain::Chain::from_config(chain_config)?)?;
        }
        init(&mut normal_registry, &normal_config.providers.softsign)?;
        let normal_chain_id = "cosmoshub-4".try_into()?;
        let normal_chain = normal_registry.get_chain(&normal_chain_id).unwrap();
        let normal_signature = normal_chain.keyring.sign(None, &payload)?;
        let normal_sig_bytes = normal_signature.to_vec();

        let mut expanded_config: KmsConfig =
            toml::from_str(&fs::read_to_string(&expanded_config_path)?)?;
        let temp_home_expanded = tempdir()?;
        expanded_config.chain[0].state_file =
            Some(temp_home_expanded.path().join("state-expanded.json"));

        let mut expanded_registry = chain::Registry::default();
        for chain_config in &expanded_config.chain {
            expanded_registry.register_chain(chain::Chain::from_config(chain_config)?)?;
        }
        init(&mut expanded_registry, &expanded_config.providers.softsign)?;

        let expanded_chain_id = "cosmoshub-4".try_into()?;
        let expanded_chain = expanded_registry.get_chain(&expanded_chain_id).unwrap();
        let expanded_signature = expanded_chain.keyring.sign(None, &payload)?;
        let expanded_sig_bytes = expanded_signature.to_vec();
        println!("regular key sig: {}", base64::encode(&normal_sig_bytes));
        println!("expanded key sig: {}", base64::encode(&expanded_sig_bytes));

        assert_eq!(
            normal_sig_bytes, expanded_sig_bytes,
            "the signatures from the normal and expanded keys must be identical!"
        );

        Ok(())
    }
}
