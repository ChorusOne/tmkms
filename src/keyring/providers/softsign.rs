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
