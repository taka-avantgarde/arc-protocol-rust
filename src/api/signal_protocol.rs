use flutter_rust_bridge::frb;
use libsignal_protocol::*;
use rand::rngs::OsRng;
use rand::TryRngCore;

/// Signal Protocol の鍵ペアを生成
///
/// Identity Key Pair (X25519) を生成し、
/// 公開鍵と秘密鍵をバイト列で返す
#[frb(sync)]
pub fn generate_identity_key_pair() -> SignalKeyPairResult {
    let key_pair = IdentityKeyPair::generate(&mut OsRng.unwrap_err());
    let public_key = key_pair.public_key().serialize().to_vec();
    let private_key = key_pair.serialize().to_vec();

    SignalKeyPairResult {
        public_key,
        private_key,
    }
}

/// Signed PreKey を生成
#[frb(sync)]
pub fn generate_signed_pre_key(
    identity_key_pair_bytes: Vec<u8>,
    signed_pre_key_id: u32,
) -> Result<SignalSignedPreKeyResult, String> {
    let identity_key_pair = IdentityKeyPair::try_from(identity_key_pair_bytes.as_slice())
        .map_err(|e| format!("Invalid identity key pair: {e}"))?;

    let signed_pre_key_pair = KeyPair::generate(&mut OsRng.unwrap_err());
    let signature = identity_key_pair
        .private_key()
        .calculate_signature(
            &signed_pre_key_pair.public_key.serialize(),
            &mut OsRng.unwrap_err(),
        )
        .map_err(|e| format!("Signature failed: {e}"))?;

    Ok(SignalSignedPreKeyResult {
        key_id: signed_pre_key_id,
        public_key: signed_pre_key_pair.public_key.serialize().to_vec(),
        private_key: signed_pre_key_pair.private_key.serialize().to_vec(),
        signature: signature.to_vec(),
    })
}

/// One-Time PreKey を生成
#[frb(sync)]
pub fn generate_one_time_pre_key(pre_key_id: u32) -> SignalKeyPairWithIdResult {
    let key_pair = KeyPair::generate(&mut OsRng.unwrap_err());

    SignalKeyPairWithIdResult {
        key_id: pre_key_id,
        public_key: key_pair.public_key.serialize().to_vec(),
        private_key: key_pair.private_key.serialize().to_vec(),
    }
}

/// KyberPreKey (ML-KEM-1024) を生成
///
/// PQXDH ハンドシェイクに使用。Identity Key で署名される。
/// 戻り値: KyberPreKeyRecord のシリアライズバイト列 + 公開鍵 + 署名
#[frb(sync)]
pub fn generate_kyber_pre_key(
    identity_key_pair_bytes: Vec<u8>,
    kyber_pre_key_id: u32,
) -> Result<SignalKyberPreKeyResult, String> {
    let identity_key_pair = IdentityKeyPair::try_from(identity_key_pair_bytes.as_slice())
        .map_err(|e| format!("Invalid identity key pair: {e}"))?;

    let kyber_record = KyberPreKeyRecord::generate(
        kem::KeyType::Kyber1024,
        KyberPreKeyId::from(kyber_pre_key_id),
        identity_key_pair.private_key(),
    )
    .map_err(|e| format!("Failed to generate KyberPreKey: {e}"))?;

    let public_key = kyber_record
        .key_pair()
        .map_err(|e| format!("Failed to get KyberPreKey key pair: {e}"))?
        .public_key
        .serialize()
        .to_vec();

    let signature = kyber_record
        .signature()
        .map_err(|e| format!("Failed to get KyberPreKey signature: {e}"))?
        .to_vec();

    let record_bytes = kyber_record
        .serialize()
        .map_err(|e| format!("Failed to serialize KyberPreKey: {e}"))?
        .to_vec();

    Ok(SignalKyberPreKeyResult {
        key_id: kyber_pre_key_id,
        public_key,
        signature,
        record_bytes,
    })
}

/// XEdDSA 署名を生成（Identity Key で署名）
///
/// libsignal の PrivateKey::calculate_signature() を使用。
/// Ed25519 ではなく XEdDSA（X25519 鍵で EdDSA 署名を行う方式）。
/// Signal Protocol の全ての署名はこの方式を使用する。
#[frb(sync)]
pub fn xeddsa_sign(identity_key_pair_bytes: Vec<u8>, data: Vec<u8>) -> Result<Vec<u8>, String> {
    let identity_key_pair = IdentityKeyPair::try_from(identity_key_pair_bytes.as_slice())
        .map_err(|e| format!("Invalid identity key pair: {e}"))?;

    let signature = identity_key_pair
        .private_key()
        .calculate_signature(&data, &mut OsRng.unwrap_err())
        .map_err(|e| format!("XEdDSA signature failed: {e}"))?;

    Ok(signature.to_vec())
}

/// XEdDSA 署名を検証
///
/// libsignal の PublicKey::verify_signature() を使用。
#[frb(sync)]
pub fn xeddsa_verify(
    public_key_bytes: Vec<u8>,
    data: Vec<u8>,
    signature: Vec<u8>,
) -> Result<bool, String> {
    let public_key = PublicKey::deserialize(&public_key_bytes)
        .map_err(|e| format!("Invalid public key: {e}"))?;

    Ok(public_key.verify_signature(&data, &signature))
}

/// libsignal のバージョン情報を返す（疎通確認用）
#[frb(sync)]
pub fn signal_protocol_version() -> String {
    "libsignal-protocol v0.94.1 (PQXDH + SPQR Triple Ratchet + Sender Key)".to_string()
}

// ============================================================
// 結果型（Dart 側に返すデータ）
// ============================================================

/// 鍵ペアの結果
pub struct SignalKeyPairResult {
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

/// Signed PreKey の結果
pub struct SignalSignedPreKeyResult {
    pub key_id: u32,
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
    pub signature: Vec<u8>,
}

/// ID 付き鍵ペアの結果
pub struct SignalKeyPairWithIdResult {
    pub key_id: u32,
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

/// KyberPreKey の結果
pub struct SignalKyberPreKeyResult {
    pub key_id: u32,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
    pub record_bytes: Vec<u8>,
}
