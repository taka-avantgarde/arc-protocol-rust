//! libsignal Sender Key (Group Messaging) API
//!
//! 設計原則:
//! - 暗号プリミティブは libsignal にのみ委譲 (CLAUDE.md ルール)
//! - 本ファイルが提供するのは **ストア層** のみ (`ArcSenderKeyStore`)
//!   メンバー除外時の Forward Secrecy (rotate) を可能にするため delete capability を追加
//!   (libsignal 標準の `InMemSenderKeyStore` には delete API がない)
//!
//! ストア実装本体は `crate::sender_key_store` に置き、frb スキャン外にしている
//! (frb は `crate::api::*` のみ scan)。

use std::sync::Mutex;

use flutter_rust_bridge::frb;
use libsignal_protocol::*;
use rand::rngs::OsRng;
use rand::TryRngCore;

use crate::sender_key_store::ArcSenderKeyStore;

lazy_static::lazy_static! {
    static ref SENDER_KEY_STORE: Mutex<ArcSenderKeyStore> =
        Mutex::new(ArcSenderKeyStore::new());
}

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("Failed to create tokio runtime");
    rt.block_on(f)
}

/// u32 -> DeviceId 変換ヘルパー (libsignal v0.92 以降 `DeviceId::new` 必須、1..=127)
fn to_device_id(id: u32) -> Result<DeviceId, String> {
    if id == 0 || id > 127 {
        return Err(format!("Invalid device id {id}: must be 1..=127"));
    }
    DeviceId::new(id as u8).map_err(|e| format!("Invalid device id {id}: {e}"))
}

/// Sender Key Distribution Message を作成
#[frb(sync)]
pub fn create_sender_key_distribution(
    sender_id: String,
    sender_device_id: u32,
    distribution_id_bytes: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let sender_addr = ProtocolAddress::new(sender_id, to_device_id(sender_device_id)?);
    let dist_id = uuid_from_bytes(&distribution_id_bytes)?;

    let mut store = SENDER_KEY_STORE
        .lock()
        .map_err(|e| format!("Lock error: {e}"))?;

    let skdm = block_on(create_sender_key_distribution_message(
        &sender_addr,
        dist_id,
        &mut *store,
        &mut OsRng.unwrap_err(),
    ))
    .map_err(|e| format!("Failed to create SKDM: {e}"))?;

    Ok(skdm.serialized().to_vec())
}

/// 受信した Sender Key Distribution Message を処理
#[frb(sync)]
pub fn process_sender_key_distribution(
    sender_id: String,
    sender_device_id: u32,
    distribution_message_bytes: Vec<u8>,
) -> Result<(), String> {
    let sender_addr = ProtocolAddress::new(sender_id, to_device_id(sender_device_id)?);

    let skdm = SenderKeyDistributionMessage::try_from(distribution_message_bytes.as_slice())
        .map_err(|e| format!("Invalid SKDM: {e}"))?;

    let mut store = SENDER_KEY_STORE
        .lock()
        .map_err(|e| format!("Lock error: {e}"))?;

    block_on(libsignal_protocol::process_sender_key_distribution_message(
        &sender_addr,
        &skdm,
        &mut *store,
    ))
    .map_err(|e| format!("Failed to process SKDM: {e}"))?;

    Ok(())
}

/// グループメッセージを暗号化（Sender Key）
#[frb(sync)]
pub fn group_encrypt(
    sender_id: String,
    sender_device_id: u32,
    distribution_id_bytes: Vec<u8>,
    plaintext: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let sender_addr = ProtocolAddress::new(sender_id, to_device_id(sender_device_id)?);
    let dist_id = uuid_from_bytes(&distribution_id_bytes)?;

    let mut store = SENDER_KEY_STORE
        .lock()
        .map_err(|e| format!("Lock error: {e}"))?;

    let ciphertext = block_on(libsignal_protocol::group_encrypt(
        &mut *store,
        &sender_addr,
        dist_id,
        &plaintext,
        &mut OsRng.unwrap_err(),
    ))
    .map_err(|e| format!("Group encrypt failed: {e}"))?;

    Ok(ciphertext.serialized().to_vec())
}

/// グループメッセージを復号（Sender Key）
#[frb(sync)]
pub fn group_decrypt(
    sender_id: String,
    sender_device_id: u32,
    ciphertext: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let sender_addr = ProtocolAddress::new(sender_id, to_device_id(sender_device_id)?);

    let mut store = SENDER_KEY_STORE
        .lock()
        .map_err(|e| format!("Lock error: {e}"))?;

    let plaintext = block_on(libsignal_protocol::group_decrypt(
        &ciphertext,
        &mut *store,
        &sender_addr,
    ))
    .map_err(|e| format!("Group decrypt failed: {e}"))?;

    Ok(plaintext)
}

/// Sender Key ストアをリセット（全データ削除）
#[frb(sync)]
pub fn reset_sender_key_store() -> Result<(), String> {
    let mut store = SENDER_KEY_STORE
        .lock()
        .map_err(|e| format!("Lock error: {e}"))?;
    *store = ArcSenderKeyStore::new();
    Ok(())
}

/// 指定した (sender, distribution_id) の Sender Key を Rust 側ストアから削除
///
/// メンバー除外時の Forward Secrecy 復旧で使用。
/// libsignal の `create_sender_key_distribution_message` は store に既存 entry が
/// あれば同じ Chain Key を再利用する仕様のため、rotate 前に必ず本関数で削除する。
///
/// 戻り値: 既存 entry を削除した場合 `true`、存在しなかった場合 `false`。
#[frb(sync)]
pub fn delete_sender_key(
    sender_id: String,
    sender_device_id: u32,
    distribution_id_bytes: Vec<u8>,
) -> Result<bool, String> {
    let sender_addr = ProtocolAddress::new(sender_id, to_device_id(sender_device_id)?);
    let dist_id = uuid_from_bytes(&distribution_id_bytes)?;

    let mut store = SENDER_KEY_STORE
        .lock()
        .map_err(|e| format!("Lock error: {e}"))?;

    Ok(store.delete(&sender_addr, dist_id))
}

/// 指定した sender/distribution の Sender Key レコードをエクスポート
///
/// SecureStorage に永続化するために使用。
/// 戻り値: SenderKeyRecord のシリアライズバイト列。存在しない場合は None。
#[frb(sync)]
pub fn export_sender_key(
    sender_id: String,
    sender_device_id: u32,
    distribution_id_bytes: Vec<u8>,
) -> Result<Option<Vec<u8>>, String> {
    let sender_addr = ProtocolAddress::new(sender_id, to_device_id(sender_device_id)?);
    let dist_id = uuid_from_bytes(&distribution_id_bytes)?;

    let mut store = SENDER_KEY_STORE
        .lock()
        .map_err(|e| format!("Lock error: {e}"))?;

    let record = block_on(SenderKeyStore::load_sender_key(
        &mut *store,
        &sender_addr,
        dist_id,
    ))
    .map_err(|e| format!("Failed to load sender key: {e}"))?;

    match record {
        Some(r) => {
            Ok(Some(r.serialize().map_err(|e| {
                format!("Failed to serialize sender key: {e}")
            })?))
        }
        None => Ok(None),
    }
}

/// バイト列から Sender Key レコードをインポート
///
/// SecureStorage から復元する際に使用。
#[frb(sync)]
pub fn import_sender_key(
    sender_id: String,
    sender_device_id: u32,
    distribution_id_bytes: Vec<u8>,
    record_bytes: Vec<u8>,
) -> Result<(), String> {
    let sender_addr = ProtocolAddress::new(sender_id, to_device_id(sender_device_id)?);
    let dist_id = uuid_from_bytes(&distribution_id_bytes)?;

    let record = SenderKeyRecord::deserialize(&record_bytes)
        .map_err(|e| format!("Invalid sender key record: {e}"))?;

    let mut store = SENDER_KEY_STORE
        .lock()
        .map_err(|e| format!("Lock error: {e}"))?;

    block_on(SenderKeyStore::store_sender_key(
        &mut *store,
        &sender_addr,
        dist_id,
        &record,
    ))
    .map_err(|e| format!("Failed to store sender key: {e}"))?;

    Ok(())
}

/// 指定した sender/distribution の Sender Key が存在するか確認
#[frb(sync)]
pub fn has_sender_key(
    sender_id: String,
    sender_device_id: u32,
    distribution_id_bytes: Vec<u8>,
) -> Result<bool, String> {
    let sender_addr = ProtocolAddress::new(sender_id, to_device_id(sender_device_id)?);
    let dist_id = uuid_from_bytes(&distribution_id_bytes)?;

    let mut store = SENDER_KEY_STORE
        .lock()
        .map_err(|e| format!("Lock error: {e}"))?;

    let record = block_on(SenderKeyStore::load_sender_key(
        &mut *store,
        &sender_addr,
        dist_id,
    ))
    .map_err(|e| format!("Failed to load sender key: {e}"))?;

    Ok(record.is_some())
}

/// 16バイト配列から Uuid を生成
fn uuid_from_bytes(bytes: &[u8]) -> Result<uuid::Uuid, String> {
    if bytes.len() != 16 {
        return Err(format!("UUID must be 16 bytes, got {}", bytes.len()));
    }
    let mut arr = [0u8; 16];
    arr.copy_from_slice(bytes);
    Ok(uuid::Uuid::from_bytes(arr))
}

// ============================================================
// Unit tests (cargo test)
// ============================================================
#[cfg(test)]
mod tests {
    use super::*;

    fn dist_id_bytes_for(label: &str) -> Vec<u8> {
        // テスト用 16-byte UUID (label 先頭を埋め、UUID v5 風に整形)
        let mut bytes = [0u8; 16];
        let label_bytes = label.as_bytes();
        let copy_len = label_bytes.len().min(16);
        bytes[..copy_len].copy_from_slice(&label_bytes[..copy_len]);
        bytes[6] = (bytes[6] & 0x0f) | 0x50;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        bytes.to_vec()
    }

    #[test]
    fn delete_sender_key_removes_existing_entry() {
        reset_sender_key_store().expect("reset");
        let dist = dist_id_bytes_for("group_test_001");

        create_sender_key_distribution("alice".into(), 1, dist.clone()).expect("create SKDM");
        assert!(
            has_sender_key("alice".into(), 1, dist.clone()).unwrap(),
            "key must exist after create"
        );

        let removed =
            delete_sender_key("alice".into(), 1, dist.clone()).expect("delete sender key");
        assert!(removed, "delete must report existing-entry removal");

        assert!(
            !has_sender_key("alice".into(), 1, dist.clone()).unwrap(),
            "key must not exist after delete"
        );
    }

    #[test]
    fn delete_sender_key_returns_false_for_nonexistent() {
        reset_sender_key_store().expect("reset");
        let dist = dist_id_bytes_for("group_test_002");

        let removed =
            delete_sender_key("nonexistent_user".into(), 1, dist).expect("delete sender key");
        assert!(!removed, "delete must return false for nonexistent entry");
    }

    #[test]
    fn delete_then_recreate_yields_fresh_chain_key() {
        // Forward Secrecy: 削除 → 再作成で SKDM (chain key を含む) が新規生成されることを確認
        reset_sender_key_store().expect("reset");
        let dist = dist_id_bytes_for("group_test_003");

        let skdm1 = create_sender_key_distribution("alice".into(), 1, dist.clone())
            .expect("create 1st SKDM");

        delete_sender_key("alice".into(), 1, dist.clone()).expect("delete");

        let skdm2 = create_sender_key_distribution("alice".into(), 1, dist.clone())
            .expect("create 2nd SKDM after delete");

        assert_ne!(
            skdm1, skdm2,
            "SKDM bytes must differ after delete+recreate (Forward Secrecy)"
        );
    }
}
