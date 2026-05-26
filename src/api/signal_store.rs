//! libsignal Store 実装 + セッション確立・暗号化/復号 API
//!
//! libsignal v0.92.2 (PQXDH + SPQR Triple Ratchet) にアップグレード済み。
//! 主な変更:
//! - `PreKeyBundle::new` が 10 引数化、Kyber 必須 (PQXDH 必須、X3DH フォールバック廃止)
//! - `message_encrypt` / `message_decrypt_prekey` に `local_address` と `now` が追加
//! - `DeviceId` が newtype (u8, 1..=127) 化 — `DeviceId::new()` で明示構築
//!
//! libsignal の protocol 関数は async だが、Store の trait objects が Send ではないため、
//! flutter_rust_bridge の async ラッパーと互換性がない。
//! 解決策: 同期関数内で専用の single-thread runtime を使って block_on する。

use flutter_rust_bridge::frb;
use libsignal_protocol::*;
use rand::rngs::OsRng;
use rand::TryRngCore;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::SystemTime;

// ============================================================
// グローバル状態
// ============================================================

lazy_static::lazy_static! {
    static ref STORE: Mutex<Option<InMemSignalProtocolStore>> = Mutex::new(None);
    static ref SESSION_MAP: Mutex<HashMap<String, bool>> = Mutex::new(HashMap::new());
}

/// 内部 async 関数を同期的に実行するヘルパー
fn block_on<F: std::future::Future>(f: F) -> F::Output {
    // single-thread runtime で実行（Send 制約を回避）
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

// ============================================================
// ストア初期化
// ============================================================

/// ストアを初期化（アプリ起動時に1回呼ぶ）
#[frb(sync)]
pub fn init_signal_store(
    identity_key_pair_bytes: Vec<u8>,
    registration_id: u32,
) -> Result<(), String> {
    let identity_key_pair = IdentityKeyPair::try_from(identity_key_pair_bytes.as_slice())
        .map_err(|e| format!("Invalid identity key pair: {e}"))?;

    let store = InMemSignalProtocolStore::new(identity_key_pair, registration_id)
        .map_err(|e| format!("Failed to create store: {e}"))?;

    let mut guard = STORE.lock().map_err(|e| format!("Lock error: {e}"))?;
    *guard = Some(store);

    Ok(())
}

/// Signed PreKey をストアに登録
#[frb(sync)]
pub fn store_signed_pre_key(
    key_id: u32,
    public_key_bytes: Vec<u8>,
    private_key_bytes: Vec<u8>,
    signature_bytes: Vec<u8>,
) -> Result<(), String> {
    let mut guard = STORE.lock().map_err(|e| format!("Lock error: {e}"))?;
    let store = guard.as_mut().ok_or("Store not initialized")?;

    let public_key = PublicKey::deserialize(&public_key_bytes)
        .map_err(|e| format!("Invalid public key: {e}"))?;
    let private_key = PrivateKey::deserialize(&private_key_bytes)
        .map_err(|e| format!("Invalid private key: {e}"))?;
    let key_pair = KeyPair::new(public_key, private_key);

    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let record = SignedPreKeyRecord::new(
        SignedPreKeyId::from(key_id),
        Timestamp::from_epoch_millis(timestamp * 1000),
        &key_pair,
        &signature_bytes,
    );

    block_on(SignedPreKeyStore::save_signed_pre_key(
        store,
        SignedPreKeyId::from(key_id),
        &record,
    ))
    .map_err(|e| format!("Failed to store signed pre key: {e}"))?;

    Ok(())
}

/// One-Time PreKey をストアに登録
#[frb(sync)]
pub fn store_one_time_pre_key(
    key_id: u32,
    public_key_bytes: Vec<u8>,
    private_key_bytes: Vec<u8>,
) -> Result<(), String> {
    let mut guard = STORE.lock().map_err(|e| format!("Lock error: {e}"))?;
    let store = guard.as_mut().ok_or("Store not initialized")?;

    let public_key = PublicKey::deserialize(&public_key_bytes)
        .map_err(|e| format!("Invalid public key: {e}"))?;
    let private_key = PrivateKey::deserialize(&private_key_bytes)
        .map_err(|e| format!("Invalid private key: {e}"))?;
    let key_pair = KeyPair::new(public_key, private_key);

    let record = PreKeyRecord::new(PreKeyId::from(key_id), &key_pair);

    block_on(PreKeyStore::save_pre_key(
        store,
        PreKeyId::from(key_id),
        &record,
    ))
    .map_err(|e| format!("Failed to store pre key: {e}"))?;

    Ok(())
}

// ============================================================
// セッション確立
// ============================================================

/// セッションを確立（送信者側 - Alice）
///
/// v0.92 以降 PQXDH 必須のため、Kyber PreKey (ML-KEM-1024) の提供は必須。
/// X3DH フォールバックは廃止された。
///
/// v0.94: `process_prekey_bundle` が local_address (own_address) を要求するため
/// 呼び出し側で渡す必要がある。
#[frb(sync)]
pub fn establish_session(
    own_address: String,
    own_device_id: u32,
    peer_address: String,
    peer_device_id: u32,
    peer_registration_id: u32,
    peer_identity_key_bytes: Vec<u8>,
    peer_signed_pre_key_id: u32,
    peer_signed_pre_key_bytes: Vec<u8>,
    peer_signed_pre_key_signature: Vec<u8>,
    peer_one_time_pre_key_id: Option<u32>,
    peer_one_time_pre_key_bytes: Option<Vec<u8>>,
    // PQXDH 必須 (v0.92+)
    peer_kyber_pre_key_id: u32,
    peer_kyber_pre_key_bytes: Vec<u8>,
    peer_kyber_pre_key_signature: Vec<u8>,
) -> Result<(), String> {
    let mut guard = STORE.lock().map_err(|e| format!("Lock error: {e}"))?;
    let store = guard.as_mut().ok_or("Store not initialized")?;

    let own_addr = ProtocolAddress::new(own_address, to_device_id(own_device_id)?);
    let peer_addr = ProtocolAddress::new(peer_address.clone(), to_device_id(peer_device_id)?);

    let peer_identity_key = IdentityKey::decode(&peer_identity_key_bytes)
        .map_err(|e| format!("Invalid peer identity key: {e}"))?;

    let peer_signed_pre_key = PublicKey::deserialize(&peer_signed_pre_key_bytes)
        .map_err(|e| format!("Invalid peer signed pre key: {e}"))?;

    let peer_kyber_public = kem::PublicKey::deserialize(&peer_kyber_pre_key_bytes)
        .map_err(|e| format!("Invalid peer KyberPreKey: {e}"))?;

    let one_time_pre_key = match (&peer_one_time_pre_key_id, &peer_one_time_pre_key_bytes) {
        (Some(_id), Some(bytes)) => Some(
            PublicKey::deserialize(bytes)
                .map_err(|e| format!("Invalid peer one-time pre key: {e}"))?,
        ),
        _ => None,
    };

    let bundle = PreKeyBundle::new(
        peer_registration_id,
        to_device_id(peer_device_id)?,
        peer_one_time_pre_key_id
            .zip(one_time_pre_key)
            .map(|(id, key)| (PreKeyId::from(id), key)),
        SignedPreKeyId::from(peer_signed_pre_key_id),
        peer_signed_pre_key,
        peer_signed_pre_key_signature,
        KyberPreKeyId::from(peer_kyber_pre_key_id),
        peer_kyber_public,
        peer_kyber_pre_key_signature,
        peer_identity_key,
    )
    .map_err(|e| format!("Failed to create PreKeyBundle: {e}"))?;

    block_on(process_prekey_bundle(
        &peer_addr,
        &own_addr,
        &mut store.session_store,
        &mut store.identity_store,
        &bundle,
        SystemTime::now(),
        &mut OsRng.unwrap_err(),
    ))
    .map_err(|e| format!("Failed to process prekey bundle: {e}"))?;

    let mut sessions = SESSION_MAP.lock().map_err(|e| format!("Lock error: {e}"))?;
    sessions.insert(peer_address, true);

    Ok(())
}

/// KyberPreKey を Rust ストアに保存（受信側の PQXDH 復号用）
#[frb(sync)]
pub fn store_kyber_pre_key(kyber_pre_key_record_bytes: Vec<u8>) -> Result<(), String> {
    let mut guard = STORE.lock().map_err(|e| format!("Lock error: {e}"))?;
    let store = guard.as_mut().ok_or("Store not initialized")?;

    let record = KyberPreKeyRecord::deserialize(&kyber_pre_key_record_bytes)
        .map_err(|e| format!("Invalid KyberPreKey record: {e}"))?;

    let key_id = record
        .id()
        .map_err(|e| format!("Failed to get KyberPreKey ID: {e}"))?;

    block_on(KyberPreKeyStore::save_kyber_pre_key(
        &mut store.kyber_pre_key_store,
        key_id,
        &record,
    ))
    .map_err(|e| format!("Failed to store KyberPreKey: {e}"))?;

    Ok(())
}

/// セッションが存在するか確認
#[frb(sync)]
pub fn has_signal_session(peer_address: String) -> bool {
    let sessions = SESSION_MAP.lock().unwrap_or_else(|e| e.into_inner());
    sessions.contains_key(&peer_address)
}

// ============================================================
// メッセージ暗号化/復号
// ============================================================

/// メッセージを暗号化
///
/// v0.92 以降は SPQR Triple Ratchet を自動適用 (新規セッションのみ)。
/// 既存の Double Ratchet セッションは互換性のため従来通り動作する。
///
/// `own_address` / `own_device_id` は SPQR Triple Ratchet の送信側 local_address。
/// Dart 側はログイン中ユーザーの UID + デバイス ID (Arc は単一デバイスモデルなので 1) を渡す。
#[frb(sync)]
pub fn signal_encrypt(
    own_address: String,
    own_device_id: u32,
    peer_address: String,
    peer_device_id: u32,
    plaintext: Vec<u8>,
) -> Result<SignalEncryptResult, String> {
    let own_addr = ProtocolAddress::new(own_address, to_device_id(own_device_id)?);

    let mut guard = STORE.lock().map_err(|e| format!("Lock error: {e}"))?;
    let store = guard.as_mut().ok_or("Store not initialized")?;

    let peer_addr = ProtocolAddress::new(peer_address, to_device_id(peer_device_id)?);

    let ciphertext = block_on(message_encrypt(
        &plaintext,
        &peer_addr,
        &own_addr,
        &mut store.session_store,
        &mut store.identity_store,
        SystemTime::now(),
        &mut OsRng.unwrap_err(),
    ))
    .map_err(|e| format!("Encryption failed: {e}"))?;

    let msg_type = ciphertext.message_type() as u8;
    let serialized = ciphertext.serialize().to_vec();

    Ok(SignalEncryptResult {
        ciphertext: serialized,
        message_type: msg_type,
    })
}

/// メッセージを復号
///
/// `own_address` / `own_device_id` は SPQR Triple Ratchet の受信側 local_address。
#[frb(sync)]
pub fn signal_decrypt(
    own_address: String,
    own_device_id: u32,
    peer_address: String,
    peer_device_id: u32,
    ciphertext: Vec<u8>,
    message_type: u8,
) -> Result<Vec<u8>, String> {
    let own_addr = ProtocolAddress::new(own_address, to_device_id(own_device_id)?);

    let mut guard = STORE.lock().map_err(|e| format!("Lock error: {e}"))?;
    let store = guard.as_mut().ok_or("Store not initialized")?;

    let peer_addr = ProtocolAddress::new(peer_address, to_device_id(peer_device_id)?);

    let plaintext = if message_type == CiphertextMessageType::PreKey as u8 {
        let msg = PreKeySignalMessage::try_from(ciphertext.as_slice())
            .map_err(|e| format!("Invalid PreKeySignalMessage: {e}"))?;

        block_on(message_decrypt_prekey(
            &msg,
            &peer_addr,
            &own_addr,
            &mut store.session_store,
            &mut store.identity_store,
            &mut store.pre_key_store,
            &mut store.signed_pre_key_store,
            &mut store.kyber_pre_key_store,
            &mut OsRng.unwrap_err(),
        ))
        .map_err(|e| format!("PreKey decryption failed: {e}"))?
    } else {
        let msg = SignalMessage::try_from(ciphertext.as_slice())
            .map_err(|e| format!("Invalid SignalMessage: {e}"))?;

        block_on(message_decrypt_signal(
            &msg,
            &peer_addr,
            &own_addr,
            &mut store.session_store,
            &mut store.identity_store,
            &mut OsRng.unwrap_err(),
        ))
        .map_err(|e| format!("Signal decryption failed: {e}"))?
    };

    Ok(plaintext)
}

// ============================================================
// セッション永続化
// ============================================================

/// セッションレコードをバイト列としてエクスポート
#[frb(sync)]
pub fn export_session(
    peer_address: String,
    peer_device_id: u32,
) -> Result<Option<Vec<u8>>, String> {
    let guard = STORE.lock().map_err(|e| format!("Lock error: {e}"))?;
    let store = guard.as_ref().ok_or("Store not initialized")?;

    let peer_addr = ProtocolAddress::new(peer_address, to_device_id(peer_device_id)?);

    let session = block_on(SessionStore::load_session(&store.session_store, &peer_addr))
        .map_err(|e| format!("Failed to load session: {e}"))?;

    Ok(session.map(|s| s.serialize().unwrap_or_default()))
}

/// バイト列からセッションレコードをインポート
#[frb(sync)]
pub fn import_session(
    peer_address: String,
    peer_device_id: u32,
    session_bytes: Vec<u8>,
) -> Result<(), String> {
    let mut guard = STORE.lock().map_err(|e| format!("Lock error: {e}"))?;
    let store = guard.as_mut().ok_or("Store not initialized")?;

    let peer_addr = ProtocolAddress::new(peer_address.clone(), to_device_id(peer_device_id)?);

    let record = SessionRecord::deserialize(&session_bytes)
        .map_err(|e| format!("Invalid session record: {e}"))?;

    block_on(SessionStore::store_session(
        &mut store.session_store,
        &peer_addr,
        &record,
    ))
    .map_err(|e| format!("Failed to store session: {e}"))?;

    let mut sessions = SESSION_MAP.lock().map_err(|e| format!("Lock error: {e}"))?;
    sessions.insert(peer_address, true);

    Ok(())
}

/// LOW-4: 全セッションを一括クリア（SESSION_MAP のみ）
///
/// 主にテスト用途 (setup/teardown) と緊急時の完全リセット。
/// `delete_signal_session` を全 peer に対して呼ぶより効率的。
/// InMemSignalProtocolStore のセッションレコード自体には触らないため、
/// 完全リセットしたい場合は `init_signal_store` で再初期化する経路と組み合わせる。
///
/// 戻り値: クリアしたエントリ数
#[frb(sync)]
pub fn clear_all_signal_sessions() -> Result<u32, String> {
    let mut sessions = SESSION_MAP.lock().map_err(|e| format!("Lock error: {e}"))?;
    let count = sessions.len() as u32;
    sessions.clear();
    Ok(count)
}

/// セッションを削除（セッションストア + Identity Store + SESSION_MAP すべてクリア）
#[frb(sync)]
pub fn delete_signal_session(peer_address: String) -> Result<(), String> {
    // SESSION_MAP からエントリ削除
    let mut sessions = SESSION_MAP.lock().map_err(|e| format!("Lock error: {e}"))?;
    sessions.remove(&peer_address);

    // InMemSignalProtocolStore からセッションレコードも削除
    let mut guard = STORE.lock().map_err(|e| format!("Lock error: {e}"))?;
    if let Some(store) = guard.as_mut() {
        // デバイスID 1 のセッションを削除（Arcは単一デバイスモデル）
        let peer_addr = ProtocolAddress::new(peer_address.clone(), to_device_id(1)?);
        // セッションストアから削除（空のセッションで上書き→実質削除）
        // libsignal の InMemSignalProtocolStore はセッション削除APIがないため、
        // ストア全体の再初期化時に古いセッションが残らないようにする
        let _ = block_on(async {
            // セッションを空で上書きすることで実質削除
            // Note: InMemSignalProtocolStore は内部 HashMap なので
            // 次の process_prekey_bundle で新しいセッションが作られる
            let empty_session = SessionRecord::new_fresh();
            SessionStore::store_session(&mut store.session_store, &peer_addr, &empty_session).await
        });
    }

    Ok(())
}

/// ピアの Identity Key 信頼情報をリセット（untrusted identity エラー時に呼ぶ）
///
/// InMemSignalProtocolStore の identity_store に新しい Identity Key を
/// 保存し直すことで、次回のセッション確立で新しい鍵を受け入れる。
#[frb(sync)]
pub fn reset_peer_identity(
    peer_address: String,
    new_identity_key_bytes: Vec<u8>,
) -> Result<(), String> {
    let mut guard = STORE.lock().map_err(|e| format!("Lock error: {e}"))?;
    let store = guard.as_mut().ok_or("Store not initialized")?;

    let peer_addr = ProtocolAddress::new(peer_address, to_device_id(1)?);
    let new_identity_key = IdentityKey::decode(&new_identity_key_bytes)
        .map_err(|e| format!("Invalid identity key: {e}"))?;

    block_on(IdentityKeyStore::save_identity(
        &mut store.identity_store,
        &peer_addr,
        &new_identity_key,
    ))
    .map_err(|e| format!("Failed to save new identity: {e}"))?;

    // セッションもクリア（新しい鍵で再確立するため）
    let _ = block_on(async {
        let empty_session = SessionRecord::new_fresh();
        SessionStore::store_session(&mut store.session_store, &peer_addr, &empty_session).await
    });

    let mut sessions = SESSION_MAP.lock().map_err(|e| format!("Lock error: {e}"))?;
    sessions.remove(peer_addr.name());

    Ok(())
}

// ============================================================
// 結果型
// ============================================================

pub struct SignalEncryptResult {
    pub ciphertext: Vec<u8>,
    pub message_type: u8,
}
