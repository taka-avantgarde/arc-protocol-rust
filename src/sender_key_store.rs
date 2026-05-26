//! HashMap-backed Sender Key Store (frb スキャン外に置く)
//!
//! flutter_rust_bridge は `crate::api::*` を scan して marshallable 型を自動生成する。
//! 内部 HashMap を持つストアを `api/` 内に置くと frb が ProtocolAddress 等を
//! opaque type として持ち込もうとして compile error になるため、ここに分離する。

use std::borrow::Cow;
use std::collections::HashMap;

use async_trait::async_trait;
use libsignal_protocol::*;
use uuid::Uuid;

/// HashMap-backed Sender Key Store with delete capability.
///
/// libsignal の `InMemSenderKeyStore` と同じ内部表現 (HashMap) を持つが、
/// `delete()` を追加で公開する。暗号プリミティブは触らず、`SenderKeyRecord` の
/// 格納 / 取り出し / 削除のみ。
#[derive(Default)]
pub struct ArcSenderKeyStore {
    keys: HashMap<(Cow<'static, ProtocolAddress>, Uuid), SenderKeyRecord>,
}

impl ArcSenderKeyStore {
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    /// 指定 (sender, distribution_id) の entry を削除。
    /// 返り値: 既存 entry を削除した場合 `true`、存在しなかった場合 `false`。
    pub fn delete(&mut self, sender: &ProtocolAddress, distribution_id: Uuid) -> bool {
        self.keys
            .remove(&(Cow::Owned(sender.clone()), distribution_id))
            .is_some()
    }
}

#[async_trait(?Send)]
impl SenderKeyStore for ArcSenderKeyStore {
    async fn store_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
        record: &SenderKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        self.keys.insert(
            (Cow::Owned(sender.clone()), distribution_id),
            record.clone(),
        );
        Ok(())
    }

    async fn load_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
    ) -> Result<Option<SenderKeyRecord>, SignalProtocolError> {
        Ok(self
            .keys
            .get(&(Cow::Owned(sender.clone()), distribution_id))
            .cloned())
    }
}
