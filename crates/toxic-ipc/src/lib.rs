//! Toxic IPC katmanı — GUI ↔ daemon haberleşmesi (Faz 5 stub).
//!
//! Faz 5'te Named Pipe (Windows) + JSON-RPC 2.0 ile tam implementasyon yapılacak.
//! Şu an sadece tip iskelet ve hata enum'u tanımlıdır.

#[cfg(not(feature = "std"))]
compile_error!("toxic-ipc requires the 'std' feature");

use serde::{Deserialize, Serialize};

/// IPC katmanı hatası.
#[derive(Debug)]
pub enum IpcError {
    /// Bağlantı kurulamadı.
    ConnectionFailed,
    /// Serileştirme / deserileştirme hatası.
    Encoding(String),
    /// Protokol ihlali.
    Protocol(String),
}

impl core::fmt::Display for IpcError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            IpcError::ConnectionFailed    => write!(f, "IPC bağlantısı kurulamadı"),
            IpcError::Encoding(msg)       => write!(f, "Kodlama hatası: {msg}"),
            IpcError::Protocol(msg)       => write!(f, "Protokol hatası: {msg}"),
        }
    }
}

impl std::error::Error for IpcError {}

/// IPC istek türleri (Faz 5'te genişletilecek).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    /// Ping — bağlantı canlılık kontrolü.
    Ping,
    /// Daemon sürüm bilgisi iste.
    GetVersion,
}

/// IPC yanıt türleri (Faz 5'te genişletilecek).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    /// Pong — Ping yanıtı.
    Pong,
    /// Daemon sürüm bilgisi.
    Version { version: String },
    /// Hata yanıtı.
    Error { code: u32, message: String },
}
