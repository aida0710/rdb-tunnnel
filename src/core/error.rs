use thiserror::Error;

#[derive(Error, Debug)]
pub enum TunnelError {
    #[error("設定エラー: {0}")]
    Config(String),

    #[error("キャプチャエラー: {0}")]
    Capture(#[from] std::io::Error),

    #[error("IDPSエラー: {0}")]
    IDPS(String),

    #[error("ファイアウォールエラー: {0}")]
    Firewall(String),

    #[error("データベースエラー: {0}")]
    Database(#[from] tokio_postgres::Error),

    #[error("パケット注入エラー: {0}")]
    Injection(String),

    #[error("タイムアウト")]
    Timeout,

    #[error("予期せぬエラー: {0}")]
    Unexpected(String),
}

pub type TunnelResult<T> = Result<T, TunnelError>;
