use thiserror::Error;

#[derive(Error, Debug)]
pub enum InitProcessError {
    #[error("環境変数ファイルの読み取りに失敗しました: {0}")]
    EnvFileReadError(String),

    #[error("環境変数の取得に失敗しました: {0}")]
    EnvVarError(String),

    #[error("環境変数の文字列変換に失敗しました: {0}")]
    EnvVarParseError(String),

    #[error("デバイスの選択に失敗しました: {0}")]
    DeviceSelectionError(String),

    #[error("パケットの解析に失敗しました: {0}")]
    PacketAnalysisError(String),

    #[error("データベース接続に失敗しました: {0}")]
    DatabaseConnectionError(String),

    #[error("仮想デバイスの作成に失敗しました: {0}")]
    VirtualInterfaceError(String),
}