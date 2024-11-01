use thiserror::Error;

#[derive(Error, Debug)]
pub enum InitProcessError {
    #[error("ロガーのセットアップに失敗しました: {0}")]
    LoggerError(String),

    #[error("環境変数ファイルの読み込みに失敗しました: {0}")]
    EnvFileReadError(String),

    #[error("環境変数の取得に失敗しました: {0}")]
    EnvVarError(String),

    #[error("環境変数の解析に失敗しました: {0}")]
    EnvVarParseError(String),

    #[error("データベース接続エラー: {0}")]
    DatabaseConnectionError(String),

    #[error("仮想インターフェースのエラー: {0}")]
    VirtualInterfaceError(String),

    #[error("デバイス選択エラー: {0}")]
    DeviceSelectionError(String),

    #[error("パケット分析エラー: {0}")]
    PacketAnalysisError(String),
}

#[derive(Error, Debug)]
pub enum DatabaseError {
    #[error("データベース接続エラー: {0}")]
    ConnectionError(String),

    #[error("クエリ実行エラー: {0}")]
    QueryError(String),

    #[error("トランザクションエラー: {0}")]
    TransactionError(String),
}