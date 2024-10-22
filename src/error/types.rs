use thiserror::Error;
pub type Result<T> = std::result::Result<T, AppError>;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("データベースエラー: {0}")]
    Database(#[from] DbError),

    #[error("初期化エラー: {0}")]
    Init(#[from] InitProcessError),

    #[error("ネットワークエラー: {0}")]
    Network(String),

    #[error("パケット処理エラー: {0}")]
    PacketProcessing(String),

    #[error("ファイアウォールエラー: {0}")]
    Firewall(String),
}

#[derive(Error, Debug)]
pub enum DbError {
    #[error("接続エラー: {0}")]
    Connection(String),

    #[error("クエリ実行エラー: {0}")]
    Query(String),

    #[error("トランザクションエラー: {0}")]
    Transaction(String),
}

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
}