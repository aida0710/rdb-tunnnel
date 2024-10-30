use env_logger::{Builder, Target};
use log::LevelFilter;
use std::fs::File;
use std::io::Write;

pub fn setup_logger() -> Result<(), Box<dyn std::error::Error>> {
    // ログファイルを開く
    let file = File::create("application.log")?;

    // ビルダーでロガーをカスタマイズ
    Builder::new()
        // ログレベルの設定
        .filter_level(LevelFilter::Debug)
        // タイムスタンプ付きのフォーマット
        .format(|buf, record| {
            writeln!(
                buf,
                "{} [{}] {} - {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.level(),
                record.target(),  // モジュールパスが表示される
                record.args()
            )
        })
        // ファイルに出力
        .target(Target::Pipe(Box::new(file)))
        .init();

    Ok(())
}