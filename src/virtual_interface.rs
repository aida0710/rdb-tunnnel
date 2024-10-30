use crate::error::InitProcessError;
use futures::TryStreamExt;
use ipnetwork::IpNetwork;
use rtnetlink::new_connection;

pub async fn setup_interface(name: &str, ip: &str) -> Result<(), InitProcessError> {
    // IPアドレスのパース
    let ip_net: IpNetwork = ip.parse()
        .map_err(|e| InitProcessError::VirtualInterfaceError(format!("IPアドレスのパースに失敗: {}", e)))?;

    // netlinkコネクションの作成
    let (connection, handle, _) = new_connection()
        .map_err(|e| InitProcessError::VirtualInterfaceError(format!("netlink接続の作成に失敗: {}", e)))?;
    tokio::spawn(connection);

    // インターフェースIDの取得
    let interface = handle.link().get()
        .match_name(name.to_string())
        .execute()
        .try_next()
        .await
        .map_err(|e| InitProcessError::VirtualInterfaceError(format!("インターフェース情報の取得に失敗: {}", e)))?
        .ok_or_else(|| InitProcessError::VirtualInterfaceError("インターフェースが見つかりません".to_string()))?;

    let if_index = interface.header.index;

    // IPアドレスの設定
    handle.address().add(
        if_index,
        ip_net.ip(),
        ip_net.prefix(),
    ).execute().await
        .map_err(|e| InitProcessError::VirtualInterfaceError(format!("IPアドレスの設定に失敗: {}", e)))?;

    // インターフェースの有効化
    handle.link().set(if_index)
        .up()
        .execute()
        .await
        .map_err(|e| InitProcessError::VirtualInterfaceError(format!("インターフェースの有効化に失敗: {}", e)))?;

    Ok(())
}