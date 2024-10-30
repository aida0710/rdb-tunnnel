use futures::StreamExt;
use ipnetwork::IpNetwork;
use rtnetlink::new_connection;

pub async fn setup_interface(name: &str, ip: &str) -> Result<(), Box<dyn std::error::Error>> {
    // IPアドレスのパース
    let ip_net: IpNetwork = ip.parse()?;

    // netlinkコネクションの作成
    let (connection, handle, _) = new_connection()?;
    tokio::spawn(connection);

    // インターフェースIDの取得
    let interface = handle.link().get()
        .match_name(name.to_string())
        .execute()
        .next()
        .await
        .ok_or("Interface not found")?
        .ok_or("Interface not found")?;

    let if_index = interface.header.index;

    // IPアドレスの設定
    handle.address().add(
        if_index,
        ip_net.ip(),
        ip_net.prefix(),
    ).execute().await?;

    // インターフェースの有効化
    handle.link().set(if_index)
        .up()
        .execute()
        .await?;

    Ok(())
}