use crate::select_device::select_device;
use dotenv::dotenv;
use pcap::{Active, Capture, Device};
mod select_device;
mod host_ids;
mod vpn;
mod real_time_analytics;
mod web_console;
mod database;

use crate::host_ids::packet_analysis::packet_analysis;
use std::error::Error;
use crate::database::connect;

fn main() -> Result<(), Box<dyn Error>> {
    // .envファイルを読み込む
    dotenv().expect(".envファイルの読み取りに失敗しました");

    //let env = dotenv::var("ENV").expect("ENVの取得に失敗しました");
    let timescale_host = dotenv::var("TIMESCALE_HOST").expect("TIMESCALE_HOSTの取得に失敗しました").as_str();
    let timescale_port = dotenv::var("TIMESCALE_PORT").expect("TIMESCALE_PORTの取得に失敗しました").parse::<u16>().expect("TIMESCALE_PORTのパースに失敗しました");
    let timescale_user = dotenv::var("TIMESCALE_USER").expect("TIMESCALE_USERの取得に失敗しました").as_str();
    let timescale_password = dotenv::var("TIMESCALE_PASSWORD").expect("TIMESCALE_PASSWORDの取得に失敗しました").as_str();
    let timescale_db = dotenv::var("TIMESCALE_DB").expect("TIMESCALE_DBの取得に失敗しました").as_str();

    connect(timescale_host, timescale_port, timescale_user, timescale_password, timescale_db);

    let (cap, device): (Capture<Active>, Device) = select_device()?;
    println!("デバイスの選択に成功しました: {}", device.name);

    if let Err(e) = packet_analysis(cap) {
        println!("パケットの解析に失敗しました: {}", e);
    }

    Ok(())
}