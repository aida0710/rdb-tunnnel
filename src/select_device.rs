use pcap::{Active, Capture, Device};
use std::io;
use std::io::Write;

pub fn select_device() -> Result<(Capture<Active>, Device), Box<dyn std::error::Error>> {
    let device_list = Device::list()?;

    println!("利用可能なデバイス:");
    for (index, device) in device_list.iter().enumerate() {
        println!("{}. {}", index + 1, device.name);
    }

    print!("キャプチャするデバイスの番号を入力してください: ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let device_index: usize = input.trim().parse()?;

    if device_index == 0 || device_index > device_list.len() {
        return Err("無効なデバイス番号です".into());
    }

    let selected_device = &device_list[device_index - 1];
    println!("選択されたデバイス: {}", selected_device.name);

    let cap = Capture::from_device(selected_device.clone())?
        .promisc(true)
        .snaplen(65535)
        .timeout(0)
        .immediate_mode(true)
        .buffer_size(3 * 1024 * 1024)
        .open()?;

    println!("パケットのキャプチャを開始します。Ctrl+Cで終了します。");

    Ok((cap, selected_device.clone()))
}
