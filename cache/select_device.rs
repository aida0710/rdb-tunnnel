use pnet::datalink;
use std::io::{self, Write};

pub fn select_device() -> Result<datalink::NetworkInterface, Box<dyn std::error::Error>> {
    let interfaces = datalink::interfaces();

    println!("利用可能なデバイス:");
    for (index, interface) in interfaces.iter().enumerate() {
        println!("{}. {}", index + 1, interface.name);
    }

    print!("キャプチャするデバイスの番号を入力してください: ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let device_index: usize = input.trim().parse()?;

    if device_index == 0 || device_index > interfaces.len() {
        return Err("無効なデバイス番号です".into());
    }

    let selected_interface = interfaces[device_index - 1].clone();
    println!("選択されたデバイス: {}", selected_interface.name);

    Ok(selected_interface)
}