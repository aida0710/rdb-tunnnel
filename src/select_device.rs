use pnet::datalink::{self, NetworkInterface};
use std::io::{self, Write};

pub fn select_device() -> Result<NetworkInterface, String> {
    let interfaces = datalink::interfaces();

    println!("\n利用可能なネットワークインターフェース:");
    for (idx, interface) in interfaces.iter().enumerate() {
        println!("{}. {} ({})",
                 idx + 1,
                 interface.name,
                 interface.description
        );
    }

    print!("\nインターフェースを選択してください [1-{}]: ", interfaces.len());
    io::stdout().flush().map_err(|e| e.to_string())?;

    let mut input = String::new();
    io::stdin().read_line(&mut input).map_err(|e| e.to_string())?;

    let selection = input.trim().parse::<usize>()
        .map_err(|_| "無効な選択です".to_string())?;

    if selection < 1 || selection > interfaces.len() {
        return Err("選択範囲外です".to_string());
    }

    Ok(interfaces[selection - 1].clone())
}