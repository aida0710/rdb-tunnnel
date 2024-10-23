use super::rules::{FirewallAction, FirewallRule};
use crate::core::error::TunnelResult;
use crate::network::packet::Packet;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct Firewall {
    rules: Arc<RwLock<Vec<FirewallRule>>>,
}

impl Firewall {
    pub fn new() -> Self {
        Self {
            rules: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub async fn check(&self, packet: &Packet) -> TunnelResult<bool> {
        let rules = self.rules.read().await;

        for rule in rules.iter() {
            if rule.matches(packet) {
                match rule.action {
                    FirewallAction::Accept => return Ok(true),
                    FirewallAction::Drop => {
                        println!("ファイアウォールによってパケットがドロップされました: {:?}", rule.name);
                        return Ok(false);
                    }
                    FirewallAction::Reject => {
                        println!("ファイアウォールによってパケットがリジェクトされました: {:?}", rule.name);
                        // リジェクトパケットを送信するロジックをここに追加
                        return Ok(false);
                    }
                }
            }
        }

        // デフォルトポリシー
        Ok(true)
    }

    pub async fn add_rule(&self, rule: FirewallRule) {
        let mut rules = self.rules.write().await;
        rules.push(rule);
        rules.sort_by_key(|r| std::cmp::Reverse(r.priority));
    }

    pub async fn remove_rule(&self, name: &str) {
        let mut rules = self.rules.write().await;
        rules.retain(|r| r.name != name);
    }
}