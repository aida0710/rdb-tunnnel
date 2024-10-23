use super::rules::{Rule, RuleAction, RuleSet};
use crate::core::error::TunnelResult;
use crate::network::packet::Packet;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct IDPSAnalyzer {
    rules: Arc<RwLock<RuleSet>>,
}

impl IDPSAnalyzer {
    pub fn new() -> Self {
        Self {
            rules: Arc::new(RwLock::new(RuleSet::new())),
        }
    }

    pub async fn analyze(&self, packet: &Packet) -> TunnelResult<bool> {
        let rules = self.rules.read().await;

        for rule in rules.get_rules() {
            if rule.matches(packet) {
                match rule.action {
                    RuleAction::Allow => return Ok(true),
                    RuleAction::Block => {
                        println!("IDPSによってパケットがブロックされました: {:?}", rule.name);
                        return Ok(false);
                    }
                    RuleAction::Alert => {
                        println!("IDPSアラート: {:?} - {:?}", rule.name, packet);
                        // アラートを記録するロジックをここに追加
                    }
                    RuleAction::Log => {
                        println!("IDPSログ: {:?} - {:?}", rule.name, packet);
                        // ログを記録するロジックをここに追加
                    }
                }
            }
        }

        Ok(true) // デフォルトで許可
    }

    pub async fn add_rule(&self, rule: Rule) {
        let mut rules = self.rules.write().await;
        rules.add_rule(rule);
    }

    pub async fn remove_rule(&self, name: &str) {
        let mut rules = self.rules.write().await;
        rules.remove_rule(name);
    }
}