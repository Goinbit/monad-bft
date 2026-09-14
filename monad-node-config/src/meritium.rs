// Copyright (C) 2026 Meritium contributors.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

use serde::Deserialize;

/// Optional Meritium oracle controls in `node.toml`.
///
/// This table is intentionally optional:
/// - table omitted => upstream-compatible noop bundle
/// - table present => flags and thresholds from this struct
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct MeritiumConfig {
    pub rewards_enabled: bool,
    pub audits_enabled: bool,
    pub verifications_enabled: bool,
    /// Feature gate for emitting 0x1004 registration system txs.
    pub registrations_enabled: bool,
    pub vrf_seed: Option<String>,
    /// Optional founder vesting contract wallet.
    ///
    /// When set, reward-oracle wiring can route founder reward emissions to
    /// this single address instead of founder EOAs.
    pub founder_vesting_address: Option<String>,
    /// Optional block-height activation for founder vesting routing.
    ///
    /// When set together with `founder_vesting_address`, reward routing stays
    /// on legacy founder wallets before this sequence number and switches to
    /// the vesting address at/after this sequence.
    pub founder_vesting_activation_seq: Option<u64>,
    pub threshold_m: u8,
    pub threshold_n: u8,
    pub poaw_endpoint: Option<String>,
    /// Optional TaskMarket contract address used for Skill mining reward signals.
    pub task_market_address: Option<String>,
    /// Optional JSON-RPC endpoint used by the reward-signal indexer.
    pub reward_signal_rpc_url: Option<String>,
    /// Blocks to wait between observing a TaskRewardSignal and emitting reward txs.
    pub reward_signal_delay_blocks: u64,
    /// How many source blocks to retain before pruning indexed pending batches.
    pub reward_signal_prune_depth_blocks: u64,
    /// Optional AgentRegistry contract address (used by registration oracle paths).
    pub agent_registry_address: Option<String>,
    /// Optional ValidatorRegistry contract address (used by C4 option B paths).
    pub validator_registry_address: Option<String>,
}

impl Default for MeritiumConfig {
    fn default() -> Self {
        Self {
            rewards_enabled: false,
            audits_enabled: false,
            verifications_enabled: false,
            registrations_enabled: false,
            vrf_seed: None,
            founder_vesting_address: None,
            founder_vesting_activation_seq: None,
            threshold_m: 2,
            threshold_n: 3,
            poaw_endpoint: None,
            task_market_address: None,
            reward_signal_rpc_url: None,
            reward_signal_delay_blocks: 2,
            reward_signal_prune_depth_blocks: 4_096,
            agent_registry_address: None,
            validator_registry_address: None,
        }
    }
}

impl MeritiumConfig {
    pub fn reward_signal_indexing_enabled(&self) -> bool {
        self.task_market_address.is_some() && self.reward_signal_rpc_url.is_some()
    }

    /// Semantic checks that serde cannot encode directly.
    pub fn validate(&self) -> Result<(), String> {
        if self.threshold_m > self.threshold_n {
            return Err(format!(
                "invalid meritium threshold: threshold_m ({}) must be <= threshold_n ({})",
                self.threshold_m, self.threshold_n
            ));
        }
        if self.verifications_enabled && self.threshold_n == 0 {
            return Err(
                "invalid meritium threshold: threshold_n must be > 0 when verifications_enabled=true"
                    .to_owned(),
            );
        }

        if let Some(seed) = &self.vrf_seed {
            let raw = seed
                .strip_prefix("0x")
                .or_else(|| seed.strip_prefix("0X"))
                .unwrap_or(seed.as_str());

            if raw.len() != 64 {
                return Err(format!(
                    "invalid meritium vrf_seed length: expected 64 hex chars, got {}",
                    raw.len()
                ));
            }
            if !raw.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err("invalid meritium vrf_seed: expected hex chars [0-9a-fA-F]".to_owned());
            }
        }

        if let Some(addr) = &self.founder_vesting_address {
            let raw = addr
                .strip_prefix("0x")
                .or_else(|| addr.strip_prefix("0X"))
                .unwrap_or(addr.as_str());
            if raw.len() != 40 {
                return Err(format!(
                    "invalid meritium founder_vesting_address length: expected 40 hex chars, got {}",
                    raw.len()
                ));
            }
            if !raw.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(
                    "invalid meritium founder_vesting_address: expected hex chars [0-9a-fA-F]"
                        .to_owned(),
                );
            }
            if raw.eq_ignore_ascii_case("0000000000000000000000000000000000000000") {
                return Err(
                    "invalid meritium founder_vesting_address: zero address not allowed".to_owned(),
                );
            }
        }

        if self.founder_vesting_activation_seq.is_some() && self.founder_vesting_address.is_none() {
            return Err(
                "invalid meritium founder_vesting_activation_seq: requires founder_vesting_address"
                    .to_owned(),
            );
        }

        if self.task_market_address.is_some() ^ self.reward_signal_rpc_url.is_some() {
            return Err(
                "invalid meritium reward signal indexer: task_market_address and reward_signal_rpc_url must be set together"
                    .to_owned(),
            );
        }

        if self.reward_signal_indexing_enabled() {
            if !self.rewards_enabled {
                return Err(
                    "invalid meritium reward signal indexer: rewards_enabled must be true"
                        .to_owned(),
                );
            }
            if self.reward_signal_delay_blocks == 0 {
                return Err("invalid meritium reward_signal_delay_blocks: must be > 0".to_owned());
            }
            if let Some(addr) = &self.task_market_address {
                validate_nonzero_hex_address(addr, "task_market_address")?;
            }
            if let Some(url) = &self.reward_signal_rpc_url {
                if !(url.starts_with("http://") || url.starts_with("https://")) {
                    return Err(
                        "invalid meritium reward_signal_rpc_url: expected http:// or https://"
                            .to_owned(),
                    );
                }
            }
        }

        Ok(())
    }
}

fn validate_nonzero_hex_address(addr: &str, field: &'static str) -> Result<(), String> {
    let raw = addr
        .strip_prefix("0x")
        .or_else(|| addr.strip_prefix("0X"))
        .unwrap_or(addr);
    if raw.len() != 40 {
        return Err(format!(
            "invalid meritium {} length: expected 40 hex chars, got {}",
            field,
            raw.len()
        ));
    }
    if !raw.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(format!(
            "invalid meritium {}: expected hex chars [0-9a-fA-F]",
            field
        ));
    }
    if raw.eq_ignore_ascii_case("0000000000000000000000000000000000000000") {
        return Err(format!(
            "invalid meritium {}: zero address not allowed",
            field
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Wrapper {
        #[serde(default)]
        meritium: Option<MeritiumConfig>,
    }

    #[test]
    fn wrapper_without_meritium_table_parses() {
        let parsed: Wrapper = toml::from_str("").expect("parse should succeed");
        assert!(parsed.meritium.is_none());
    }

    #[test]
    fn empty_meritium_table_uses_defaults() {
        let parsed: Wrapper = toml::from_str("[meritium]").expect("parse should succeed");
        let cfg = parsed.meritium.expect("meritium table missing");
        assert_eq!(cfg, MeritiumConfig::default());
    }

    #[test]
    fn unknown_meritium_field_fails_due_to_deny_unknown_fields() {
        let err = toml::from_str::<Wrapper>("[meritium]\nreward_enabled=true")
            .expect_err("parse should fail");
        let msg = err.to_string();
        assert!(msg.contains("unknown field"));
    }

    #[test]
    fn validate_rejects_threshold_m_greater_than_n() {
        let cfg = MeritiumConfig {
            threshold_m: 4,
            threshold_n: 3,
            ..MeritiumConfig::default()
        };
        let err = cfg.validate().expect_err("validate should fail");
        assert!(err.contains("threshold_m"));
    }

    #[test]
    fn validate_rejects_verification_with_zero_threshold_n() {
        let cfg = MeritiumConfig {
            verifications_enabled: true,
            threshold_n: 0,
            ..MeritiumConfig::default()
        };
        let err = cfg.validate().expect_err("validate should fail");
        assert!(err.contains("threshold_n"));
    }

    #[test]
    fn validate_accepts_hex_seed_with_prefix() {
        let cfg = MeritiumConfig {
            vrf_seed: Some(
                "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f".to_owned(),
            ),
            ..MeritiumConfig::default()
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn validate_rejects_short_seed() {
        let cfg = MeritiumConfig {
            vrf_seed: Some("0x1234".to_owned()),
            ..MeritiumConfig::default()
        };
        let err = cfg.validate().expect_err("validate should fail");
        assert!(err.contains("length"));
    }

    #[test]
    fn validate_rejects_non_hex_seed() {
        let cfg = MeritiumConfig {
            vrf_seed: Some(
                "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1g".to_owned(),
            ),
            ..MeritiumConfig::default()
        };
        let err = cfg.validate().expect_err("validate should fail");
        assert!(err.contains("expected hex"));
    }

    #[test]
    fn validate_accepts_founder_vesting_address() {
        let cfg = MeritiumConfig {
            founder_vesting_address: Some("0x111122223333444455556666777788889999AaAa".to_owned()),
            ..MeritiumConfig::default()
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn validate_rejects_short_founder_vesting_address() {
        let cfg = MeritiumConfig {
            founder_vesting_address: Some("0x1234".to_owned()),
            ..MeritiumConfig::default()
        };
        let err = cfg.validate().expect_err("validate should fail");
        assert!(err.contains("founder_vesting_address"));
    }

    #[test]
    fn validate_rejects_zero_founder_vesting_address() {
        let cfg = MeritiumConfig {
            founder_vesting_address: Some("0x0000000000000000000000000000000000000000".to_owned()),
            ..MeritiumConfig::default()
        };
        let err = cfg.validate().expect_err("validate should fail");
        assert!(err.contains("zero address"));
    }

    #[test]
    fn validate_accepts_founder_vesting_activation_seq() {
        let cfg = MeritiumConfig {
            founder_vesting_address: Some("0x111122223333444455556666777788889999AaAa".to_owned()),
            founder_vesting_activation_seq: Some(340_500),
            ..MeritiumConfig::default()
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn validate_rejects_activation_without_founder_vesting_address() {
        let cfg = MeritiumConfig {
            founder_vesting_activation_seq: Some(1),
            ..MeritiumConfig::default()
        };
        let err = cfg.validate().expect_err("validate should fail");
        assert!(err.contains("requires founder_vesting_address"));
    }

    #[test]
    fn validate_accepts_reward_signal_indexer_config() {
        let parsed: Wrapper = toml::from_str(
            r#"
            [meritium]
            rewards_enabled = true
            task_market_address = "0x111122223333444455556666777788889999aaaa"
            reward_signal_rpc_url = "http://127.0.0.1:8545"
            reward_signal_delay_blocks = 2
            reward_signal_prune_depth_blocks = 64
            "#,
        )
        .expect("parse should succeed");
        let cfg = parsed.meritium.expect("meritium config");

        assert!(cfg.validate().is_ok());
        assert!(cfg.reward_signal_indexing_enabled());
        assert_eq!(cfg.reward_signal_delay_blocks, 2);
        assert_eq!(cfg.reward_signal_prune_depth_blocks, 64);
    }

    #[test]
    fn validate_rejects_reward_signal_rpc_without_task_market_address() {
        let cfg = MeritiumConfig {
            rewards_enabled: true,
            reward_signal_rpc_url: Some("http://127.0.0.1:8545".to_owned()),
            ..MeritiumConfig::default()
        };

        let err = cfg.validate().expect_err("validate should fail");
        assert!(err.contains("task_market_address"));
    }

    #[test]
    fn validate_rejects_reward_signal_indexing_when_rewards_disabled() {
        let cfg = MeritiumConfig {
            task_market_address: Some("0x111122223333444455556666777788889999aaaa".to_owned()),
            reward_signal_rpc_url: Some("http://127.0.0.1:8545".to_owned()),
            ..MeritiumConfig::default()
        };

        let err = cfg.validate().expect_err("validate should fail");
        assert!(err.contains("rewards_enabled"));
    }

    #[test]
    fn validate_rejects_zero_reward_signal_delay() {
        let cfg = MeritiumConfig {
            rewards_enabled: true,
            task_market_address: Some("0x111122223333444455556666777788889999aaaa".to_owned()),
            reward_signal_rpc_url: Some("http://127.0.0.1:8545".to_owned()),
            reward_signal_delay_blocks: 0,
            ..MeritiumConfig::default()
        };

        let err = cfg.validate().expect_err("validate should fail");
        assert!(err.contains("reward_signal_delay_blocks"));
    }
}
