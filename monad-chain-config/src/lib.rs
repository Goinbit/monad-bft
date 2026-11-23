// Copyright (C) 2025 Category Labs, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use execution_revision::MonadExecutionRevision;
use monad_types::{Epoch, Round, SeqNum};
use revision::{
    ChainParams, ChainRevision, MockChainRevision, MonadChainRevision, CHAIN_PARAMS_LATEST,
};
use serde::Deserialize;
use staking_config::{
    MonadStakingConfig, MERITIUM_STAKING_CONFIG, MONAD_DEVNET_STAKING_CONFIG,
    MONAD_MAINNET_STAKING_CONFIG, MONAD_TESTNET_STAKING_CONFIG,
};
use thiserror::Error;
use tracing::{info, warn};

pub mod execution_revision;
pub mod revision;
mod staking_config;

/// CHAIN_ID
pub const ETHEREUM_MAINNET_CHAIN_ID: u64 = 1;
pub const MONAD_MAINNET_CHAIN_ID: u64 = 143;
pub const MONAD_TESTNET_CHAIN_ID: u64 = 10143;
pub const MONAD_DEVNET_CHAIN_ID: u64 = 20143;

// Meritium chain ids. Mainnet is 888 (founder decision 2026-06-24). The live
// testnet runs as 20260401; devnet is given a distinct id to avoid an
// unreachable match arm alongside testnet in downstream consumers (monad-rpc).
pub const MERITIUM_MAINNET_CHAIN_ID: u64 = 888;
pub const MERITIUM_TESTNET_CHAIN_ID: u64 = 20_260_401;
pub const MERITIUM_DEVNET_CHAIN_ID: u64 = 20_260_402;

pub trait ChainConfig<CR: ChainRevision>: Copy + Clone {
    fn chain_id(&self) -> u64;
    fn get_epoch_length(&self) -> SeqNum;
    fn get_epoch_start_delay(&self) -> Round;
    fn get_staking_activation(&self) -> Epoch;
    fn get_block_reward_mon(&self, epoch: Epoch) -> u64;
    fn get_chain_revision(&self, round: Round) -> CR;
    fn get_execution_chain_revision(&self, execution_timestamp_s: u64) -> MonadExecutionRevision;
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MonadChainConfig {
    pub chain_id: u64,
    pub epoch_length: SeqNum,
    pub epoch_start_delay: Round,

    pub v_0_7_0_activation: Round,
    pub v_0_8_0_activation: Round,
    pub v_0_10_0_activation: Round,
    pub v_0_11_0_activation: Round,

    pub staking_config: MonadStakingConfig,

    pub execution_v_one_activation: u64,
    pub execution_v_two_activation: u64,
    pub execution_v_four_activation: u64,
}

#[derive(Debug, Error)]
pub enum ChainConfigError {
    WrongOverrideChainId(u64),
    UnsupportedChainId(u64),
}

impl std::fmt::Display for ChainConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl MonadChainConfig {
    pub fn new(
        chain_id: u64,
        devnet_override: Option<MonadChainConfig>,
    ) -> Result<Self, ChainConfigError> {
        if chain_id == MONAD_MAINNET_CHAIN_ID {
            if devnet_override.is_some() {
                warn!("Ignoring chain config from file in mainnet");
            }
            Ok(MONAD_MAINNET_CHAIN_CONFIG)
        } else if chain_id == MONAD_TESTNET_CHAIN_ID {
            if devnet_override.is_some() {
                warn!("Ignoring chain config from file in testnet");
            }
            Ok(MONAD_TESTNET_CHAIN_CONFIG)
        } else if chain_id == MONAD_DEVNET_CHAIN_ID {
            let Some(override_config) = devnet_override else {
                info!("Using default devnet chain config");
                return Ok(MONAD_DEVNET_CHAIN_CONFIG);
            };

            if override_config.chain_id != MONAD_DEVNET_CHAIN_ID {
                return Err(ChainConfigError::WrongOverrideChainId(
                    override_config.chain_id,
                ));
            }

            info!("Using override devnet chain config");
            Ok(override_config)
        } else if chain_id == MERITIUM_MAINNET_CHAIN_ID {
            if devnet_override.is_some() {
                warn!("Ignoring chain config from file in Meritium mainnet");
            }
            Ok(MERITIUM_MAINNET_CHAIN_CONFIG)
        } else if chain_id == MERITIUM_TESTNET_CHAIN_ID {
            if devnet_override.is_some() {
                warn!("Ignoring chain config from file in Meritium testnet");
            }
            Ok(MERITIUM_TESTNET_CHAIN_CONFIG)
        } else if chain_id == MERITIUM_DEVNET_CHAIN_ID {
            let Some(override_config) = devnet_override else {
                info!("Using default Meritium devnet chain config");
                return Ok(MERITIUM_DEVNET_CHAIN_CONFIG);
            };

            if override_config.chain_id != MERITIUM_DEVNET_CHAIN_ID {
                return Err(ChainConfigError::WrongOverrideChainId(
                    override_config.chain_id,
                ));
            }

            info!("Using override Meritium devnet chain config");
            Ok(override_config)
        } else {
            Err(ChainConfigError::UnsupportedChainId(chain_id))
        }
    }
}

impl ChainConfig<MonadChainRevision> for MonadChainConfig {
    fn chain_id(&self) -> u64 {
        self.chain_id
    }

    fn get_epoch_length(&self) -> SeqNum {
        self.epoch_length
    }

    fn get_epoch_start_delay(&self) -> Round {
        self.epoch_start_delay
    }

    fn get_staking_activation(&self) -> Epoch {
        self.staking_config.get_staking_activation()
    }

    fn get_block_reward_mon(&self, epoch: Epoch) -> u64 {
        self.staking_config.get_block_reward_mon(epoch)
    }

    #[allow(clippy::if_same_then_else)]
    fn get_chain_revision(&self, round: Round) -> MonadChainRevision {
        if round >= self.v_0_11_0_activation {
            MonadChainRevision::V_0_11_0
        } else if round >= self.v_0_10_0_activation {
            MonadChainRevision::V_0_10_0
        } else if round >= self.v_0_8_0_activation {
            MonadChainRevision::V_0_8_0
        } else if round >= self.v_0_7_0_activation {
            MonadChainRevision::V_0_7_0
        } else {
            MonadChainRevision::V_0_7_0
        }
    }

    fn get_execution_chain_revision(&self, execution_timestamp_s: u64) -> MonadExecutionRevision {
        if execution_timestamp_s >= self.execution_v_four_activation {
            MonadExecutionRevision::V_FOUR
        } else if execution_timestamp_s >= self.execution_v_two_activation {
            MonadExecutionRevision::V_TWO
        } else if execution_timestamp_s >= self.execution_v_one_activation {
            MonadExecutionRevision::V_ONE
        } else {
            MonadExecutionRevision::V_ZERO
        }
    }
}

const MONAD_DEVNET_CHAIN_CONFIG: MonadChainConfig = MonadChainConfig {
    chain_id: MONAD_DEVNET_CHAIN_ID,
    epoch_length: SeqNum(10_000),
    epoch_start_delay: Round(1_000),

    v_0_7_0_activation: Round::MIN,
    v_0_8_0_activation: Round::MIN,
    v_0_10_0_activation: Round::MIN,
    v_0_11_0_activation: Round::MIN,

    staking_config: MONAD_DEVNET_STAKING_CONFIG,

    execution_v_one_activation: 0,
    execution_v_two_activation: 0,
    execution_v_four_activation: 0,
};

const MONAD_TESTNET_CHAIN_CONFIG: MonadChainConfig = MonadChainConfig {
    chain_id: MONAD_TESTNET_CHAIN_ID,
    epoch_length: SeqNum(50_000),
    epoch_start_delay: Round(5_000),

    v_0_7_0_activation: Round::MIN,
    v_0_8_0_activation: Round::MIN,
    v_0_10_0_activation: Round::MIN,
    v_0_11_0_activation: Round::MIN,

    staking_config: MONAD_TESTNET_STAKING_CONFIG,

    execution_v_one_activation: 0,
    execution_v_two_activation: 0,
    execution_v_four_activation: 0,
};

// Mainnet uses latest version of testnet from genesis
const MONAD_MAINNET_CHAIN_CONFIG: MonadChainConfig = MonadChainConfig {
    chain_id: MONAD_MAINNET_CHAIN_ID,
    epoch_length: SeqNum(50_000),
    epoch_start_delay: Round(5_000),

    v_0_7_0_activation: Round::MIN,
    v_0_8_0_activation: Round::MIN,
    v_0_10_0_activation: Round(15_643_179), // 2025-08-13T13:30:00.000Z
    v_0_11_0_activation: Round(33_493_399), // Approx 2025-11-04T14:00:00.000Z

    staking_config: MONAD_MAINNET_STAKING_CONFIG,

    execution_v_one_activation: 0,
    execution_v_two_activation: 0,
    execution_v_four_activation: 1762266600, // 2025-11-04T14:30:00.000Z
};

// Meritium mainnet (chain id 888). A fresh fork starts at the latest protocol
// revision from genesis, so all consensus/execution hardforks activate at
// Round::MIN / timestamp 0.
//
// O-007/D-008 (2026-11-13, authorized): restore target epoch_length 50_000 for
// Meritium mainnet (aligned with Monad mainnet/testnet baseline). Epoch-boundary
// validator-set transition must be validated on testnet (multi-epoch, restart,
// recovery) before mainnet activation; see MAINNET_BLOCKERS M-06 and
// reports/audit/2026-11-11/M-06-implementation-checklist.md.
const MERITIUM_MAINNET_CHAIN_CONFIG: MonadChainConfig = MonadChainConfig {
    chain_id: MERITIUM_MAINNET_CHAIN_ID,
    epoch_length: SeqNum(50_000),
    epoch_start_delay: Round(5_000),

    v_0_7_0_activation: Round::MIN,
    v_0_8_0_activation: Round::MIN,
    v_0_10_0_activation: Round::MIN,
    v_0_11_0_activation: Round::MIN,

    staking_config: MERITIUM_STAKING_CONFIG,

    execution_v_one_activation: 0,
    execution_v_two_activation: 0,
    execution_v_four_activation: 0,
};

// Meritium testnet — the live testnet runs as chain id 20260401.
//
// O-007/D-008 (2026-11-13, authorized): restore target epoch_length 50_000.
// Requires epoch-boundary validation evidence (validator-set snapshot/transition,
// multi-epoch crossing, restart/recovery) before treating as production-safe.
const MERITIUM_TESTNET_CHAIN_CONFIG: MonadChainConfig = MonadChainConfig {
    chain_id: MERITIUM_TESTNET_CHAIN_ID,
    epoch_length: SeqNum(50_000),
    epoch_start_delay: Round(5_000),

    v_0_7_0_activation: Round::MIN,
    v_0_8_0_activation: Round::MIN,
    v_0_10_0_activation: Round::MIN,
    v_0_11_0_activation: Round::MIN,

    staking_config: MERITIUM_STAKING_CONFIG,

    execution_v_one_activation: 0,
    execution_v_two_activation: 0,
    execution_v_four_activation: 0,
};

// Meritium devnet — supports a node.toml override (like Monad devnet); shorter
// epoch for local iteration.
const MERITIUM_DEVNET_CHAIN_CONFIG: MonadChainConfig = MonadChainConfig {
    chain_id: MERITIUM_DEVNET_CHAIN_ID,
    epoch_length: SeqNum(10_000),
    epoch_start_delay: Round(1_000),

    v_0_7_0_activation: Round::MIN,
    v_0_8_0_activation: Round::MIN,
    v_0_10_0_activation: Round::MIN,
    v_0_11_0_activation: Round::MIN,

    staking_config: MERITIUM_STAKING_CONFIG,

    execution_v_one_activation: 0,
    execution_v_two_activation: 0,
    execution_v_four_activation: 0,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MockChainConfig {
    chain_params: &'static ChainParams,
    epoch_length: SeqNum,
    epoch_start_delay: Round,
}

impl Default for MockChainConfig {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl MockChainConfig {
    pub const DEFAULT: Self = Self {
        chain_params: &CHAIN_PARAMS_LATEST,
        epoch_length: SeqNum::MAX,
        epoch_start_delay: Round::MAX,
    };

    pub const fn new(chain_params: &'static ChainParams) -> Self {
        Self {
            chain_params,
            epoch_length: SeqNum::MAX,
            epoch_start_delay: Round::MAX,
        }
    }

    pub const fn new_with_epoch_params(
        chain_params: &'static ChainParams,
        epoch_length: SeqNum,
        epoch_start_delay: Round,
    ) -> Self {
        Self {
            chain_params,
            epoch_length,
            epoch_start_delay,
        }
    }
}

impl ChainConfig<MockChainRevision> for MockChainConfig {
    fn chain_id(&self) -> u64 {
        1337
    }

    fn get_epoch_length(&self) -> SeqNum {
        self.epoch_length
    }

    fn get_epoch_start_delay(&self) -> Round {
        self.epoch_start_delay
    }

    fn get_staking_activation(&self) -> Epoch {
        Epoch::MAX
    }

    fn get_block_reward_mon(&self, _epoch: Epoch) -> u64 {
        0
    }

    fn get_chain_revision(&self, _round: Round) -> MockChainRevision {
        MockChainRevision {
            chain_params: self.chain_params,
        }
    }

    fn get_execution_chain_revision(&self, _execution_timestamp_s: u64) -> MonadExecutionRevision {
        MonadExecutionRevision::LATEST
    }
}
