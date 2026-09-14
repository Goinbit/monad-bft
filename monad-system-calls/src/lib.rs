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

//! This library is used to generate and validate expected system calls
//! for a block and generate transactions for them from the system sender.
//! To generate system calls for a block, `generate_system_calls()` should
//! be used which can then be converted into SystemTransaction(s) and
//! added to the block.

use alloy_consensus::{
    SignableTransaction, Transaction, TxEnvelope, TxLegacy, transaction::Recovered,
};
use alloy_primitives::{Address, B256, U256, hex};
use alloy_rlp::Encodable;
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use monad_chain_config::{ChainConfig, revision::ChainRevision};
use monad_eth_types::ValidatedTx;
use monad_types::{Epoch, GENESIS_SEQ_NUM, SeqNum};
use staking_contract::{StakingContractCall, StakingContractTransaction};
use std::sync::{OnceLock, RwLock};
use validator::SystemTransactionError;
use {
    agent_audit_contract::{AgentAuditCall, AgentAuditEntry, AgentAuditTransaction},
    agent_reward_contract::{AgentRewardCall, AgentRewardEntry, AgentRewardTransaction},
    agent_verification_contract::{
        AgentVerificationCall, AgentVerificationEntry, AgentVerificationTransaction,
    },
};

pub mod agent_audit_contract;
pub mod agent_reward_contract;
pub mod agent_verification_contract;
pub mod staking_contract;
pub mod validator;

// System-sender private key source.
//
// Production/runtime: provided via env var MERITIUM_SYSTEM_SENDER_PRIV_KEY
// as 32-byte hex (with or without 0x prefix).
//
// Tests: use a deterministic test key to keep unit tests stable without
// external env wiring.
#[cfg(any(test, feature = "test-system-sender-key"))]
pub(crate) const TEST_SYSTEM_SENDER_PRIV_KEY: B256 = B256::new(hex!(
    "b0358e6d701a955d9926676f227e40172763296b317ff554e49cdf2c2c35f8a7"
));
pub const SYSTEM_SENDER_ETH_ADDRESS: Address =
    Address::new(hex!("0x6f49a8F621353f12378d0046E7d7e4b9B249DC9e"));

const MERITIUM_HALVING_INTERVAL_BLOCKS: u64 = 2_000_000;
const MERITIUM_PER_AGENT_REWARD_WEI: u128 = 594_000_000_000_000_000;
const MERITIUM_PROTOCOL_FEE_WEI: u128 = 30_000_000_000_000_000;
const MERITIUM_PROTOCOL_FUND_ADDRESS: Address =
    Address::new(hex!("0x3Ca55197a258FBC3ABFDB3F3d870D7Cca8b52DEC"));
const MERITIUM_DEFAULT_AGENT_WALLETS: [Address; 5] = [
    Address::new(hex!("EF08abD86c983EaD2908663d1115fb8Abe4eF176")),
    Address::new(hex!("c50DE5Cfda3663BB128c22C5E53242548d8d752D")),
    Address::new(hex!("A0195DD3335B6DACFdB4f424a5A2D1DB4f6B42E1")),
    Address::new(hex!("086726F4C695437D9dA5c6B22EddddFfD06Ca004")),
    Address::new(hex!("B1157CC5c703577d40262370f1FC30C2797f4D58")),
];

#[derive(Clone, Debug, Default)]
pub struct MeritiumSystemCallConfig {
    pub rewards_enabled: bool,
    pub audits_enabled: bool,
    pub verifications_enabled: bool,
    pub founder_vesting_address: Option<Address>,
    pub founder_vesting_activation_seq: Option<u64>,
}

fn meritium_validation_config() -> &'static RwLock<MeritiumSystemCallConfig> {
    static CONFIG: OnceLock<RwLock<MeritiumSystemCallConfig>> = OnceLock::new();
    CONFIG.get_or_init(|| RwLock::new(MeritiumSystemCallConfig::default()))
}

pub fn set_meritium_system_call_config(config: MeritiumSystemCallConfig) {
    *meritium_validation_config()
        .write()
        .expect("meritium validation config lock poisoned") = config;
}

fn get_meritium_system_call_config() -> MeritiumSystemCallConfig {
    meritium_validation_config()
        .read()
        .expect("meritium validation config lock poisoned")
        .clone()
}

fn parse_env_system_sender_key(raw: &str) -> Result<B256, String> {
    let trimmed = raw.trim();
    let no_prefix = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    if no_prefix.len() != 64 {
        return Err(format!("expected 64 hex chars, got {}", no_prefix.len()));
    }
    let bytes =
        hex::decode(no_prefix).map_err(|err| format!("invalid hex in system sender key: {err}"))?;
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "system sender key must decode to 32 bytes".to_owned())?;
    Ok(B256::from(array))
}

fn system_sender_priv_key() -> &'static B256 {
    static KEY: OnceLock<B256> = OnceLock::new();
    KEY.get_or_init(|| match std::env::var("MERITIUM_SYSTEM_SENDER_PRIV_KEY") {
        Ok(v) => parse_env_system_sender_key(&v)
            .unwrap_or_else(|err| panic!("invalid MERITIUM_SYSTEM_SENDER_PRIV_KEY: {err}")),
        // `cfg(test)` covers this crate's own unit tests; the
        // `test-system-sender-key` feature lets DOWNSTREAM crates' test builds
        // (which compile this as a non-test dependency) use the test key too.
        // Production builds must have neither and will panic below.
        #[cfg(any(test, feature = "test-system-sender-key"))]
        Err(_) => TEST_SYSTEM_SENDER_PRIV_KEY,
        #[cfg(not(any(test, feature = "test-system-sender-key")))]
        Err(_) => panic!("MERITIUM_SYSTEM_SENDER_PRIV_KEY is required in non-test builds"),
    })
}

fn sign_with_system_sender(transaction: TxLegacy) -> Recovered<TxEnvelope> {
    let signer = PrivateKeySigner::from_bytes(system_sender_priv_key()).unwrap();
    let signature = signer
        .sign_hash_sync(&transaction.signature_hash())
        .unwrap();
    let signed = transaction.into_signed(signature);

    Recovered::new_unchecked(TxEnvelope::Legacy(signed), SYSTEM_SENDER_ETH_ADDRESS)
}

#[derive(Debug)]
enum SystemCall {
    StakingContractCall(StakingContractCall),
    AgentRewardCall(AgentRewardCall),
    AgentAuditCall(AgentAuditCall),
    AgentVerificationCall(AgentVerificationCall),
}

impl SystemCall {
    // Used to validate inputs of user transactions in RPC and TxPool
    pub fn is_restricted_system_call(txn: &Recovered<TxEnvelope>) -> bool {
        StakingContractCall::is_restricted_staking_contract_call(txn)
            || AgentRewardCall::is_restricted_agent_reward_call(txn)
            || AgentAuditCall::is_restricted_agent_audit_call(txn)
            || AgentVerificationCall::is_restricted_agent_verification_call(txn)
    }

    // Used to validate inputs of the expected system transactions
    pub fn validate_system_transaction_input(
        &self,
        sys_txn: &ValidatedTx,
    ) -> Result<(), SystemTransactionError> {
        match self {
            Self::StakingContractCall(staking_sys_call) => {
                staking_sys_call.validate_system_transaction_input(sys_txn)
            }
            Self::AgentRewardCall(agent_reward_call) => {
                let expected_dest = Some(AgentRewardCall::AGENT_REWARD_CONTRACT_ADDRESS);
                let actual_dest = sys_txn.tx.to();
                if expected_dest != actual_dest {
                    return Err(SystemTransactionError::UnexpectedDestAddress {
                        expected: AgentRewardCall::AGENT_REWARD_CONTRACT_ADDRESS,
                        actual: actual_dest,
                    });
                }
                let expected_value = agent_reward_call.entry.reward_amount;
                let actual_value = sys_txn.tx.value();
                if expected_value != actual_value {
                    return Err(SystemTransactionError::UnexpectedValue {
                        expected_value,
                        actual_value,
                    });
                }
                let expected = agent_reward_call.get_transaction_input();
                let actual = sys_txn.tx.input().to_vec().into();
                if expected != actual {
                    return Err(SystemTransactionError::UnexpectedInput {
                        expected_input: expected,
                        actual_input: actual,
                    });
                }
                Ok(())
            }
            Self::AgentAuditCall(agent_audit_call) => {
                let expected_dest = Some(AgentAuditCall::AGENT_AUDIT_CONTRACT_ADDRESS);
                let actual_dest = sys_txn.tx.to();
                if expected_dest != actual_dest {
                    return Err(SystemTransactionError::UnexpectedDestAddress {
                        expected: AgentAuditCall::AGENT_AUDIT_CONTRACT_ADDRESS,
                        actual: actual_dest,
                    });
                }
                let expected_value = U256::ZERO;
                let actual_value = sys_txn.tx.value();
                if expected_value != actual_value {
                    return Err(SystemTransactionError::UnexpectedValue {
                        expected_value,
                        actual_value,
                    });
                }
                let expected = agent_audit_call.get_transaction_input();
                let actual = sys_txn.tx.input().to_vec().into();
                if expected != actual {
                    return Err(SystemTransactionError::UnexpectedInput {
                        expected_input: expected,
                        actual_input: actual,
                    });
                }
                Ok(())
            }
            Self::AgentVerificationCall(agent_verification_call) => {
                let expected_dest =
                    Some(AgentVerificationCall::AGENT_VERIFICATION_CONTRACT_ADDRESS);
                let actual_dest = sys_txn.tx.to();
                if expected_dest != actual_dest {
                    return Err(SystemTransactionError::UnexpectedDestAddress {
                        expected: AgentVerificationCall::AGENT_VERIFICATION_CONTRACT_ADDRESS,
                        actual: actual_dest,
                    });
                }
                let expected_value = U256::ZERO;
                let actual_value = sys_txn.tx.value();
                if expected_value != actual_value {
                    return Err(SystemTransactionError::UnexpectedValue {
                        expected_value,
                        actual_value,
                    });
                }
                let expected = agent_verification_call.get_transaction_input();
                let actual = sys_txn.tx.input().to_vec().into();
                if expected != actual {
                    return Err(SystemTransactionError::UnexpectedInput {
                        expected_input: expected,
                        actual_input: actual,
                    });
                }
                Ok(())
            }
        }
    }

    fn into_signed_transaction(self, chain_id: u64, nonce: u64) -> SystemTransaction {
        match self {
            Self::StakingContractCall(staking_sys_call) => {
                SystemTransaction::StakingContractTransaction(
                    staking_sys_call.into_signed_transaction(chain_id, nonce),
                )
            }
            Self::AgentRewardCall(agent_reward_call) => SystemTransaction::AgentRewardTransaction(
                agent_reward_call.into_signed_transaction(chain_id, nonce),
            ),
            Self::AgentAuditCall(agent_audit_call) => SystemTransaction::AgentAuditTransaction(
                agent_audit_call.into_signed_transaction(chain_id, nonce),
            ),
            Self::AgentVerificationCall(agent_verification_call) => {
                SystemTransaction::AgentVerificationTransaction(
                    agent_verification_call.into_signed_transaction(chain_id, nonce),
                )
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum SystemTransaction {
    StakingContractTransaction(StakingContractTransaction),
    AgentRewardTransaction(AgentRewardTransaction),
    AgentAuditTransaction(AgentAuditTransaction),
    AgentVerificationTransaction(AgentVerificationTransaction),
}

impl SystemTransaction {
    pub fn signer(&self) -> Address {
        let signer = match &self {
            Self::StakingContractTransaction(staking_transaction) => {
                staking_transaction.inner().signer()
            }
            Self::AgentRewardTransaction(agent_reward_transaction) => {
                agent_reward_transaction.inner().signer()
            }
            Self::AgentAuditTransaction(agent_audit_transaction) => {
                agent_audit_transaction.inner().signer()
            }
            Self::AgentVerificationTransaction(agent_verification_transaction) => {
                agent_verification_transaction.inner().signer()
            }
        };
        assert_eq!(signer, SYSTEM_SENDER_ETH_ADDRESS);

        signer
    }
    pub fn nonce(&self) -> u64 {
        match &self {
            Self::StakingContractTransaction(staking_transaction) => {
                staking_transaction.inner().nonce()
            }
            Self::AgentRewardTransaction(agent_reward_transaction) => {
                agent_reward_transaction.inner().nonce()
            }
            Self::AgentAuditTransaction(agent_audit_transaction) => {
                agent_audit_transaction.inner().nonce()
            }
            Self::AgentVerificationTransaction(agent_verification_transaction) => {
                agent_verification_transaction.inner().nonce()
            }
        }
    }

    pub fn length(&self) -> usize {
        match &self {
            Self::StakingContractTransaction(staking_transaction) => {
                staking_transaction.inner().length()
            }
            Self::AgentRewardTransaction(agent_reward_transaction) => {
                agent_reward_transaction.inner().length()
            }
            Self::AgentAuditTransaction(agent_audit_transaction) => {
                agent_audit_transaction.inner().length()
            }
            Self::AgentVerificationTransaction(agent_verification_transaction) => {
                agent_verification_transaction.inner().length()
            }
        }
    }
}

impl From<SystemTransaction> for Recovered<TxEnvelope> {
    fn from(sys_txn: SystemTransaction) -> Self {
        match sys_txn {
            SystemTransaction::StakingContractTransaction(staking_txn) => staking_txn.into_inner(),
            SystemTransaction::AgentRewardTransaction(agent_reward_txn) => {
                agent_reward_txn.into_inner()
            }
            SystemTransaction::AgentAuditTransaction(agent_audit_txn) => {
                agent_audit_txn.into_inner()
            }
            SystemTransaction::AgentVerificationTransaction(agent_verification_txn) => {
                agent_verification_txn.into_inner()
            }
        }
    }
}

fn generate_system_calls<CCT, CRT>(
    proposed_seq_num: SeqNum,
    proposed_epoch: Epoch,
    parent_block_epoch: Epoch,
    block_author_address: Address,
    chain_config: &CCT,
) -> Vec<SystemCall>
where
    CCT: ChainConfig<CRT>,
    CRT: ChainRevision,
{
    let epoch_length = chain_config.get_epoch_length();
    let staking_activation = chain_config.get_staking_activation();

    let mut system_calls = Vec::new();

    // If staking activates in Epoch N, generate snapshot transactions
    // starting at the boundary of Epoch N-1
    let generate_snapshot_txn = proposed_seq_num.is_boundary_block(epoch_length)
        && proposed_seq_num.get_locked_epoch(epoch_length) >= staking_activation;
    if generate_snapshot_txn {
        system_calls.push(SystemCall::StakingContractCall(
            StakingContractCall::Snapshot,
        ));
    }

    // If staking activates in Epoch N, generate epoch change transactions
    // starting at Epoch N-1
    // Special case: If staking starts at Epoch 2, generate epoch change
    // as the first transaction in Epoch 1
    let is_first_epoch_block =
        parent_block_epoch != proposed_epoch && proposed_epoch >= staking_activation - Epoch(1);
    let is_genesis_block =
        proposed_seq_num == GENESIS_SEQ_NUM + SeqNum(1) && staking_activation == Epoch(2);
    let generate_epoch_change_txn = is_first_epoch_block || is_genesis_block;
    if generate_epoch_change_txn {
        system_calls.push(SystemCall::StakingContractCall(
            StakingContractCall::EpochChange {
                new_epoch: proposed_epoch,
            },
        ));
    }

    // If staking activates in Epoch N, generate reward transactions
    // starting at the first block in Epoch N
    let generate_reward_txn = proposed_epoch >= staking_activation;
    if generate_reward_txn {
        let block_reward_mon = chain_config.get_block_reward_mon(proposed_epoch);
        let block_reward = U256::from(StakingContractCall::MON) * U256::from(block_reward_mon);

        system_calls.push(SystemCall::StakingContractCall(
            StakingContractCall::Reward {
                block_author_address,
                block_reward,
            },
        ));
    }

    system_calls
}

fn halving_shift_for_seq_num(seq_num: SeqNum) -> usize {
    (seq_num.0 / MERITIUM_HALVING_INTERVAL_BLOCKS).min(127) as usize
}

fn agent_id_from_address(address: Address) -> B256 {
    let mut agent_id = [0u8; 32];
    agent_id[12..].copy_from_slice(address.as_slice());
    B256::from(agent_id)
}

pub fn resolve_founder_vesting_address_for_seq(
    seq_num: SeqNum,
    founder_vesting_address: Option<Address>,
    founder_vesting_activation_seq: Option<u64>,
) -> Option<Address> {
    match (founder_vesting_address, founder_vesting_activation_seq) {
        (Some(addr), Some(activation_seq)) if seq_num.0 >= activation_seq => Some(addr),
        (Some(_), Some(_)) => None,
        (Some(addr), None) => Some(addr),
        _ => None,
    }
}

/// Deterministic Meritium reward-entry builder shared by proposer and validator
/// paths.
///
/// This function is the single source of truth for:
/// - founder vesting cutover activation-by-seq behavior
/// - per-block halving shift
/// - 5x founder reward + 1x protocol-fund reward shape
pub fn build_meritium_reward_entries_for_seq(
    seq_num: SeqNum,
    founder_vesting_address: Option<Address>,
    founder_vesting_activation_seq: Option<u64>,
) -> Vec<AgentRewardEntry> {
    let active_founder_vesting_address = resolve_founder_vesting_address_for_seq(
        seq_num,
        founder_vesting_address,
        founder_vesting_activation_seq,
    );
    let shift = halving_shift_for_seq_num(seq_num);
    let per_agent_reward = U256::from(MERITIUM_PER_AGENT_REWARD_WEI) >> shift;
    let protocol_fee_reward = U256::from(MERITIUM_PROTOCOL_FEE_WEI) >> shift;

    let reward_wallets: [Address; 5] = active_founder_vesting_address
        .map(|addr| [addr; 5])
        .unwrap_or(MERITIUM_DEFAULT_AGENT_WALLETS);

    let mut out = Vec::new();
    if !per_agent_reward.is_zero() {
        out.extend(reward_wallets.into_iter().map(|wallet| AgentRewardEntry {
            agent_id: agent_id_from_address(wallet),
            poaw_score: 1_000_000,
            reward_amount: per_agent_reward,
        }));
    }

    if !protocol_fee_reward.is_zero() {
        out.push(AgentRewardEntry {
            agent_id: agent_id_from_address(MERITIUM_PROTOCOL_FUND_ADDRESS),
            poaw_score: 0,
            reward_amount: protocol_fee_reward,
        });
    }

    out
}

fn append_meritium_system_calls_for_validation(
    system_calls: &mut Vec<SystemCall>,
    seq_num: SeqNum,
    config: &MeritiumSystemCallConfig,
) {
    if config.rewards_enabled {
        for entry in build_meritium_reward_entries_for_seq(
            seq_num,
            config.founder_vesting_address,
            config.founder_vesting_activation_seq,
        ) {
            system_calls.push(SystemCall::AgentRewardCall(AgentRewardCall::from_entry(
                entry,
            )));
        }
    }

    if config.audits_enabled {
        system_calls.push(SystemCall::AgentAuditCall(AgentAuditCall::from_entry(
            AgentAuditEntry {
                agent_id: B256::with_last_byte(0x02),
                vrf_proof: B256::with_last_byte(0xAA),
                audit_epoch: 1,
            },
        )));
    }

    if config.verifications_enabled {
        system_calls.push(SystemCall::AgentVerificationCall(
            AgentVerificationCall::from_entry(AgentVerificationEntry {
                task_id: B256::with_last_byte(0x10),
                agent_id: B256::with_last_byte(0x01),
                result_hash: B256::with_last_byte(0xFF),
                verifier_count: 3,
            }),
        ));
    }
}

fn generate_expected_system_calls_for_validation<CCT, CRT>(
    proposed_seq_num: SeqNum,
    proposed_epoch: Epoch,
    parent_block_epoch: Epoch,
    block_author_address: Address,
    chain_config: &CCT,
) -> Vec<SystemCall>
where
    CCT: ChainConfig<CRT>,
    CRT: ChainRevision,
{
    let mut system_calls = generate_system_calls(
        proposed_seq_num,
        proposed_epoch,
        parent_block_epoch,
        block_author_address,
        chain_config,
    );
    let meritium_config = get_meritium_system_call_config();
    append_meritium_system_calls_for_validation(
        &mut system_calls,
        proposed_seq_num,
        &meritium_config,
    );
    system_calls
}

#[derive(Clone, Debug)]
pub struct SystemTransactionGenerator;

impl SystemTransactionGenerator {
    // Used by a round leader to generate system calls for the proposing block
    pub fn generate_system_transactions<CCT, CRT>(
        proposed_seq_num: SeqNum,
        proposed_epoch: Epoch,
        parent_block_epoch: Epoch,
        block_author: Address,
        mut next_system_txn_nonce: u64,
        chain_config: &CCT,
    ) -> Vec<SystemTransaction>
    where
        CCT: ChainConfig<CRT>,
        CRT: ChainRevision,
    {
        let system_calls = generate_system_calls(
            proposed_seq_num,
            proposed_epoch,
            parent_block_epoch,
            block_author,
            chain_config,
        );

        system_calls
            .into_iter()
            .map(|sys_call| {
                let system_txn = sys_call
                    .into_signed_transaction(chain_config.chain_id(), next_system_txn_nonce);
                next_system_txn_nonce += 1;

                system_txn
            })
            .collect()
    }

    // Backward-compatible extension: append Meritium reward transactions
    // after the upstream staking system-transaction set.
    pub fn generate_system_transactions_with_agent_rewards<CCT, CRT>(
        proposed_seq_num: SeqNum,
        proposed_epoch: Epoch,
        parent_block_epoch: Epoch,
        block_author: Address,
        next_system_txn_nonce: u64,
        chain_config: &CCT,
        rewards: impl IntoIterator<Item = AgentRewardEntry>,
    ) -> Vec<SystemTransaction>
    where
        CCT: ChainConfig<CRT>,
        CRT: ChainRevision,
    {
        let mut txs = Self::generate_system_transactions(
            proposed_seq_num,
            proposed_epoch,
            parent_block_epoch,
            block_author,
            next_system_txn_nonce,
            chain_config,
        );
        let mut nonce = next_system_txn_nonce + txs.len() as u64;

        for entry in rewards {
            let txn = AgentRewardCall::from_entry(entry)
                .into_signed_transaction(chain_config.chain_id(), nonce);
            txs.push(SystemTransaction::AgentRewardTransaction(txn));
            nonce += 1;
        }

        txs
    }

    // Meritium extras path: rewards + audits.
    pub fn generate_system_transactions_with_meritium_extras<CCT, CRT>(
        proposed_seq_num: SeqNum,
        proposed_epoch: Epoch,
        parent_block_epoch: Epoch,
        block_author: Address,
        next_system_txn_nonce: u64,
        chain_config: &CCT,
        rewards: impl IntoIterator<Item = AgentRewardEntry>,
        audits: impl IntoIterator<Item = AgentAuditEntry>,
    ) -> Vec<SystemTransaction>
    where
        CCT: ChainConfig<CRT>,
        CRT: ChainRevision,
    {
        let mut txs = Self::generate_system_transactions_with_agent_rewards(
            proposed_seq_num,
            proposed_epoch,
            parent_block_epoch,
            block_author,
            next_system_txn_nonce,
            chain_config,
            rewards,
        );
        let mut nonce = next_system_txn_nonce + txs.len() as u64;

        for entry in audits {
            let txn = AgentAuditCall::from_entry(entry)
                .into_signed_transaction(chain_config.chain_id(), nonce);
            txs.push(SystemTransaction::AgentAuditTransaction(txn));
            nonce += 1;
        }

        txs
    }

    // Meritium full bundle path: rewards + audits + verifications.
    pub fn generate_system_transactions_with_meritium_bundle<CCT, CRT>(
        proposed_seq_num: SeqNum,
        proposed_epoch: Epoch,
        parent_block_epoch: Epoch,
        block_author: Address,
        next_system_txn_nonce: u64,
        chain_config: &CCT,
        rewards: impl IntoIterator<Item = AgentRewardEntry>,
        audits: impl IntoIterator<Item = AgentAuditEntry>,
        verifications: impl IntoIterator<Item = AgentVerificationEntry>,
    ) -> Vec<SystemTransaction>
    where
        CCT: ChainConfig<CRT>,
        CRT: ChainRevision,
    {
        let mut txs = Self::generate_system_transactions_with_meritium_extras(
            proposed_seq_num,
            proposed_epoch,
            parent_block_epoch,
            block_author,
            next_system_txn_nonce,
            chain_config,
            rewards,
            audits,
        );
        let mut nonce = next_system_txn_nonce + txs.len() as u64;

        for entry in verifications {
            let txn = AgentVerificationCall::from_entry(entry)
                .into_signed_transaction(chain_config.chain_id(), nonce);
            txs.push(SystemTransaction::AgentVerificationTransaction(txn));
            nonce += 1;
        }

        txs
    }
}

#[cfg(test)]
mod test_utils {
    use alloy_consensus::{SignableTransaction, TxEnvelope, TxLegacy, transaction::Recovered};
    use alloy_primitives::{Address, Bytes, TxKind};
    use alloy_signer::SignerSync;
    use alloy_signer_local::LocalSigner;

    use crate::{SYSTEM_SENDER_ETH_ADDRESS, TEST_SYSTEM_SENDER_PRIV_KEY};

    pub fn get_valid_system_transaction() -> TxLegacy {
        TxLegacy {
            chain_id: Some(1337),
            nonce: 0,
            gas_price: 0,
            gas_limit: 0,
            to: TxKind::Call(Address::new([0_u8; 20])),
            value: Default::default(),
            input: Bytes::new(),
        }
    }

    pub fn sign_with_system_sender(transaction: TxLegacy) -> Recovered<TxEnvelope> {
        let signature_hash = transaction.signature_hash();
        let local_signer = LocalSigner::from_bytes(&TEST_SYSTEM_SENDER_PRIV_KEY).unwrap();
        let signature = local_signer.sign_hash_sync(&signature_hash).unwrap();

        Recovered::new_unchecked(
            TxEnvelope::Legacy(transaction.into_signed(signature)),
            SYSTEM_SENDER_ETH_ADDRESS,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_meritium_reward_entries_for_seq, parse_env_system_sender_key,
        resolve_founder_vesting_address_for_seq,
    };
    use alloy_primitives::{Address, B256, U256, hex};
    use monad_types::SeqNum;

    #[test]
    fn parse_env_key_accepts_0x_prefixed_hex() {
        let key = parse_env_system_sender_key(
            "0xb0358e6d701a955d9926676f227e40172763296b317ff554e49cdf2c2c35f8a7",
        )
        .unwrap();
        assert_eq!(
            key,
            B256::new(hex!(
                "b0358e6d701a955d9926676f227e40172763296b317ff554e49cdf2c2c35f8a7"
            ))
        );
    }

    #[test]
    fn parse_env_key_accepts_plain_hex() {
        let key = parse_env_system_sender_key(
            "b0358e6d701a955d9926676f227e40172763296b317ff554e49cdf2c2c35f8a7",
        )
        .unwrap();
        assert_eq!(
            key,
            B256::new(hex!(
                "b0358e6d701a955d9926676f227e40172763296b317ff554e49cdf2c2c35f8a7"
            ))
        );
    }

    #[test]
    fn parse_env_key_rejects_bad_length() {
        let err = parse_env_system_sender_key("0x1234").unwrap_err();
        assert!(err.contains("expected 64 hex chars"));
    }

    #[test]
    fn founder_vesting_resolution_respects_activation_seq_boundary() {
        let vesting = Address::new(hex!("111122223333444455556666777788889999aaaa"));
        assert_eq!(
            resolve_founder_vesting_address_for_seq(SeqNum(99), Some(vesting), Some(100)),
            None
        );
        assert_eq!(
            resolve_founder_vesting_address_for_seq(SeqNum(100), Some(vesting), Some(100)),
            Some(vesting)
        );
    }

    #[test]
    fn reward_entries_use_legacy_wallets_before_activation_and_vesting_after() {
        let vesting = Address::new(hex!("111122223333444455556666777788889999aaaa"));

        let before = build_meritium_reward_entries_for_seq(SeqNum(99), Some(vesting), Some(100));
        let after = build_meritium_reward_entries_for_seq(SeqNum(100), Some(vesting), Some(100));

        assert_eq!(before.len(), 6);
        assert_eq!(after.len(), 6);

        assert_eq!(
            &before[0].agent_id.as_slice()[12..],
            hex!("EF08abD86c983EaD2908663d1115fb8Abe4eF176").as_slice()
        );
        assert_eq!(
            &after[0].agent_id.as_slice()[12..],
            hex!("111122223333444455556666777788889999aaaa").as_slice()
        );
    }

    #[test]
    fn reward_entries_apply_halving_at_boundary() {
        let before = build_meritium_reward_entries_for_seq(SeqNum(1_999_999), None, None);
        let after = build_meritium_reward_entries_for_seq(SeqNum(2_000_000), None, None);

        assert_eq!(before.len(), 6);
        assert_eq!(after.len(), 6);
        assert_eq!(
            before[0].reward_amount,
            U256::from(594_000_000_000_000_000u128)
        );
        assert_eq!(
            after[0].reward_amount,
            U256::from(297_000_000_000_000_000u128)
        );
        assert_eq!(
            before[5].reward_amount,
            U256::from(30_000_000_000_000_000u128)
        );
        assert_eq!(
            after[5].reward_amount,
            U256::from(15_000_000_000_000_000u128)
        );
    }
}
