// Copyright (C) 2026 Meritium contributors.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

use alloy_consensus::{Transaction, TxEnvelope, TxLegacy, transaction::Recovered};
use alloy_primitives::{Address, B256, Bytes, FixedBytes, TxKind, U256, hex};
use alloy_sol_types::SolValue;

use crate::sign_with_system_sender;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentRewardEntry {
    pub agent_id: B256,
    pub poaw_score: u64,
    pub reward_amount: U256,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentRewardCall {
    pub entry: AgentRewardEntry,
}

impl AgentRewardCall {
    pub const AGENT_REWARD_CONTRACT_ADDRESS: Address =
        Address::new(hex!("0x0000000000000000000000000000000000001001"));
    // selector("syscallAgentReward(bytes32,uint64,uint256)")
    pub const AGENT_REWARD_FUNCTION_SELECTOR: FixedBytes<4> = FixedBytes::new(hex!("0x38195dbc"));

    pub fn from_entry(entry: AgentRewardEntry) -> Self {
        Self { entry }
    }

    pub fn is_restricted_agent_reward_call(txn: &Recovered<TxEnvelope>) -> bool {
        txn.to() == Some(Self::AGENT_REWARD_CONTRACT_ADDRESS)
            && txn
                .input()
                .starts_with(Self::AGENT_REWARD_FUNCTION_SELECTOR.as_slice())
    }

    pub(crate) fn get_transaction_input(&self) -> Bytes {
        [
            Self::AGENT_REWARD_FUNCTION_SELECTOR.as_slice(),
            self.entry.agent_id.abi_encode().as_slice(),
            self.entry.poaw_score.abi_encode().as_slice(),
            self.entry.reward_amount.abi_encode().as_slice(),
        ]
        .concat()
        .into()
    }

    fn as_legacy_transaction(&self, chain_id: u64, nonce: u64) -> TxLegacy {
        TxLegacy {
            chain_id: Some(chain_id),
            nonce,
            gas_price: 0,
            gas_limit: 0,
            to: TxKind::Call(Self::AGENT_REWARD_CONTRACT_ADDRESS),
            value: self.entry.reward_amount,
            input: self.get_transaction_input(),
        }
    }

    pub fn into_signed_transaction(self, chain_id: u64, nonce: u64) -> AgentRewardTransaction {
        AgentRewardTransaction(sign_with_system_sender(
            self.as_legacy_transaction(chain_id, nonce),
        ))
    }
}

#[derive(Debug, Clone)]
pub struct AgentRewardTransaction(pub Recovered<TxEnvelope>);

impl AgentRewardTransaction {
    pub fn into_inner(self) -> Recovered<TxEnvelope> {
        self.0
    }

    pub fn inner(&self) -> &Recovered<TxEnvelope> {
        &self.0
    }
}
