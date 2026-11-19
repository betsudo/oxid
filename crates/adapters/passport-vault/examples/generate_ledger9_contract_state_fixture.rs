// SPDX-License-Identifier: Apache-2.0

//! Emit the deterministic Passport Vault layout fixture in Ledger9's native
//! `contract-state[v8]` encoding.
//!
//! This fixture authenticates the public 15-field layout and replay boundary;
//! it intentionally carries no deployable operations. The Ledger9 Compact
//! artifact and operation closure is tracked separately by issue #1194.

use midnight_base_crypto::fab::AlignedValue;
use midnight_onchain_runtime::state::{ContractMaintenanceAuthority, ContractState, StateValue};
use midnight_serialize::tagged_serialize;
use midnight_storage::{
    DefaultDB,
    arena::Sp,
    storage::{Array, HashMap},
};

fn cell(value: impl Into<AlignedValue>) -> StateValue<DefaultDB> {
    StateValue::Cell(Sp::new(value.into()))
}

fn lock(
    minimum_age: u8,
    require_issuing_state: bool,
    issuing_state: [u8; 32],
    require_document_number: bool,
    document_number: [u8; 32],
    maximum_claim: u128,
    challenge: [u8; 32],
) -> StateValue<DefaultDB> {
    cell((
        [1_u8; 32],
        minimum_age,
        require_issuing_state,
        issuing_state,
        require_document_number,
        document_number,
        maximum_claim,
        challenge,
        0_u128,
        0_u128,
    ))
}

fn main() {
    let locks = HashMap::new()
        .insert(
            AlignedValue::from(0_u64),
            lock(18, true, [4; 32], false, [0; 32], 40, [5; 32]),
        )
        .insert(
            AlignedValue::from(1_u64),
            lock(21, false, [0; 32], true, [6; 32], 25, [7; 32]),
        );
    let mut no_credential = [0_u8; 32];
    no_credential[..22].copy_from_slice(b"passport-vault:no-cred");
    let issuer_hash: [u8; 32] =
        hex::decode("dd1749c35435bc7251c11df7a37354fd7bf64fa38d0255873e03509241588eda")
            .expect("fixed issuer hash")
            .try_into()
            .expect("32-byte issuer hash");
    let data = StateValue::Array(Array::from(vec![
        cell(1_u32),
        cell([1_u8; 32]),
        cell(([2_u8; 32], [3_u8; 32])),
        cell(issuer_hash),
        StateValue::Map(locks),
        cell(2_u64),
        StateValue::Map(HashMap::new()),
        cell(0_u128),
        cell(0_u128),
        cell(0_u64),
        cell(no_credential),
        cell(0_u32),
        cell(0_u8),
        cell(0_u128),
        cell(0_u8),
    ]));
    let contract = ContractState::new(data, HashMap::new(), ContractMaintenanceAuthority::new());
    let mut encoded = Vec::new();
    tagged_serialize(&contract, &mut encoded).expect("Ledger9 fixture serialization");
    println!("{}", hex::encode(encoded));
}
