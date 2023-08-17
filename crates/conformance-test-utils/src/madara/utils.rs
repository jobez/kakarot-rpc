use kakarot_rpc_core::client::constants::STARKNET_NATIVE_TOKEN;
use kakarot_rpc_core::client::helpers::split_u256_into_field_elements;
use reth_primitives::{Bytes, U256};
use starknet::core::types::FieldElement;
use starknet::core::utils::get_storage_var_address;

use crate::types::{ContractAddress, StorageKey, StorageValue};

/// Generates the genesis storage tuples for setting the bytecode of a Kakarot countract account
///
/// This function calculates the storage keys for the Kakarot contract using the provided bytecode
/// and Starknet address. The resulting Vec of tuples represent the initial storage of the Kakarot
/// contract, where the storage key is computed using the storage variable "bytecode_" and the index
/// of the 16-byte chunk of the bytecode. The value stored is the 16-byte chunk of the bytecode.
pub fn genesis_set_bytecode(
    bytecode: &Bytes,
    starknet_address: FieldElement,
) -> Vec<((ContractAddress, StorageKey), StorageValue)> {
    bytecode
        .chunks(16)
        .enumerate()
        .map(|(i, x)| {
            let mut storage_value = [0u8; 16];
            storage_value[..x.len()].copy_from_slice(x);
            let storage_value = FieldElement::from(u128::from_be_bytes(storage_value));

            genesis_set_storage_starknet_contract(
                starknet_address,
                "bytecode_",
                &[FieldElement::from(i)],
                storage_value,
                0, // only felt is stored so offset is always 0
            )
        })
        .collect()
}

/// Generates the genesis storage tuple for setting the storage of a Starknet contract.
///
/// This function calculates the storage key for the storage variable `storage_variable_name` and
/// its keys. The resulting tuple represents the initial storage of the contract, where the storage
/// key at a given `storage_offset` is set to the specified `storage_value`.
pub fn genesis_set_storage_starknet_contract(
    starknet_address: FieldElement,
    storage_variable_name: &str,
    keys: &[FieldElement],
    storage_value: FieldElement,
    storage_offset: u64,
) -> ((ContractAddress, StorageKey), StorageValue) {
    // Compute the storage key for the storage variable name and the keys.
    let mut storage_key =
        get_storage_var_address(storage_variable_name, keys).expect("Non-ASCII storage variable name");

    // Add the offset to the storage key.
    storage_key += FieldElement::from(storage_offset);

    let contract_address: ContractAddress = starknet_address.into();

    // Create the tuple for the initial storage data on the Starknet contract with the given storage
    // key.
    ((contract_address, storage_key.into()), storage_value.into())
}

/// Generates the genesis storage tuples for pre-funding a Starknet address on Madara.
///
/// This function calculates the storage keys for the balance of the ERC20 Fee Token
/// contract using the provided Starknet address. The resulting Vec of tuples represent the initial
/// storage of the Fee Token contract, where the account associated with the Starknet address is
/// pre-funded with the specified `amount`. The `amount` is split into two 128-bit chunks, which
/// are stored in the storage keys at offsets 0 and 1.
pub fn genesis_fund_starknet_address(
    starknet_address: FieldElement,
    amount: U256,
) -> Vec<((ContractAddress, StorageKey), StorageValue)> {
    // Split the amount into two 128-bit chunks.
    let amount = split_u256_into_field_elements(amount);

    // Iterate over the storage key offsets and generate the storage tuples.
    amount
        .iter()
        .enumerate() // Enumerate the key offsets.
        .map(|(offset, value)| {
            genesis_set_storage_starknet_contract(
                FieldElement::from_hex_be(STARKNET_NATIVE_TOKEN).unwrap(), // Safe unwrap
                "ERC20_balances",
                &[starknet_address],
                *value,
                offset as u64,
            )
        })
        .collect()
}

/// Generates the genesis storage tuples for setting the storage of the Kakarot contract.
///
/// This function calculates the storage keys for the Kakarot contract using the provided Starknet
/// address. The resulting Vec of tuples represent the initial storage of the Kakarot contract,
/// where the storage key is computed using the provided `key` of the storage variable "storage_"
/// and the `value` is split into two 128-bit chunks, which are stored in the storage keys at
/// offsets 0 and 1.
pub fn genesis_set_storage_kakarot_contract_account(
    starknet_address: FieldElement,
    key: U256,
    value: U256,
) -> Vec<((ContractAddress, StorageKey), StorageValue)> {
    // Split the key into Vec of two 128-bit chunks.
    let keys = split_u256_into_field_elements(key);

    // Split the value into two 128-bit chunks.
    let values = split_u256_into_field_elements(value);

    // Iterate over the storage key offsets and generate the storage tuples.
    values
        .iter()
        .enumerate() // Enumerate the key offsets.
        .map(|(offset, value)| {
            genesis_set_storage_starknet_contract(
                starknet_address,
                "storage_",
                &keys,
                *value,
                offset as u64,
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::str::FromStr;
    use std::sync::Arc;

    use bytes::BytesMut;
    use kakarot_rpc_core::client::api::{KakarotEthApi, KakarotStarknetApi};
    use kakarot_rpc_core::client::constants::STARKNET_NATIVE_TOKEN;
    use kakarot_rpc_core::client::helpers::split_u256_into_field_elements;
    use kakarot_rpc_core::contracts::account::Account;
    use kakarot_rpc_core::contracts::contract_account::ContractAccount;
    use kakarot_rpc_core::mock::constants::ACCOUNT_ADDRESS;
    use kakarot_rpc_core::test_utils::deploy_helpers::{
        compute_kakarot_contracts_class_hash, KakarotTestEnvironmentContext,
    };
    use kakarot_rpc_core::test_utils::fixtures::kakarot_test_env_ctx;
    use katana_core::backend::state::StorageRecord;
    use reth_primitives::{SealedBlock, U256};
    use reth_rlp::{Decodable, Encodable};
    use rstest::rstest;
    use starknet::core::types::{BlockId as StarknetBlockId, BlockTag, FieldElement};
    use starknet::core::utils::get_storage_var_address;
    use starknet::providers::Provider;
    use starknet_api::core::{ClassHash, ContractAddress as StarknetContractAddress, Nonce};
    use starknet_api::hash::StarkFelt;
    use starknet_api::state::StorageKey as StarknetStorageKey;

    use super::*;
    use crate::kakarot::compute_starknet_address;

    /// This test verifies that the `genesis_set_storage_starknet_contract` function generates the
    /// correct storage data tuples for a given Starknet address, storage variable name, keys,
    /// storage value, and storage key offset.
    #[tokio::test]
    async fn test_genesis_set_storage_starknet_contract() {
        // Given
        let starknet_address = FieldElement::from_hex_be("0x1234").unwrap();
        let storage_variable_name = "test_name";
        let keys = vec![];
        let storage_value = FieldElement::from_hex_be("0x1234").unwrap();
        let storage_offset = 0;

        // This is the expected output tuple of storage data.
        let expected_output = (
            (starknet_address.into(), get_storage_var_address(storage_variable_name, &keys).unwrap().into()),
            storage_value.into(),
        );

        // When
        let result = genesis_set_storage_starknet_contract(
            starknet_address,
            storage_variable_name,
            &keys,
            storage_value,
            storage_offset,
        );

        // Then
        assert_eq!(result, expected_output);
    }

    fn get_starknet_storage_key(var_name: &str, args: &[FieldElement]) -> StarknetStorageKey {
        StarknetStorageKey(
            Into::<StarkFelt>::into(get_storage_var_address(var_name, args).unwrap()).try_into().unwrap(),
        )
    }

    #[test]
    fn test_genesis_set_bytecode() {
        // Given
        const TEST_BYTECODE: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        const BIG_ENDIAN_BYTECODE_ONE: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        const BIG_ENDIAN_BYTECODE_TWO: &str = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let bytecode = Bytes::from_str(TEST_BYTECODE).unwrap();
        let address = *ACCOUNT_ADDRESS;

        // When
        let storage = genesis_set_bytecode(&bytecode, address);

        // Then
        let expected_storage: Vec<((ContractAddress, StorageKey), StorageValue)> = vec![
            (
                (address.into(), get_storage_var_address("bytecode_", &[FieldElement::from(0u8)]).unwrap().into()),
                FieldElement::from_hex_be(BIG_ENDIAN_BYTECODE_ONE).unwrap().into(),
            ),
            (
                (address.into(), get_storage_var_address("bytecode_", &[FieldElement::from(1u8)]).unwrap().into()),
                FieldElement::from_hex_be(BIG_ENDIAN_BYTECODE_TWO).unwrap().into(),
            ),
        ];
        assert_eq!(expected_storage, storage);
    }

    #[rstest]
    #[tokio::test(flavor = "multi_thread")]
    async fn test_counter_bytecode(kakarot_test_env_ctx: KakarotTestEnvironmentContext) {
        // Given
        let test_environment = Arc::new(kakarot_test_env_ctx);
        let starknet_client = test_environment.client().starknet_provider();
        let counter = test_environment.evm_contract("Counter");
        let counter_contract = ContractAccount::new(counter.addresses.starknet_address, &starknet_client);

        // When
        let deployed_evm_bytecode = counter_contract.bytecode(&StarknetBlockId::Tag(BlockTag::Latest)).await.unwrap();
        let deployed_evm_bytecode_len = deployed_evm_bytecode.len();

        // Use genesis_set_bytecode to get the bytecode to be stored into counter
        let counter_genesis_address = FieldElement::from_str("0x1234").unwrap();
        let counter_genesis_storage = genesis_set_bytecode(&deployed_evm_bytecode, counter_genesis_address);

        // Create an atomic reference to the test environment to avoid dropping it
        let env = Arc::clone(&test_environment);
        // It is not possible to block the async test task, so we need to spawn a blocking task
        tokio::task::spawn_blocking(move || {
            // Get lock on the Starknet sequencer
            let mut starknet = env.sequencer().sequencer.backend.state.blocking_write();
            let mut counter_storage = HashMap::new();

            // Set the counter bytecode length into the contract
            let key = get_starknet_storage_key("bytecode_len_", &[]);
            let value = Into::<StarkFelt>::into(StarkFelt::from(deployed_evm_bytecode_len as u64));
            counter_storage.insert(key, value);

            // Set the counter bytecode into the contract
            counter_genesis_storage.into_iter().for_each(|((_, k), v)| {
                let key = StarknetStorageKey(Into::<StarkFelt>::into(k.0).try_into().unwrap());
                let value = Into::<StarkFelt>::into(v.0);
                counter_storage.insert(key, value);
            });

            // Deploy the contract account at genesis address
            let contract_account_class_hash = env.kakarot().contract_account_class_hash;
            let counter_address =
                StarknetContractAddress(Into::<StarkFelt>::into(counter_genesis_address).try_into().unwrap());
            let counter_storage_record = StorageRecord {
                nonce: Nonce(StarkFelt::from(0u8)),
                class_hash: ClassHash(contract_account_class_hash.into()),
                storage: counter_storage,
            };
            starknet.storage.insert(counter_address, counter_storage_record);
        })
        .await
        .unwrap();

        // Create a new counter contract pointing to the genesis initialized storage
        let counter_genesis = ContractAccount::new(counter_genesis_address, &starknet_client);
        let evm_bytecode_actual = counter_genesis.bytecode(&StarknetBlockId::Tag(BlockTag::Latest)).await.unwrap();

        // Then
        // Assert that the expected and actual bytecodes are equal
        assert_eq!(evm_bytecode_actual, deployed_evm_bytecode);
    }

    fn madara_to_katana_storage(
        source: Vec<((ContractAddress, StorageKey), StorageValue)>,
        destination: &mut HashMap<StarknetStorageKey, StarkFelt>,
    ) {
        for ((_, k), v) in source {
            let key = StarknetStorageKey(Into::<StarkFelt>::into(k.0).try_into().unwrap());
            let value = Into::<StarkFelt>::into(v.0);
            destination.insert(key, value);
        }
    }

    #[rstest]
    #[tokio::test(flavor = "multi_thread")]
    async fn test_generalstatetransition_mvp(kakarot_test_env_ctx: KakarotTestEnvironmentContext) {
        let data = r#"
{"add_d0g0v0_Shanghai": {
    "_info": {
      "comment": "Ori Pomerantz qbzzt1@gmail.com",
      "filling-rpc-server": "evm version 1.11.4-unstable-e14043db-20230308",
      "filling-tool-version": "retesteth-0.3.0-shanghai+commit.fd2c0a83.Linux.g++",
      "generatedTestHash": "dc4687b4e526bcd4fe23eac73894cacf8ba5b9a139363de0073eb67db0df36fb",
      "lllcversion": "Version: 0.5.14-develop.2022.7.30+commit.a096d7a9.Linux.g++",
      "solidity": "Version: 0.8.17+commit.8df45f5f.Linux.g++",
      "source": "src/GeneralStateTestsFiller/VMTests/vmArithmeticTest/addFiller.yml",
      "sourceHash": "78afea990a2d534831acc4883b9ff6e81d560091942db7234232d68fdbf1c33e"
    },
    "blocks": [
      {
        "blockHeader": {
          "baseFeePerGas": "0x0a",
          "bloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
          "coinbase": "0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba",
          "difficulty": "0x00",
          "extraData": "0x00",
          "gasLimit": "0x05f5e100",
          "gasUsed": "0xb36e",
          "hash": "0xc52b87215ff3cea57b70b9e2104f7be6877a00eb98a1f10e8f4941aaefc90ae6",
          "mixHash": "0x0000000000000000000000000000000000000000000000000000000000020000",
          "nonce": "0x0000000000000000",
          "number": "0x01",
          "parentHash": "0x6d4b3f3898786350e8b7bccdce7f1d4a567c5594699de8cd7884e948d019672c",
          "receiptTrie": "0x7fb0f40c31c7596ff1847f39f294a466a231fa3d722c78408d6dcff53a3bcdb4",
          "stateRoot": "0x6e9dccb57a15e2885ff1193da0db98cbaaac218bf3a0abeb0c3ceff966de2830",
          "timestamp": "0x03e8",
          "transactionsTrie": "0x86be9b5d20254e0393853c82e5534d9d9f8486f1fd2ed4f4c0a169339c79bd1c",
          "uncleHash": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
          "withdrawalsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
        },
        "rlp": "0xf902a5f90217a06d4b3f3898786350e8b7bccdce7f1d4a567c5594699de8cd7884e948d019672ca01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347942adc25665018aa1fe0e6bc666dac8fc2697ff9baa06e9dccb57a15e2885ff1193da0db98cbaaac218bf3a0abeb0c3ceff966de2830a086be9b5d20254e0393853c82e5534d9d9f8486f1fd2ed4f4c0a169339c79bd1ca07fb0f40c31c7596ff1847f39f294a466a231fa3d722c78408d6dcff53a3bcdb4b901000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080018405f5e10082b36e8203e800a000000000000000000000000000000000000000000000000000000000000200008800000000000000000aa056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421f887f885800a8404c4b40094cccccccccccccccccccccccccccccccccccccccc01a4693c613900000000000000000000000000000000000000000000000000000000000000001ba0e8ff56322287185f6afd3422a825b47bf5c1a4ccf0dc0389cdc03f7c1c32b7eaa0776b02f9f5773238d3ff36b74a123f409cd6420908d7855bbe4c8ff63e00d698c0c0",
        "transactions": [
          {
            "data": "0x693c61390000000000000000000000000000000000000000000000000000000000000000",
            "gasLimit": "0x04c4b400",
            "gasPrice": "0x0a",
            "nonce": "0x00",
            "r": "0xe8ff56322287185f6afd3422a825b47bf5c1a4ccf0dc0389cdc03f7c1c32b7ea",
            "s": "0x776b02f9f5773238d3ff36b74a123f409cd6420908d7855bbe4c8ff63e00d698",
            "sender": "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b",
            "to": "0xcccccccccccccccccccccccccccccccccccccccc",
            "v": "0x1b",
            "value": "0x01"
          }
        ],
        "uncleHeaders": [],
        "withdrawals": []
      }
    ],
    "genesisBlockHeader": {
      "baseFeePerGas": "0x0b",
      "bloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      "coinbase": "0x2adc25665018aa1fe0e6bc666dac8fc2697ff9ba",
      "difficulty": "0x00",
      "extraData": "0x00",
      "gasLimit": "0x05f5e100",
      "gasUsed": "0x00",
      "hash": "0x6d4b3f3898786350e8b7bccdce7f1d4a567c5594699de8cd7884e948d019672c",
      "mixHash": "0x0000000000000000000000000000000000000000000000000000000000020000",
      "nonce": "0x0000000000000000",
      "number": "0x00",
      "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
      "receiptTrie": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
      "stateRoot": "0xf3d3787e33cb7913a304f188002f59e7b7a1e1fe3a712988c7092a213f8c2e8f",
      "timestamp": "0x00",
      "transactionsTrie": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
      "uncleHash": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
      "withdrawalsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
    },
    "genesisRLP": "0xf90219f90213a00000000000000000000000000000000000000000000000000000000000000000a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347942adc25665018aa1fe0e6bc666dac8fc2697ff9baa0f3d3787e33cb7913a304f188002f59e7b7a1e1fe3a712988c7092a213f8c2e8fa056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b901000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080808405f5e100808000a000000000000000000000000000000000000000000000000000000000000200008800000000000000000ba056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421c0c0c0",
    "lastblockhash": "0xc52b87215ff3cea57b70b9e2104f7be6877a00eb98a1f10e8f4941aaefc90ae6",
    "network": "Shanghai",
    "postState": {
      "0x0000000000000000000000000000000000000100": {
        "balance": "0x0ba1a9ce0ba1a9ce",
        "code": "0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0160005500",
        "nonce": "0x00",
        "storage": {
          "0x00": "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe"
        }
      },
      "0x0000000000000000000000000000000000000101": {
        "balance": "0x0ba1a9ce0ba1a9ce",
        "code": "0x60047fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0160005500",
        "nonce": "0x00",
        "storage": {}
      },
      "0x0000000000000000000000000000000000000102": {
        "balance": "0x0ba1a9ce0ba1a9ce",
        "code": "0x60017fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0160005500",
        "nonce": "0x00",
        "storage": {}
      },
      "0x0000000000000000000000000000000000000103": {
        "balance": "0x0ba1a9ce0ba1a9ce",
        "code": "0x600060000160005500",
        "nonce": "0x00",
        "storage": {}
      },
      "0x0000000000000000000000000000000000000104": {
        "balance": "0x0ba1a9ce0ba1a9ce",
        "code": "0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff60010160005500",
        "nonce": "0x00",
        "storage": {}
      },
      "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b": {
        "balance": "0x0ba1a9ce0b9aa781",
        "code": "0x",
        "nonce": "0x01",
        "storage": {}
      },
      "0xcccccccccccccccccccccccccccccccccccccccc": {
        "balance": "0x0ba1a9ce0ba1a9cf",
        "code": "0x600060006000600060006004356101000162fffffff100",
        "nonce": "0x00",
        "storage": {}
      }
    },
    "pre": {
      "0x0000000000000000000000000000000000000100": {
        "balance": "0x0ba1a9ce0ba1a9ce",
        "code": "0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0160005500",
        "nonce": "0x00",
        "storage": {}
      },
      "0x0000000000000000000000000000000000000101": {
        "balance": "0x0ba1a9ce0ba1a9ce",
        "code": "0x60047fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0160005500",
        "nonce": "0x00",
        "storage": {}
      },
      "0x0000000000000000000000000000000000000102": {
        "balance": "0x0ba1a9ce0ba1a9ce",
        "code": "0x60017fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0160005500",
        "nonce": "0x00",
        "storage": {}
      },
      "0x0000000000000000000000000000000000000103": {
        "balance": "0x0ba1a9ce0ba1a9ce",
        "code": "0x600060000160005500",
        "nonce": "0x00",
        "storage": {}
      },
      "0x0000000000000000000000000000000000000104": {
        "balance": "0x0ba1a9ce0ba1a9ce",
        "code": "0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff60010160005500",
        "nonce": "0x00",
        "storage": {}
      },
      "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b": {
        "balance": "0x0ba1a9ce0ba1a9ce",
        "code": "0x",
        "nonce": "0x00",
        "storage": {}
      },
      "0xcccccccccccccccccccccccccccccccccccccccc": {
        "balance": "0x0ba1a9ce0ba1a9ce",
        "code": "0x600060006000600060006004356101000162fffffff100",
        "nonce": "0x00",
        "storage": {}
      }
    },
    "sealEngine": "NoProof"
  }}
    
    "#;

        let v: serde_json::Value = serde_json::from_str(data).expect("Failed to parse JSON");

        // Get the first entry as a (key, value) tuple and clone the values to ensure no reference to `v`
        // remains
        let (_test_name, test_structure) =
            v.as_object().and_then(|obj| obj.iter().next()).map(|(k, v)| (k.clone(), v.clone())).unwrap();

        // decode rlp of block
        // look into constructing a TransactionSigned just from the transaction field
        // let decoded = SealedBlock::decode()

        // Given
        let test_environment = Arc::new(kakarot_test_env_ctx);
        let starknet_client = test_environment.client().starknet_provider();

        // REFACTOR: would be good to have this done in a single helper
        let _class_hashes = compute_kakarot_contracts_class_hash();
        let kakarot_class_hashes: HashMap<String, FieldElement> =
            _class_hashes.into_iter().map(|(filename, class_hash)| (filename.to_string(), class_hash)).collect();

        // TODO we want to preserve the evm -> starknet mapping for easier assertions of post-state

        // Create an atomic reference to the test environment to avoid dropping it
        let env = Arc::clone(&test_environment);
        // It is not possible to block the async test task, so we need to spawn a blocking task

        // prop up seed state
        let binding = test_structure.clone();

        tokio::task::spawn_blocking(move || {
            let pre = binding.get("pre").unwrap();
            // let mut locked_address_mapping = address_map.lock().unwrap();

            // Get lock on the Starknet sequencer
            let mut starknet = env.sequencer().sequencer.backend.state.blocking_write();
            let mut storage = HashMap::new();
            // iterate through pre-state addresses
            for (original_address, account_info) in pre.as_object().unwrap().iter() {
                let address_ = FieldElement::from_str(original_address).unwrap();
                let address_as_sn_address =
                    compute_starknet_address(env.kakarot().kakarot_address, env.kakarot().proxy_class_hash, address_);
                dbg!(original_address, address_as_sn_address);
                // balance
                let balance = U256::from_str(account_info.get("balance").unwrap().as_str().unwrap())
                    .expect("balance ddshould be convertable to u256");
                let balance_storage_tuples_madara = genesis_fund_starknet_address(address_as_sn_address, balance);
                madara_to_katana_storage(balance_storage_tuples_madara, &mut storage);

                // storage
                if let Some(evm_contract_storage) = account_info.get("storage").unwrap().as_object() {
                    let mut evm_contract_storage: Vec<(U256, U256)> = evm_contract_storage
                        .iter()
                        .map(|(k, v)| {
                            (U256::from_str(k.as_str()).unwrap(), U256::from_str(v.as_str().unwrap()).unwrap())
                        })
                        .collect();
                    evm_contract_storage.sort_by_key(|(key, _)| *key);
                    evm_contract_storage.iter().for_each(|(key, value)| {
                        // Call genesis_set_storage_kakarot_contract_account util to get the storage tuples
                        let storage_tuples =
                            genesis_set_storage_kakarot_contract_account(address_as_sn_address, *key, *value);
                        madara_to_katana_storage(storage_tuples, &mut storage);
                    });
                }

                // eoa / contract distinction
                let proxy_implementation_class_hash = if let Some(bytecode) = account_info.get("code") {
                    let code_as_bytes = Bytes::from_str(bytecode.as_str().unwrap()).unwrap();
                    let kakarot_bytes_storage_madara = genesis_set_bytecode(&code_as_bytes, address_as_sn_address);
                    madara_to_katana_storage(kakarot_bytes_storage_madara, &mut storage);

                    let key = get_starknet_storage_key("bytecode_len_", &[]);
                    let value = Into::<StarkFelt>::into(StarkFelt::from(code_as_bytes.len() as u64));
                    storage.insert(key, value);

                    env.kakarot().contract_account_class_hash
                } else {
                    *kakarot_class_hashes.get("externally_owned_account").expect("failed to get eoa class hash")
                };

                let address =
                    StarknetContractAddress(Into::<StarkFelt>::into(address_as_sn_address).try_into().unwrap());
                let account_nonce =
                    FieldElement::from_str(account_info.get("nonce").unwrap().as_str().unwrap()).unwrap();
                let storage_record = StorageRecord {
                    nonce: Nonce(StarkFelt::from(account_nonce)),
                    class_hash: ClassHash(proxy_implementation_class_hash.into()),
                    storage: storage.clone(),
                };
                starknet.storage.insert(address, storage_record);
            }
        })
        .await
        .unwrap();

        test_environment.sequencer().sequencer.backend.generate_latest_block().await;
        test_environment.sequencer().sequencer.backend.generate_pending_block().await;

        let temp_value = test_structure.clone();
        let blocks = temp_value.get("blocks").unwrap();

        let block_rlp_bytes =
            Bytes::from_str(blocks.get(0).unwrap().as_object().unwrap().get("rlp").unwrap().as_str().unwrap()).unwrap();
        let parsed_block = SealedBlock::decode(&mut block_rlp_bytes.as_ref());
        // let signed_transaction = parsed_block.unwrap().body.get(0).unwrap();
        let mut encoded_transaction = BytesMut::new();
        parsed_block.unwrap().body.get(0).unwrap().encode(&mut encoded_transaction);

        // execute transaction in block
        let client = test_environment.client();
        let hash = client.send_transaction(encoded_transaction.to_vec().into()).await.unwrap();
        dbg!(hash);
        let transaction_hash: FieldElement = FieldElement::from_bytes_be(&hash).unwrap();
        dbg!(&transaction_hash);
        let receipt = starknet_client
            .get_transaction_receipt::<FieldElement>(transaction_hash.into())
            .await
            .expect("transaction has receipt");
        // let txns = &test_environment.sequencer().sequencer.backend.storage.read().await.transactions;

        dbg!(receipt);

        // assert on post state
        // prop up seed state
        // let binding = test_structure.clone();
        // let env = Arc::clone(&test_environment);
        // tokio::task::spawn_blocking(move || {
        //     let post_state = binding.get("postState").unwrap();

        //     // Get lock on the Starknet sequencer
        //     let starknet = env.sequencer().sequencer.backend.state.blocking_read();

        //     // dbg!(&env.sequencer().sequencer.backend);
        //     // iterate through post-state addresses
        //     for (original_address, account_info) in post_state.as_object().unwrap().iter() {

        //         let address_ = FieldElement::from_str(original_address).unwrap();
        //         let address_as_sn_address =
        // compute_starknet_address(env.kakarot().kakarot_address, env.kakarot().proxy_class_hash,
        // address_);          let address =
        //         StarknetContractAddress(Into::<StarkFelt>::into(address_as_sn_address).
        // try_into().unwrap());         dbg!(original_address,
        // starknet.storage.get(&address));

        //     };
        // }).await.unwrap();
    }

    /// This test verifies that the `genesis_fund_starknet_address` function generates the correct
    /// Vec of storage data tuples for a given Starknet address and amount.
    #[tokio::test]
    async fn test_genesis_fund_starknet_address() {
        // Given
        let starknet_address = FieldElement::from_hex_be("0x1234").unwrap();
        let token_fee_address = FieldElement::from_hex_be(STARKNET_NATIVE_TOKEN).unwrap();
        let storage_variable_name = "ERC20_balances";
        let amount = U256::from_str("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap();
        let amount_split = split_u256_into_field_elements(amount);

        // This is equivalent to pre-funding the Starknet address with
        // 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb Fee Tokens.
        // The first storage key is for u256.low
        // The second storage key is for u256.high
        let expected_output = vec![
            (
                (
                    token_fee_address.into(),
                    get_storage_var_address(storage_variable_name, &[starknet_address]).unwrap().into(), /* offset for amount.low */
                ),
                amount_split[0].into(), // amount.low
            ),
            (
                (
                    token_fee_address.into(),
                    (get_storage_var_address(storage_variable_name, &[starknet_address]).unwrap()
                        + FieldElement::from(1u64))
                    .into(), // offset for amount.high
                ),
                amount_split[1].into(), // amount.high
            ),
        ];

        // When
        let result = genesis_fund_starknet_address(starknet_address, amount);

        // Then
        assert_eq!(result, expected_output);
    }

    /// This test verifies that the `genesis_set_storage_kakarot_contract_account` function
    /// generates the correct tuples for a given Starknet address, keys, storage value, and
    /// storage key offset.
    #[tokio::test]
    async fn test_genesis_set_storage_kakarot_contract_account() {
        // Given
        let starknet_address = FieldElement::from_hex_be("0x1234").unwrap();
        let key = U256::from_str("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap();
        let storage_variable_name = "storage_";
        let value = U256::from_str("0xccccccccccccccccccccccccccccccccdddddddddddddddddddddddddddddddd").unwrap();
        let value_split = split_u256_into_field_elements(value);

        // This is equivalent to setting the storage of Kakarot contract account's `storage_` variable at
        // index 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb to
        // 0xccccccccccccccccccccccccccccccccdddddddddddddddddddddddddddddddd. The first storage key
        // is for value.low. The second storage key is for value.high.
        let expected_output = vec![
            (
                (
                    starknet_address.into(),
                    get_storage_var_address(storage_variable_name, &split_u256_into_field_elements(key))
                        .unwrap()
                        .into(), // offset for value.low
                ),
                value_split[0].into(), // value.low
            ),
            (
                (
                    starknet_address.into(),
                    (get_storage_var_address(storage_variable_name, &split_u256_into_field_elements(key)).unwrap()
                        + FieldElement::from(1u64))
                    .into(), // offset for value.high
                ),
                value_split[1].into(), // value.high
            ),
        ];

        // When
        let result = genesis_set_storage_kakarot_contract_account(starknet_address, key, value);
        // Then
        assert_eq!(result, expected_output);
    }

    #[rstest]
    #[tokio::test(flavor = "multi_thread")]
    async fn test_kakarot_contract_account_storage(kakarot_test_env_ctx: KakarotTestEnvironmentContext) {
        // Given
        let test_environment = Arc::new(kakarot_test_env_ctx);

        // When
        // Use genesis_set_storage_kakarot_contract_account define the storage data
        // to be stored into the contract account
        let genesis_address = FieldElement::from_str("0x1234").unwrap();
        let expected_key =
            U256::from_str("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap();
        let expected_value =
            U256::from_str("0xccccccccccccccccccccccccccccccccdddddddddddddddddddddddddddddddd").unwrap();
        let genesis_storage_data =
            genesis_set_storage_kakarot_contract_account(genesis_address, expected_key, expected_value);

        // Create an atomic reference to the test environment to avoid dropping it
        let env = Arc::clone(&test_environment);
        // It is not possible to block the async test task, so we need to spawn a blocking task
        tokio::task::spawn_blocking(move || {
            // Get lock on the Starknet sequencer
            let mut starknet = env.sequencer().sequencer.backend.state.blocking_write();
            let mut storage = HashMap::new();

            // Prepare the record to be inserted into the storage
            genesis_storage_data.into_iter().for_each(|((_, k), v)| {
                let storage_key = StarknetStorageKey(Into::<StarkFelt>::into(k.0).try_into().unwrap());
                let storage_value = Into::<StarkFelt>::into(v.0);
                storage.insert(storage_key, storage_value);
            });

            // Set the storage record for the contract
            let contract_account_class_hash = env.kakarot().contract_account_class_hash;
            let genesis_address = StarknetContractAddress(Into::<StarkFelt>::into(genesis_address).try_into().unwrap());
            let storage_record = StorageRecord {
                nonce: Nonce(StarkFelt::from(0u8)),
                class_hash: ClassHash(contract_account_class_hash.into()),
                storage,
            };
            starknet.storage.insert(genesis_address, storage_record);
        })
        .await
        .unwrap();

        // Deploy the contract account with the set genesis storage and retrieve the storage on the contract
        let starknet_client = test_environment.client().starknet_provider();
        let genesis_contract = ContractAccount::new(genesis_address, &starknet_client);
        let [key_low, key_high] = split_u256_into_field_elements(expected_key);
        let actual_value =
            genesis_contract.storage(&key_low, &key_high, &StarknetBlockId::Tag(BlockTag::Latest)).await.unwrap();

        // Assert that the value stored in the contract is the same as the value we set in the genesis
        assert_eq!(expected_value, actual_value);
    }
}
