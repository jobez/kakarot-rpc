#[cfg(test)]
mod tests {

    use std::collections::HashMap;
    use std::fs;
    use std::str::FromStr;
    use std::sync::Arc;

    use blockifier::state::state_api::StateReader;
    use dojo_test_utils::sequencer::TestSequencer;
    use kakarot_rpc_core::client::client_api::KakarotClient;
    use kakarot_rpc_core::mock::wiremock_utils::setup_mock_client_crate;
    use kakarot_rpc_core::models::block::BlockWithTxs;
    use kakarot_rpc_core::models::convertible::{ConvertibleStarknetBlock, ConvertibleStarknetEvent};
    use kakarot_rpc_core::models::event::StarknetEvent;
    use reth_primitives::{Address, Bytes, H256};
    use reth_rpc_types::Log;
    use starknet::accounts::{Account, Call, ConnectedAccount, SingleOwnerAccount};
    use starknet::contract::ContractFactory;
    use starknet::core::types::contract::legacy::LegacyContractClass;
    use starknet::core::types::{
        BlockId, BlockTag, DeclareTransactionReceipt, Event, FieldElement, FunctionCall,
        MaybePendingTransactionReceipt, TransactionReceipt, TransactionStatus,
    };
    use starknet::core::utils::{get_contract_address, get_selector_from_name};
    use starknet::providers::jsonrpc::HttpTransport;
    use starknet::providers::{JsonRpcClient, Provider};
    use starknet::signers::LocalWallet;
    use starknet_api::block::BlockNumber;
    use starknet_api::core::{ClassHash, ContractAddress, PatriciaKey};
    use starknet_api::hash::{StarkFelt, StarkHash};
    use starknet_api::{patricia_key, stark_felt};

    async fn deploy_contract(
        sequencer: &TestSequencer,
        account: &SingleOwnerAccount<JsonRpcClient<HttpTransport>, LocalWallet>,
        class_hash: FieldElement,
        constructor_calldata: Vec<FieldElement>,
    ) -> Result<FieldElement, Box<dyn std::error::Error>> {
        // let calldata = [
        //     vec![
        //         class_hash,                                     // class hash
        //         FieldElement::ZERO,                             // salt
        //         FieldElement::ZERO,                             // unique
        //         FieldElement::from(constructor_calldata.len()), // constructor calldata len
        //     ],
        //     constructor_calldata.clone(),
        // ]
        // .concat();

        let factory = ContractFactory::new(class_hash, account);

        let result = factory.deploy(constructor_calldata.clone(), FieldElement::ZERO, false).send().await.unwrap();

        let contract_address =
            get_contract_address(FieldElement::ZERO, class_hash, &constructor_calldata.clone(), FieldElement::ZERO);

        // let res = account
        //     .execute(vec![Call {
        //         calldata,
        //         // devnet UDC address
        //         to:
        // FieldElement::from_hex_be("0x41a78e741e5af2fec34b695679bc6891742439f7afb8484ecd7766661ad02bf")?,
        //         selector: get_selector_from_name("deployContract")?,
        //     }])
        //     .send()
        //     .await?;

        let receipt = account.provider().get_transaction_receipt(&result.transaction_hash).await.unwrap();

        dbg!(&result, receipt);

        let starknet = sequencer.sequencer.starknet.write().await;

        dbg!(contract_address, class_hash);
        dbg!(&starknet.state.address_to_class_hash);

        if starknet.state.address_to_class_hash.contains_key(&ContractAddress(patricia_key!(contract_address))) {
            Ok(contract_address)
        } else {
            Err("Contract is not deployed".into())
        }
    }

    #[tokio::test]
    async fn test_use_test_sequencer() {
        let sequencer = TestSequencer::start().await;

        // todo, move to constants
        let eth_token_address =
            FieldElement::from_hex_be("0x49D36570D4E46F48E99674BD3FCC84644DDD6B96F7C741B1562B82F9E004DC7").unwrap();

        // derived from python script, TODO to do this in rust
        let evm_public_key = "0x1e81631727Ba60f6F5596D2C9c8f45b7AAff0096";

        let paths = fs::read_dir("tests/kkrt_compiled").expect("Could not read directory");

        let kkrt_compiled_contracts: Vec<_> = paths
            .filter_map(|entry| {
                let entry = entry.ok()?;
                let path = entry.path();
                if path.extension().unwrap_or_default() != "json" {
                    return None;
                }
                Some(path)
            })
            .collect();

        let account = sequencer.account();
        type DeclaredClassHash = FieldElement;
        let mut class_hash: HashMap<String, DeclaredClassHash> = HashMap::new();
        for path in kkrt_compiled_contracts {
            let file = fs::File::open(&path).unwrap();
            let legacy_contract: LegacyContractClass = serde_json::from_reader(file).unwrap();
            let contract_class = Arc::new(legacy_contract);

            let res = account.declare_legacy(contract_class).send().await.unwrap();
            let receipt = account.provider().get_transaction_receipt(res.transaction_hash).await.unwrap();

            let block_number =
                match receipt {
                    MaybePendingTransactionReceipt::Receipt(TransactionReceipt::Declare(
                        DeclareTransactionReceipt { status, block_number, .. },
                    )) => {
                        if status != TransactionStatus::AcceptedOnL2 {
                            panic!("Invalid status for {}", path.display());
                        } else {
                            block_number
                        }
                    }
                    _ => panic!("Invalid tx receipt for {}", path.display()),
                };

            let filename = path
                .file_stem()
                .expect("File has no stem")
                .to_str()
                .expect("Cannot convert filename to string")
                .to_owned();

            dbg!(&res, block_number);
            let mut state = sequencer.sequencer.starknet.write().await.state(BlockNumber(block_number)).unwrap();
            assert!(
                state.get_compiled_contract_class(&ClassHash(stark_felt!(res.class_hash))).is_ok(),
                "class is not declared"
            );

            class_hash.insert(filename, res.class_hash);
        }

        let mut deployments: HashMap<String, DeclaredClassHash> = HashMap::new();

        let kkrt_constructor_calldata = vec![
            account.address(),
            eth_token_address,
            class_hash.get("contract_account").unwrap().clone(),
            class_hash.get("externally_owned_account").unwrap().clone(),
            class_hash.get("proxy").unwrap().clone(),
        ];

        let kkrt_res = deploy_contract(
            &sequencer,
            &account,
            class_hash.get("kakarot").unwrap().clone(),
            kkrt_constructor_calldata,
        );

        deployments.insert("kakarot".to_string(), kkrt_res.await.unwrap());

        let kkrt_address = deployments.get("kakarot").unwrap().clone();

        let blockhash_registry_calldata = vec![kkrt_address];

        let blockhash_registry_res = deploy_contract(
            &sequencer,
            &account,
            class_hash.get("blockhash_registry").unwrap().clone(),
            blockhash_registry_calldata,
        );

        deployments.insert("blockhash_registry".to_string(), blockhash_registry_res.await.unwrap());

        let blockhash_registry_addr = deployments.get("blockhash_registry").unwrap().clone();

        dbg!(class_hash);
        dbg!(deployments);

        let call_set_blockhash_registry = vec![Call {
            to: kkrt_address,
            selector: get_selector_from_name("set_blockhash_registry").unwrap(),
            calldata: vec![blockhash_registry_addr],
        }];

        let result = account.execute(call_set_blockhash_registry).send().await.unwrap();
        let receipt = account.provider().get_transaction_receipt(result.transaction_hash).await.unwrap();

        dbg!(receipt);

        let mut state = sequencer.sequencer.starknet.write().await.state(BlockNumber(9)).unwrap();

        let call_get_starknet_address = FunctionCall {
            contract_address: kkrt_address,
            entry_point_selector: get_selector_from_name("compute_starknet_address").unwrap(),
            calldata: vec![FieldElement::from_hex_be(evm_public_key).unwrap()],
        };

        let eoa_account_starknet_address_result =
            account.provider().call(call_get_starknet_address, BlockId::Tag(BlockTag::Latest)).await;

        dbg!(&eoa_account_starknet_address_result);

        let deployment_of_eoa_account_result = account
            .execute(vec![Call {
                calldata: vec![FieldElement::from_hex_be(evm_public_key).unwrap()],
                // devnet UDC address
                to: kkrt_address,
                selector: get_selector_from_name("deploy_externally_owned_account").unwrap(),
            }])
            .send()
            .await
            .unwrap();

        let deployment_of_eoa_account_result_receipt = account
            .provider()
            .get_transaction_receipt(&deployment_of_eoa_account_result.transaction_hash)
            .await
            .unwrap();

        dbg!(&deployment_of_eoa_account_result_receipt);

        let eoa_account_starknet_address =
            eoa_account_starknet_address_result.unwrap().clone().first().expect("fails here").clone();
        let amount_low = FieldElement::from_dec_str("1337").expect("actually fails here");
        let amount_high = FieldElement::from_dec_str("0").expect("actually fails here");

        let transfer_calldata = vec![eoa_account_starknet_address, amount_low, amount_high];

        let transfer_res = account
            .execute(vec![Call {
                calldata: transfer_calldata,
                // eth fee addr
                to: FieldElement::from_hex_be("0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7")
                    .unwrap(),
                selector: get_selector_from_name("transfer").unwrap(),
            }])
            .send()
            .await
            .unwrap();

        let transfer_receipt =
            account.provider().get_transaction_receipt(&transfer_res.transaction_hash).await.unwrap();

        dbg!(transfer_receipt);

        let call_get_balance_of_starknet_address_of_eoa = FunctionCall {
            contract_address: FieldElement::from_hex_be(
                "0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7",
            )
            .unwrap(),
            entry_point_selector: get_selector_from_name("balanceOf").unwrap(),
            calldata: vec![eoa_account_starknet_address],
        };

        let balance_of_starknet_address_of_eoa_result =
            account.provider().call(call_get_balance_of_starknet_address_of_eoa, BlockId::Tag(BlockTag::Latest)).await;

        dbg!(&balance_of_starknet_address_of_eoa_result);
    }

    #[tokio::test]
    async fn test_starknet_block_to_eth_block() {
        let client = setup_mock_client_crate().await;
        let starknet_client = client.inner();
        let starknet_block = starknet_client.get_block_with_txs(BlockId::Tag(BlockTag::Latest)).await.unwrap();
        let eth_block = BlockWithTxs::new(starknet_block).to_eth_block(&client).await.unwrap();

        // TODO: Add more assertions & refactor into assert helpers
        // assert helpers should allow import of fixture file
        assert_eq!(
            eth_block.header.hash,
            Some(H256::from_slice(
                &FieldElement::from_hex_be("0x449aa33ad836b65b10fa60082de99e24ac876ee2fd93e723a99190a530af0a9")
                    .unwrap()
                    .to_bytes_be()
            ))
        )
    }

    #[tokio::test]
    async fn test_starknet_event_to_eth_log_success() {
        let client = setup_mock_client_crate().await;
        // given
        let data =
            vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10];
        let felt_data: Vec<FieldElement> =
            data.iter().map(|&x| FieldElement::from_dec_str(&x.to_string()).unwrap()).collect();
        let bytes_data: Bytes = felt_data.iter().flat_map(|felt| felt.to_bytes_be()).collect::<Vec<u8>>().into();
        // see https://github.com/kkrt-labs/kakarot/blob/2133aaf58d5c8ae493c579570e43c9e011774309/tests/integration/solidity_contracts/PlainOpcodes/test_plain_opcodes.py#L120 this test generates the starknet event and ethereum log expected pair

        // FROM is hardcoded to the current hardcoded value of kakarot_contract
        let kakarot_address =
            FieldElement::from_hex_be("0x566864dbc2ae76c2d12a8a5a334913d0806f85b7a4dccea87467c3ba3616e75").unwrap();

        let event3 = Event {
            from_address: kakarot_address,
            keys: vec![
                FieldElement::from_dec_str("169107000779806480224941431033275202659").unwrap(),
                FieldElement::from_dec_str("119094765373898665007727700504125002894").unwrap(),
                FieldElement::from_dec_str("10").unwrap(),
                FieldElement::ZERO,
                FieldElement::from_dec_str("11").unwrap(),
                FieldElement::ZERO,
                FieldElement::from_dec_str("247666869351872231004050922759157890085502224190").unwrap(),
            ],
            data: felt_data,
        };

        let sn_event3 = StarknetEvent::new(event3);

        // when
        let resultant_eth_log3 = sn_event3
            .to_eth_log(&client, Option::None, Option::None, Option::None, Option::None, Option::None)
            .await
            .unwrap();

        // then
        let expected_eth_log3 = Log {
            address: Address::from_str("0x2B61c43A85bD35987C5311215e8288b823A6873E").unwrap(),
            topics: vec![
                H256::from_slice(
                    &hex::decode("5998d146b8109b9444e9bb13ae9a548e7f38d2db6e0da72afe22cefa3065bc63").unwrap(),
                ),
                H256::from_slice(
                    &hex::decode("000000000000000000000000000000000000000000000000000000000000000a").unwrap(),
                ),
                H256::from_slice(
                    &hex::decode("000000000000000000000000000000000000000000000000000000000000000b").unwrap(),
                ),
            ],
            data: bytes_data,
            transaction_hash: Option::None,
            block_hash: Option::None,
            block_number: Option::None,
            log_index: Option::None,
            transaction_index: Option::None,
            removed: false,
        };

        assert_eq!(expected_eth_log3, resultant_eth_log3);

        // see https://github.com/kkrt-labs/kakarot/blob/2133aaf58d5c8ae493c579570e43c9e011774309/tests/integration/solidity_contracts/PlainOpcodes/test_plain_opcodes.py#L124 this test generates the starknet event and ethereum log expected pair
        // given
        let event4 = Event {
            from_address: kakarot_address,
            keys: vec![
                FieldElement::from_dec_str("253936425291629012954210100230398563497").unwrap(),
                FieldElement::from_dec_str("171504579546982282416100792885946140532").unwrap(),
                FieldElement::from_dec_str("10").unwrap(),
                FieldElement::ZERO,
                FieldElement::from_dec_str("11").unwrap(),
                FieldElement::ZERO,
                FieldElement::from_dec_str("10").unwrap(),
                FieldElement::ZERO,
                FieldElement::from_dec_str("247666869351872231004050922759157890085502224190").unwrap(),
            ],
            data: vec![],
        };

        let sn_event4 = StarknetEvent::new(event4);

        // when
        let resultant_eth_log4 = sn_event4
            .to_eth_log(&client, Option::None, Option::None, Option::None, Option::None, Option::None)
            .await
            .unwrap();

        // then
        let expected_eth_log4 = Log {
            address: Address::from_str("0x2B61c43A85bD35987C5311215e8288b823A6873E").unwrap(),
            topics: vec![
                H256::from_slice(
                    &hex::decode("8106949def8a44172f54941ce774c774bf0a60652fafd614e9b6be2ca74a54a9").unwrap(),
                ),
                H256::from_slice(
                    &hex::decode("000000000000000000000000000000000000000000000000000000000000000a").unwrap(),
                ),
                H256::from_slice(
                    &hex::decode("000000000000000000000000000000000000000000000000000000000000000b").unwrap(),
                ),
                H256::from_slice(
                    &hex::decode("000000000000000000000000000000000000000000000000000000000000000a").unwrap(),
                ),
            ],
            data: Bytes::default(),
            transaction_hash: Option::None,
            block_hash: Option::None,
            block_number: Option::None,
            log_index: Option::None,
            transaction_index: Option::None,
            removed: false,
        };

        assert_eq!(expected_eth_log4, resultant_eth_log4);
    }

    #[tokio::test]
    async fn test_starknet_event_to_eth_log_failure_from_address_not_kkrt_address() {
        let client = setup_mock_client_crate().await;

        let key_selector = get_selector_from_name("bbq_time").unwrap();
        // given
        let event = Event {
            // from address is not kkrt address
            from_address: FieldElement::from_hex_be("0xdeadbeef").unwrap(),
            keys: vec![key_selector],
            data: vec![],
        };

        let sn_event = StarknetEvent::new(event);

        // when
        let resultant_eth_log =
            sn_event.to_eth_log(&client, Option::None, Option::None, Option::None, Option::None, Option::None).await;

        // then
        // Expecting an error because the high value doesn't exist.
        match resultant_eth_log {
            Ok(_) => panic!("Expected an error due to missing high value, but got a result."),
            Err(err) => assert_eq!(err.to_string(), "Kakarot Filter: Event is not part of Kakarot"),
        }
    }

    #[tokio::test]
    async fn test_starknet_transaction_by_hash() {
        let client = setup_mock_client_crate().await;
        let starknet_tx = client
            .transaction_by_hash(
                H256::from_str("0x03204b4c0e379c3a5ccb80d08661d5a538e95e2960581c9faf7ebcf8ff5a7d3c").unwrap(),
            )
            .await;
        assert!(starknet_tx.is_ok());
    }
}
