use std::{collections::HashMap, str::FromStr};

use bitcoin::blockdata::opcodes::all;
use bitcoin::hashes::hex::FromHex;
use bitcoin::psbt::{Prevouts, TapTree};
use bitcoin::schnorr::TapTweak;
use bitcoin::util::key::secp256k1::{schnorr, KeyPair, Message, PublicKey, Secp256k1, SecretKey};
use bitcoin::util::sighash::{ScriptPath, SighashCache};
use bitcoin::util::taproot::{LeafVersion, TaprootBuilder};
use bitcoin::{
    bech32::decode,
    blockdata::script::Builder,
    hashes::{self, sha256, Hash},
    psbt::serialize::Serialize,
    OutPoint, PrivateKey, Script, Transaction as BitcoinLibTransaction, TxIn, TxOut, Witness,
};
use bitcoin::{Address, SchnorrSig, SchnorrSighashType, Sighash, Txid};
use bitcoin_utils::{
    convert_wif_to_private_key, double_sha256_hex, get_p2tr_address_from_pubkey,
    get_public_key_from_wif, get_public_key_hash_from_address, get_public_key_hash_from_public_key,
    get_script_hash_from_p2sh_address, get_tweaked_x_only_public_key_from_p2tr_address,
    get_wif_from_private_key, hash160_for_hex, sha256_hex, sha256_non_hex,
};
use sha2::{Digest, Sha256};
// TODO:
// - Sign a transaction with multipl p2pkh vins, not just one
// - Sign other types of transactions, not only p2pkh
use hex_utilities::{
    convert_big_endian_hex_to_little_endian, convert_decimal_to_hexadecimal, decode_hex,
    encode_hex, get_text_for_hex,
};

use crate::types::{PayFrom, PayTo, Wifs};
type SignatureScripts = HashMap<u64, String>;

// Script types:
// V0_P2WPKH: https://mempool.space/testnet/tx/b7203bd59b3c26c65699251939e1e6353f5f09952156c5b9c01bbe9f5372b89c
// P2SH: https://mempool.space/testnet/tx/04d984cdcf728975c173c45c49a242cedee2da5dc200b2f83ca6a98aecf11280
// P2PKH: https://mempool.space/testnet/tx/b7203bd59b3c26c65699251939e1e6353f5f09952156c5b9c01bbe9f5372b89c
//
// P2WPKH-in-P2SH: https://wiki.trezor.io/P2WPKH-in-P2S
// P2WPKH: https://wiki.trezor.io/P2WPKH
// p2SH-PWPKH: https://bitcoincore.org/en/segwit_wallet_dev/
//
const OP_1: &str = "51";
const OP_TRUE: &str = OP_1;
const OP_HASH160: &str = "a9";
const OP_DUP: &str = "76";
const OP_EQUAL: &str = "87";
const OP_0: &str = "00";
const OP_FALSE: &str = OP_0;
const OP_EQUALVERIFY: &str = "88";
const OP_CHECKSIG: &str = "ac";

fn is_script_pub_key_a_p2wpkh(script_pub_key: &String) -> bool {
    script_pub_key.starts_with(OP_0)
}
fn is_script_pub_key_a_p2sh(script_pub_key: &String) -> bool {
    script_pub_key.starts_with(OP_HASH160) && script_pub_key.ends_with(OP_EQUAL)
}
fn is_script_pub_key_a_p2sh_p2wpkh(script_pub_key: &String) -> bool {
    script_pub_key.starts_with(OP_HASH160) && script_pub_key.ends_with(OP_EQUAL)
}
fn is_script_pub_key_a_p2pkh(script_pub_key: &String) -> bool {
    let starting_script = format!("{}{}", OP_DUP, OP_HASH160);
    let ending_script = format!("{}{}", OP_EQUALVERIFY, OP_CHECKSIG);
    script_pub_key.starts_with(&starting_script) && script_pub_key.ends_with(&ending_script)
}

fn is_segwit_transaction() {
    // If a transaction has at least one SegWit input, native or wrapped, then it’s a SegWit transaction. Such transactions are serialized differently from legacy ones. Actually, it’s a little more complex, because we have one format for signing and a whole different one for pushing.
    todo!()
}
fn get_version(version: u8) -> String {
    if version > 2 {
        panic!("Version not supported")
    }
    // currently version 1
    // https://en.bitcoin.it/wiki/Transaction
    let hex = convert_decimal_to_hexadecimal(version as u64, false, Some(4));

    let little_endian_version_hex = convert_big_endian_hex_to_little_endian(&hex);
    little_endian_version_hex
}

fn get_input_count(input_count: u64) -> String {
    // https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer
    // Currently, only works up to 253 inputs
    // Explaination of var-ints: https://thunderbiscuit.com/posts/transactions-legacy/
    if input_count < 253 {
        format!("{:02x}", input_count)
    } else {
        todo!();
    }
    // else if input_count <= 65535 {
    //     todo!()
    // } else if input_count <= 4294967295 {
    //     todo!()
    // } else {
    //     todo!()
    // }
}
fn get_prev_transaction_hash(prev_output_hash: &String) -> String {
    let little_endian_prev_output_hash = convert_big_endian_hex_to_little_endian(&prev_output_hash);
    little_endian_prev_output_hash
}
fn get_prev_transaction_output_index(index: u64) -> String {
    let hex = convert_decimal_to_hexadecimal(index, false, Some(4));
    let hex_little_endian = convert_big_endian_hex_to_little_endian(&hex);
    hex_little_endian
}
fn get_byte_length_of_hex(hex: &str) -> String {
    // Hardcoded to the length of our hardcoded input scrip sig below
    // https://mempool.space/testnet/tx/2eabf6f8d63d25005866521c844449765e99e43948cb36dd6bbfad544a3d0f17
    let hex_as_bytes = decode_hex(hex).unwrap();
    let hex_bytes_count = hex_as_bytes.len();
    let length_bytes_in_hex =
        convert_decimal_to_hexadecimal(hex_bytes_count as u64, false, Some(1));
    length_bytes_in_hex
}
fn get_input_script_sig_length(input_script_hex: &str) -> String {
    get_byte_length_of_hex(input_script_hex)
}
// Before signing, the script sig in the transaction should be equal to the script pub key hex from
// the spending vout.
fn get_input_script_sig_for_signing(public_key_hash_of_vout_receiver: &String) -> String {
    // Hardcoded
    // Before signing, the script sig should be set to the spending public script sig.
    // https://mempool.space/testnet/tx/2eabf6f8d63d25005866521c844449765e99e43948cb36dd6bbfad544a3d0f17
    create_p2pkh_script_pub_key_hex_from_pub_key_hash(&public_key_hash_of_vout_receiver)
}
// Hardcoding for now
fn get_sequence(sequence: &str) -> String {
    sequence.to_string()
}

fn get_output_count(output_count: u64) -> String {
    // https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer
    // Currently, only works up to 253 inputs
    // Explaination of var-ints: https://thunderbiscuit.com/posts/transactions-legacy/
    if output_count < 253 {
        format!("{:02x}", output_count)
    } else {
        todo!();
    }
    // else if input_count <= 65535 {
    //     todo!()
    // } else if input_count <= 4294967295 {
    //     todo!()
    // } else {
    //     todo!()
    // }
}

fn get_output_amount(amount_in_sats: u64) -> String {
    let amount_in_sats_hex = convert_decimal_to_hexadecimal(amount_in_sats, false, Some(8));
    let little_endian_amount_in_sats = convert_big_endian_hex_to_little_endian(&amount_in_sats_hex);
    little_endian_amount_in_sats
}
fn get_output_script_length(output_script_pub_key_hex: &String) -> String {
    // let output_script_sig_hex = get_output_script_sig(public_key_hash.to_string());
    // let output_script_sig_hex_as_bytes = decode_hex(&output_script_sig_hex).unwrap();
    // let output_script_sig_hex_bytes_count = output_script_sig_hex_as_bytes.len();
    // let script_length_bytes_in_hex =
    //     convert_decimal_to_hexadecimal(output_script_sig_hex_bytes_count as u64, false, Some(1));
    // script_length_bytes_in_hex
    get_byte_length_of_hex(output_script_pub_key_hex)
}
fn get_output_script_sig_for_p2pkh(public_key_hash: String) -> String {
    let public_key_hash_to_send_to = public_key_hash.to_string();
    create_p2pkh_script_pub_key_hex_from_pub_key_hash(&public_key_hash_to_send_to)
}
fn get_output_script_sig_for_p2sh(public_key_hash: &String) -> String {
    let length = get_byte_length_of_hex(&public_key_hash);
    // TODO: HARDCODING FOR NOW
    let sh = format!("{}{}", length, public_key_hash.to_string());

    let a = create_p2sh_script_pub_key_hex_from_sh(&sh);
    a
}
fn get_output_script_sig_for_p2wpkh(public_key_hash: &String) -> String {
    create_p2wpkh_script_pub_key_hex_from_pub_key_hash(&public_key_hash)
}
fn get_output_script_sig_for_p2tr(tweaked_x_only_public_key: &String) -> String {
    create_p2tr_script_pub_key_hex_from_tweaked_x_only_public_key(&tweaked_x_only_public_key)
}
fn get_lock_time() -> String {
    "00000000".to_string()
}

enum Transaction {
    Legacy(LegacyTransaction),
    Segwit(SegwitTransaction),
}

#[derive(Debug, Clone)]
// TODO: This should be named LegacyTransaction
pub struct SegwitTransaction {
    pub version: u8,
    pub inputs: Vec<PayFrom>,
    pub outputs: Vec<PayTo>,
    pub locktime: String,
}

impl SegwitTransaction {
    pub fn new(inputs: Vec<PayFrom>, outputs: Vec<PayTo>) -> Self {
        SegwitTransaction {
            // TODO: Shouldn't hardcode this
            version: 2,
            inputs,
            outputs,
            // TODO: Shouldn't hardcode this
            locktime: "00000000".to_string(),
        }
    }

    pub fn get_parts(&self) -> LegacyRawTransaction {
        LegacyRawTransaction {
            version_hex: get_version(self.version),
            inputs: self
                .inputs
                .iter()
                .map(|input| {
                    RawInput {
                        previous_transaction_hash_hex: input.transaction.clone(),
                        previous_transaction_output_index_hex: get_prev_transaction_output_index(
                            input.vout_index,
                        ),
                        // TODO: Hardcoding this for unsigned transactions
                        script_sig_hex: "".to_string(),
                        // TODO: Shouldn't hardcode this
                        sequence_hex: get_sequence("ffffffff"),
                    }
                })
                .collect(),
            outputs: self
                .outputs
                .iter()
                .map(|output| {
                    let address = &output.address;
                    // TODO: DO BETTER ADDRESS TYPE CHECKING HERE! Maybe use bitcoin-address
                    // package
                    let is_legacy_address = bitcoin_address::is_legacy(address);
                    let is_p2sh_address = bitcoin_address::is_p2sh(address);
                    let is_p2wpkh_address = bitcoin_address::is_segwit_native(address);
                    let is_taproot_address = bitcoin_address::is_taproot(address);
                    RawOutput {
                        amount_hex: get_output_amount(output.amount_in_sats),
                        script_pub_key_hex: if is_p2sh_address {
                            if bitcoin_address::is_nested_segwit(address) {
                                let sh = get_script_hash_from_p2sh_address(address);
                                get_output_script_sig_for_p2sh(&sh)
                            } else {
                                todo!("Support other types of p2sh")
                            }
                        } else if is_p2wpkh_address {
                            let public_key_hash = get_public_key_hash_from_address(address);
                            get_output_script_sig_for_p2wpkh(&public_key_hash)
                        } else if is_taproot_address {
                            let tweaked_x_only_public_key =
                                get_tweaked_x_only_public_key_from_p2tr_address(address);
                            println!("tweaked public_key: {}", tweaked_x_only_public_key);
                            get_output_script_sig_for_p2tr(&tweaked_x_only_public_key)
                        } else if is_legacy_address {
                            let public_key_hash = get_public_key_hash_from_address(address);
                            get_output_script_sig_for_p2pkh(public_key_hash)
                        } else {
                            panic!("address type not know: {}", address);
                        },
                    }
                })
                .collect(),
            // TODO: Hardcoded
            locktime_hex: self.locktime.clone(),
        }
    }
}

#[derive(Debug, Clone)]
// TODO: This should be named V1Transaction
struct LegacyTransaction {
    version: u8,
    inputs: Vec<PayFrom>,
    outputs: Vec<PayTo>,
    locktime: String,
}

impl LegacyTransaction {
    fn new(inputs: Vec<PayFrom>, outputs: Vec<PayTo>) -> Self {
        LegacyTransaction {
            // TODO: Shouldn't hardcode this
            version: 1,
            inputs,
            outputs,
            // TODO: Shouldn't hardcode this
            locktime: "00000000".to_string(),
        }
    }

    fn get_parts(&self) -> LegacyRawTransaction {
        LegacyRawTransaction {
            version_hex: get_version(self.version),
            inputs: self
                .inputs
                .iter()
                .map(|input| {
                    RawInput {
                        previous_transaction_hash_hex: get_prev_transaction_hash(
                            &input.transaction,
                        ),
                        previous_transaction_output_index_hex: get_prev_transaction_output_index(
                            input.vout_index,
                        ),
                        // TODO: Hardcoding this for unsigned transactions
                        script_sig_hex: "".to_string(),
                        // TODO: Shouldn't hardcode this
                        sequence_hex: get_sequence("ffffffff"),
                    }
                })
                .collect(),
            outputs: self
                .outputs
                .iter()
                .map(|output| {
                    let address = &output.address;
                    // TODO: DO BETTER ADDRESS TYPE CHECKING HERE! Maybe use bitcoin-address
                    // package
                    let is_p2sh_address = address.starts_with("2");
                    let is_p2wpkh_address = address.starts_with("tb1");
                    let public_key_hash = get_public_key_hash_from_address(address);
                    RawOutput {
                        amount_hex: get_output_amount(output.amount_in_sats),
                        script_pub_key_hex: if is_p2sh_address {
                            get_output_script_sig_for_p2sh(&public_key_hash)
                        } else if is_p2wpkh_address {
                            get_output_script_sig_for_p2wpkh(&public_key_hash)
                        } else {
                            get_output_script_sig_for_p2pkh(public_key_hash)
                        },
                    }
                })
                .collect(),
            // TODO: Hardcoded
            locktime_hex: self.locktime.clone(),
        }
    }
}
#[derive(Debug, Clone)]
pub struct RawInput {
    pub previous_transaction_hash_hex: String,
    pub previous_transaction_output_index_hex: String,
    pub script_sig_hex: String,
    pub sequence_hex: String,
}
impl RawInput {
    fn get_script_sig_length_hex(&self) -> String {
        get_input_script_sig_length(&self.script_sig_hex)
    }
    fn get_raw_string(&self, should_address_be_in_little_endian: bool) -> String {
        format!(
            "{}{}{}{}{}",
            // TODO: extract this
            // segwit uses little endian
            if should_address_be_in_little_endian {
                convert_big_endian_hex_to_little_endian(&self.previous_transaction_hash_hex)
            } else {
                self.previous_transaction_hash_hex.clone()
            },
            self.previous_transaction_output_index_hex,
            self.get_script_sig_length_hex(),
            self.script_sig_hex,
            self.sequence_hex
        )
    }
    fn replace_script_sig_hex(self, new_script_sig_hex: String) -> Self {
        let Self {
            previous_transaction_hash_hex,
            previous_transaction_output_index_hex,
            sequence_hex,
            ..
        } = self;
        Self {
            previous_transaction_hash_hex,
            previous_transaction_output_index_hex,
            sequence_hex,
            script_sig_hex: new_script_sig_hex,
        }
    }
}
#[derive(Debug, Clone)]
pub struct RawOutput {
    pub amount_hex: String,
    pub script_pub_key_hex: String,
}
impl RawOutput {
    fn get_script_pub_key_length_hex(&self) -> String {
        get_output_script_length(&self.script_pub_key_hex)
    }
    fn get_raw_string(&self) -> String {
        format!(
            "{}{}{}",
            self.amount_hex,
            self.get_script_pub_key_length_hex(),
            self.script_pub_key_hex
        )
    }
}
#[derive(Debug, Clone)]
pub struct LegacyRawTransaction {
    pub version_hex: String,
    pub inputs: Vec<RawInput>,
    pub outputs: Vec<RawOutput>,
    pub locktime_hex: String,
}
impl LegacyRawTransaction {
    pub fn get_raw_string(
        &self,
        should_include_locktime: bool,
        should_include_version: bool,
        should_input_address_be_in_little_endian: bool,
    ) -> String {
        let string_between_version_and_locktime = format!(
            "{}{}{}{}",
            self.get_inputs_count_hex(),
            self.inputs.iter().fold(String::new(), |acc, input| format!(
                "{}{}",
                acc,
                &input.get_raw_string(should_input_address_be_in_little_endian)
            )),
            self.get_outputs_count_hex(),
            self.outputs
                .iter()
                .fold(String::new(), |acc, input| format!(
                    "{}{}",
                    acc,
                    &input.get_raw_string()
                )),
        );
        let string_after_version = if should_include_locktime {
            format!(
                "{}{}",
                string_between_version_and_locktime, self.locktime_hex
            )
        } else {
            string_between_version_and_locktime
        };
        if should_include_version {
            format!("{}{}", self.version_hex, string_after_version)
        } else {
            string_after_version
        }
    }
    fn get_inputs_count_hex(&self) -> String {
        get_input_count(self.inputs.len() as u64)
    }
    fn get_outputs_count_hex(&self) -> String {
        get_output_count(self.outputs.len() as u64)
    }
    fn replace_script_sig_hex_at_index(
        &self,
        new_script_sig_hex: &String,
        at_index: &usize,
    ) -> Self {
        let inputs = &self.inputs;
        // functional way to replace at index
        let new_inputs = inputs
            .into_iter()
            .enumerate()
            .map(|(index, raw_input)| {
                if index == *at_index {
                    let new_raw_input = RawInput {
                        script_sig_hex: new_script_sig_hex.to_string(),
                        ..raw_input.to_owned()
                    };
                    new_raw_input
                } else {
                    raw_input.to_owned()
                }
            })
            .collect();
        Self {
            inputs: new_inputs,
            ..self.to_owned()
        }
    }
}

fn this(public_key_hash: &String, with_length: bool) -> String {
    // get_output_script_sig_for_p2sh(&public_key_hash)
    let pub_key_length = get_byte_length_of_hex(&public_key_hash);
    // TODO: HARDCODING FOR NOW
    // let sh = format!("{}{}", length, public_key_hash.to_string());

    // TODO: Why are these the prefix and postfix for a p2pkh script?
    // let prefix = "a9";
    // let postfix = "87";
    // let a = format!("{}{}{}", prefix, sh, postfix);
    let public_key_hash_with_length = format!("{}{}", pub_key_length, public_key_hash);
    let redeem_script = format!("{}{}", "00", public_key_hash_with_length);

    //let redeem_script = get_output_script_sig_for_p2wpkh(&public_key_hash);
    let redeem_script_length = get_byte_length_of_hex(&redeem_script);

    if with_length {
        format!("{}{}", redeem_script_length, redeem_script)
    } else {
        redeem_script
    }
}
pub fn get_unsigned_segwit_transaction(transaction_to_sign: &SegwitTransaction) -> String {
    let inputs_section = transaction_to_sign
        .inputs
        .iter()
        .enumerate()
        .map(|(index, input)| {
            let raw_input = &transaction_to_sign.get_parts().inputs[index];
            if bitcoin_address::is_legacy(&input.address)
                || bitcoin_address::is_segwit_native(&input.address)
            {
                let a = format!(
                    "{}{}{}{}",
                    // TODO: extract this
                    // segwit uses little endian
                    convert_big_endian_hex_to_little_endian(
                        &raw_input.previous_transaction_hash_hex
                    ),
                    raw_input.previous_transaction_output_index_hex,
                    "00",
                    raw_input.sequence_hex
                );
                a
            } else if bitcoin_address::is_p2sh(&input.address) {
                if bitcoin_address::is_nested_segwit(&input.address) {
                    let a = format!(
                        "{}{}{}{}",
                        // TODO: extract this
                        // segwit uses little endian
                        convert_big_endian_hex_to_little_endian(
                            &raw_input.previous_transaction_hash_hex
                        ),
                        raw_input.previous_transaction_output_index_hex,
                        "00",
                        raw_input.sequence_hex,
                    );
                    a
                } else {
                    todo!();
                }
            } else if bitcoin_address::is_taproot(&input.address) {
                let a = format!(
                    "{}{}{}{}",
                    // TODO: extract this
                    // segwit uses little endian
                    convert_big_endian_hex_to_little_endian(
                        &raw_input.previous_transaction_hash_hex
                    ),
                    raw_input.previous_transaction_output_index_hex,
                    "00",
                    raw_input.sequence_hex,
                );
                a
            } else {
                todo!();
            }
        })
        .collect::<Vec<String>>()
        .join("");
    let inputs_count_hex =
        convert_decimal_to_hexadecimal(transaction_to_sign.inputs.len() as u64, false, Some(1));
    let concated_outputs = transaction_to_sign
        .get_parts()
        .outputs
        .iter()
        .map(|raw_output| {
            let script_pub_key_hex = &raw_output.script_pub_key_hex;
            format!(
                "{}{}{}",
                raw_output.amount_hex,
                get_byte_length_of_hex(&script_pub_key_hex),
                &script_pub_key_hex
            )
        })
        .collect::<Vec<String>>()
        .join("");
    let outputs_count_hex =
        convert_decimal_to_hexadecimal(transaction_to_sign.outputs.len() as u64, false, Some(1));
    let n_version_hex = transaction_to_sign.get_parts().version_hex;
    let unsigned_transaction = format!(
        "{}{}{}{}{}{}",
        n_version_hex,
        inputs_count_hex,
        inputs_section,
        outputs_count_hex,
        concated_outputs,
        transaction_to_sign.locktime
    );
    unsigned_transaction
}
fn get_final_transaction_serialization(
    transaction_to_sign: &SegwitTransaction,
    signature_scripts: SignatureScripts,
    wifs: &Wifs,
) -> String {
    println!("sig scripts: {:#?}", signature_scripts);
    let n_version_hex = transaction_to_sign.get_parts().version_hex;
    // We then have two new fields, the SegWit marker 0x00 and flag 0x01 , which allow nodes to identify this as a SegWit transaction:
    let segwit_marker = "00"; // TODO: Don't hardcode
    let flag = "01"; // TODO: Don't hardcode
    fn get_signed_transaction(
        transaction_to_sign: &SegwitTransaction,
        signature_scripts: &SignatureScripts,
        wifs: &Wifs,
    ) -> String {
        let n_version_hex = transaction_to_sign.get_parts().version_hex;
        let inputs_section = vec![0; signature_scripts.len()]
            .iter()
            .enumerate()
            .map(|(index, _)| {
                let input = &transaction_to_sign.inputs[index];
                let raw_input = &transaction_to_sign.get_parts().inputs[index];
                let public_key = get_public_key_from_wif(&wifs[&(index as u64)]);
                let public_key_hash = get_public_key_hash_from_public_key(&public_key);
                let public_key_hash_length = get_byte_length_of_hex(&public_key_hash);
                let public_key_length = get_byte_length_of_hex(&public_key);
                let public_key_with_length = format!("{}{}", public_key_length, public_key,);
                let public_key_hash_with_length =
                    format!("{}{}", public_key_hash_length, public_key_hash,);
                if bitcoin_address::is_legacy(&input.address) {
                    let signature = &signature_scripts[&(index as u64)];
                    let signature_length = get_byte_length_of_hex(signature);
                    let script_sig_with_length = format!("{}{}", signature_length, signature);
                    let signature_and_public_key =
                        format!("{}{}", script_sig_with_length, public_key_with_length);
                    let signature_and_public_key_length =
                        get_byte_length_of_hex(&signature_and_public_key);
                    let script_sig_with_length = format!(
                        "{}{}",
                        signature_and_public_key_length, signature_and_public_key
                    );
                    let a = format!(
                        "{}{}{}{}",
                        // TODO: extract this
                        // segwit uses little endian
                        convert_big_endian_hex_to_little_endian(
                            &raw_input.previous_transaction_hash_hex
                        ),
                        raw_input.previous_transaction_output_index_hex,
                        script_sig_with_length,
                        raw_input.sequence_hex
                    );
                    a
                } else if bitcoin_address::is_segwit_native(&input.address) {
                    let a = format!(
                        "{}{}{}{}",
                        // TODO: extract this
                        // segwit uses little endian
                        convert_big_endian_hex_to_little_endian(
                            &raw_input.previous_transaction_hash_hex
                        ),
                        raw_input.previous_transaction_output_index_hex,
                        "00",
                        raw_input.sequence_hex,
                    );
                    a
                } else if bitcoin_address::is_p2sh(&input.address) {
                    if bitcoin_address::is_nested_segwit(&input.address) {
                        let redeem_script = format!("{}{}", OP_0, public_key_hash_with_length);
                        let redeem_script_length = get_byte_length_of_hex(&redeem_script);
                        let script = format!("{}{}", redeem_script_length, redeem_script);
                        let script_length = get_byte_length_of_hex(&script);
                        let script_with_length = format!("{}{}", script_length, script);
                        let a = format!(
                            "{}{}{}{}",
                            // TODO: extract this
                            // segwit uses little endian
                            convert_big_endian_hex_to_little_endian(
                                &raw_input.previous_transaction_hash_hex
                            ),
                            raw_input.previous_transaction_output_index_hex,
                            script_with_length,
                            raw_input.sequence_hex,
                        );
                        a
                    } else {
                        todo!();
                    }
                } else if bitcoin_address::is_taproot(&input.address) {
                    // SHOULD THIS USE ACTUAL PUBLIC KEY INSTEAD OF TWEAKED ???
                    // let tweaked_x_only_public_key = get_tweaked_x_only_public_key_from_p2tr_address(&input.address);
                    // let tweaked_x_only_public_key_length = get_byte_length_of_hex(&tweaked_x_only_public_key);
                    // let tweaked_x_only_public_key_with_length = format!(
                    //     "{}{}",
                    //     tweaked_x_only_public_key_length, tweaked_x_only_public_key
                    // );
                    // let script_start = format!("{}", OP_1);
                    // let prefix = "00";
                    // format!("{}{}", script_start, tweaked_x_only_public_key_with_length)

                    let redeem_script = format!("{}{}", OP_1, public_key_hash_with_length);
                    let redeem_script_length = get_byte_length_of_hex(&redeem_script);
                    let script = format!("{}{}", redeem_script_length, redeem_script);
                    let script_length = get_byte_length_of_hex(&script);
                    let script_with_length = format!("{}{}", script_length, script);
                    let a = format!(
                        "{}{}{}{}",
                        // TODO: extract this
                        // segwit uses little endian
                        convert_big_endian_hex_to_little_endian(
                            &raw_input.previous_transaction_hash_hex
                        ),
                        raw_input.previous_transaction_output_index_hex,
                        "00",
                        raw_input.sequence_hex,
                    );
                    a
                    //"00".to_string()
                } else {
                    todo!();
                }
            })
            .collect::<Vec<String>>()
            .join("");
        let inputs_count_hex =
            convert_decimal_to_hexadecimal(transaction_to_sign.inputs.len() as u64, false, Some(1));
        let concated_outputs = transaction_to_sign
            .get_parts()
            .outputs
            .iter()
            .map(|raw_output| {
                let script_pub_key_hex = &raw_output.script_pub_key_hex;
                format!(
                    "{}{}{}",
                    raw_output.amount_hex,
                    get_byte_length_of_hex(&script_pub_key_hex),
                    &script_pub_key_hex
                )
            })
            .collect::<Vec<String>>()
            .join("");
        let outputs_count_hex = convert_decimal_to_hexadecimal(
            transaction_to_sign.outputs.len() as u64,
            false,
            Some(1),
        );
        let segwit_marker = "00"; // TODO: Don't hardcode
        let flag = "01"; // TODO: Don't hardcode
        let signed_transaction_before_witness_section = format!(
            "{}{}{}{}{}{}{}",
            n_version_hex,
            segwit_marker,
            flag,
            inputs_count_hex,
            inputs_section,
            outputs_count_hex,
            concated_outputs
        );
        // this is so we can loop through the hash items sorted by key
        let witness_section = vec![0; signature_scripts.len()]
            .iter()
            .enumerate()
            .map(|(index, _)| {
                let input = &transaction_to_sign.inputs[index];
                let is_input_legacy = bitcoin_address::is_legacy(&input.address);
                let raw_input = &transaction_to_sign.get_parts().inputs[index];
                let public_key = get_public_key_from_wif(&wifs[&(index as u64)]);
                let public_key_length = get_byte_length_of_hex(&public_key);
                let public_key_with_length = format!("{}{}", public_key_length, public_key,);
                if bitcoin_address::is_legacy(&input.address) {
                    "00".to_string()
                } else if bitcoin_address::is_taproot(&input.address) {
                    println!("HEREEEE");
                    let signature = &signature_scripts[&(index as u64)];
                    let signature_length = get_byte_length_of_hex(signature);
                    let script_sig_with_length = format!("{}{}", signature_length, signature);
                    // let signature_and_public_key =
                    //     format!("{}{}", script_sig_with_length, public_key_with_length);
                    // let signature_and_public_key_length =
                    //     get_byte_length_of_hex(&signature_and_public_key);
                    // let script_sig_with_length = format!(
                    //     "{}{}",
                    //     signature_and_public_key_length, signature_and_public_key
                    // );
                    let items_count_hex = convert_decimal_to_hexadecimal(1, false, Some(1));
                    format!("{}{}{}", items_count_hex, signature_length, signature)
                } else {
                    let signature = &signature_scripts[&(index as u64)];
                    let signature_length = get_byte_length_of_hex(signature);
                    let script_sig_with_length = format!("{}{}", signature_length, signature);
                    let signature_and_public_key =
                        format!("{}{}", script_sig_with_length, public_key_with_length);
                    let signature_and_public_key_length =
                        get_byte_length_of_hex(&signature_and_public_key);
                    let script_sig_with_length = format!(
                        "{}{}",
                        signature_and_public_key_length, signature_and_public_key
                    );
                    let items_count_hex = convert_decimal_to_hexadecimal(2, false, Some(1));
                    format!(
                        "{}{}{}{}{}",
                        items_count_hex, signature_length, signature, public_key_length, public_key
                    )
                }
            })
            .collect::<Vec<String>>()
            .join("");
        let signature = format!(
            "{}{}{}",
            signed_transaction_before_witness_section,
            witness_section,
            transaction_to_sign.locktime
        );
        signature
    }
    let signed_transaction_hex =
        get_signed_transaction(&transaction_to_sign, &signature_scripts, &wifs);
    signed_transaction_hex
}

pub fn sign_segwit_transaction(transaction_to_sign: &SegwitTransaction, wifs: &Wifs) -> String {
    // Source: https://medium.com/coinmonks/creating-and-signing-a-segwit-transaction-from-scratch-ec98577b526a
    let unsigned_raw_transaction = transaction_to_sign.get_parts();

    let mut signature_scripts: HashMap<u64, String> = HashMap::new();
    for (index, input) in transaction_to_sign.inputs.iter().enumerate() {
        let input_is_legacy = bitcoin_address::is_legacy(&input.address);
        if input_is_legacy {
            let signature_script = get_signiture_for_legacy_input_at_index(
                &Transaction::Segwit(transaction_to_sign.clone()),
                index,
                &wifs[&(index as u64)],
                true,
            );
            signature_scripts.insert(index as u64, signature_script);
        } else {
            let signature_script = get_segwit_sig_for_input_at_index(
                &transaction_to_sign,
                index as u64,
                &wifs[&(index as u64)],
            );
            signature_scripts.insert(index as u64, signature_script);
        }
    }

    get_final_transaction_serialization(transaction_to_sign, signature_scripts, wifs)

    //
    //
    //
}
fn get_outpoint_for_input(pay_from: &PayFrom) -> String {
    let output_index = get_prev_transaction_output_index(pay_from.vout_index);
    let previous_address = convert_big_endian_hex_to_little_endian(&pay_from.transaction);
    format!("{}{}", previous_address, output_index)
}
fn get_segwit_sig_for_input_at_index(
    transaction_to_sign: &SegwitTransaction,
    index: u64,
    wif: &String,
) -> String {
    let n_version_hex = transaction_to_sign.get_parts().version_hex;
    let prevouts = transaction_to_sign
        .inputs
        .iter()
        .map(|input| get_outpoint_for_input(&input))
        .collect::<Vec<String>>()
        .join("");
    println!("prevouts: {}", prevouts);
    let sequences = transaction_to_sign
        .get_parts()
        .inputs
        .iter()
        .map(|raw_input| raw_input.sequence_hex.clone())
        .collect::<Vec<String>>()
        .join("");
    let input_to_sign = &transaction_to_sign.inputs[index as usize];
    let is_taproot_input = bitcoin_address::is_taproot(&input_to_sign.address);
    let outpoint = get_outpoint_for_input(input_to_sign);
    let hash_outpoint = sha256_hex(&outpoint);
    let inputs_output_index = get_prev_transaction_output_index(input_to_sign.vout_index);
    let hash_prevouts = sha256_hex(&prevouts);
    let hash_sequences = sha256_hex(&sequences);

    let secp = Secp256k1::new();
    // let msg = Message::from_slice(&decode_hex(&transaction_double_sha_256).unwrap()).unwrap();

    let private_key = PrivateKey::from_wif(&wif).unwrap();
    let private_key_hex = convert_wif_to_private_key(&wif);
    let public_key = private_key.public_key(&secp);
    let public_key_hex = public_key.to_string();
    let public_key_hash = get_public_key_hash_from_public_key(&public_key_hex);
    // TODO: WHY? Source: , in P2WPKH’s case, is 1976a914 <pubkey hash> 88ac . This is the same as P2PKH’s scriptPubKey.
    // TODO This shouldn't be the same for all input types: nested_segwit, native segwit, etc
    let address_of_input = &input_to_sign.address;
    // TODO: I DONT UNDERSTAND THIS AT ALL
    let script_code = if bitcoin_address::is_nested_segwit(&address_of_input) {
        // THIS IS GOING TO BE DIFFERENT BASED ON THE VOUTS ScriptPubKey. For this example, the
        // vout script_pub_key is: OP_HASH160 <sh> OP_EQUAL, so all we have to do here is give it
        // the pub key hash and the '00' before
        // NOTE: Would be different if the vout were paying had this script key: OP_DUP OP_HASH160
        // <pkh> OP_EQUALVERIFY OP_CHECKSIG (which legacy transactions had)
        if is_script_pub_key_a_p2sh_p2wpkh(&input_to_sign.script_pub_key_hex_of_vout) {
            get_output_script_sig_for_p2pkh(public_key_hash.clone())

            // get_output_script_sig_for_p2sh(&public_key_hash)
            // let pub_key_length = get_byte_length_of_hex(&public_key_hash);
            // let public_key_hash_with_length = format!("{}{}", pub_key_length, public_key_hash);
            // let redeem_script= format!("{}{}", "00", public_key_hash_with_length);
            // redeem_script
        } else {
            todo!(
                "Not sure what to do for this script pub key of vout: {}",
                input_to_sign.script_pub_key_hex_of_vout
            );
        }
    } else if bitcoin_address::is_segwit_native(&address_of_input) {
        if is_script_pub_key_a_p2wpkh(&input_to_sign.script_pub_key_hex_of_vout) {
            // get_output_script_sig_for_p2sh(&public_key_hash)
            // let pub_key_length = get_byte_length_of_hex(&public_key_hash);
            // let public_key_hash_with_length = format!("{}{}", pub_key_length, public_key_hash);
            // let redeem_script= format!("{}{}", "00", public_key_hash_with_length);
            // redeem_script
            get_output_script_sig_for_p2pkh(public_key_hash.clone())
        } else {
            todo!(
                "Not sure what to do for this script pub key of vout: {}",
                input_to_sign.script_pub_key_hex_of_vout
            );
        }
        // get_output_script_sig_for_p2pkh(public_key_hash)
    } else if bitcoin_address::is_taproot(&address_of_input) {
        let tweaked_x_only_public_key =
            get_tweaked_x_only_public_key_from_p2tr_address(&address_of_input);
        let a = get_output_script_sig_for_p2tr(&tweaked_x_only_public_key);
        println!("script output: {}", a);
        a
    } else {
        panic!("ADDRESS TYPE NOT SUPPORTED: {}", &address_of_input);
    };
    let script_code_length = get_byte_length_of_hex(&script_code);
    let script_code_with_length = format!("{}{}", script_code_length, script_code);
    let hash_script_code = sha256_hex(&script_code_with_length);
    let amount_hex = get_output_amount(input_to_sign.vout_amount_in_sats);
    let hash_amount = sha256_hex(&amount_hex);
    let sequence = &transaction_to_sign.get_parts().inputs[index as usize].sequence_hex;
    let concated_outputs = transaction_to_sign
        .get_parts()
        .outputs
        .iter()
        .map(|raw_output| {
            let script_pub_key_hex = &raw_output.script_pub_key_hex;
            format!(
                "{}{}{}",
                raw_output.amount_hex,
                get_byte_length_of_hex(&script_pub_key_hex),
                &script_pub_key_hex
            )
        })
        .collect::<Vec<String>>()
        .join("");
    println!("concated_outputs: {}", concated_outputs);
    let hash_concated_outputs = sha256_hex(&concated_outputs);
    let locktime = &transaction_to_sign.locktime;
    let sighash_all = 1;
    let sighash_all_default = 0;
    let sighash_type = sighash_all_default;
    let ext_flag = convert_decimal_to_hexadecimal(sighash_type, false, Some(1));
    // let spend_type = convert_decimal_to_hexadecimal(sighash_type * 2, false, Some(1));
    let spend_type = "00";
    let sighash_type_hex_of_1_bytes = convert_decimal_to_hexadecimal(sighash_type, false, Some(1));
    let sighash_type_hex_in_little_endian =
        convert_big_endian_hex_to_little_endian(&sighash_type_hex_of_1_bytes);
    let txout = format!("{}{}", amount_hex, script_code);
    let hash_txout = sha256_hex(&txout);
    let input_script_pub_key_length =
        get_byte_length_of_hex(&input_to_sign.script_pub_key_hex_of_vout);
    println!("input to sign: {:#?}", input_to_sign);
    let input_script_code_with_length = format!(
        "{}{}",
        input_script_pub_key_length, input_to_sign.script_pub_key_hex_of_vout
    );
    let hash_input_script_pub_key = sha256_hex(&input_script_code_with_length);
    println!("HERE!!! {}", input_script_code_with_length);

    println!("amount: {}", amount_hex);
    let sighash_all_preimage = format!(
        "{}{}{}{}{}{}{}{}{}{}{}",
        "00", // epoch
        sighash_type_hex_in_little_endian,
        n_version_hex,
        locktime,
        hash_prevouts,
        hash_amount, // should this be little endian? big endian?
        // are tehse two in the right order?
        hash_sequences, // should this be little endian? big endian?
        //
        //
        hash_concated_outputs, // I feel like this is wrong
        //
        //
        //
        //
        spend_type,
        // script_code_with_length,
        input_script_code_with_length,
        inputs_output_index,
        // sequence,
        // script_code,
        // outpoint,
        // hash_prevouts,
    );
    println!("-----------------------------");
    println!("{}", "00");
    println!("{}", sighash_type_hex_in_little_endian);
    println!("{}", n_version_hex);
    println!("{}", locktime);
    println!("{}", hash_outpoint);
    println!("{}", hash_amount);
    println!("{}", hash_input_script_pub_key);
    println!("{}", hash_sequences);
    println!("{}", hash_concated_outputs);
    println!("{}", spend_type);
    println!("{}", inputs_output_index);
    println!("-----------------------------");
    println!("sigmsg preimage {}", sighash_all_preimage);
    let serialized_signature =
        double_sha256_and_sign_hex(&sighash_all_preimage, &wif, is_taproot_input);

    //         // TODO: REMOVE!!
    //         if bitcoin_address::is_segwit_native(&input_to_sign.address) {
    //             let sighash_all_preimage_from_article = "0200000099197e88ff743aff3e453e3a7b745abd31937ccbd56f96a179266eba786833e682a7d5bb59fc957ff7f737ca0b8be713c705d6173783ad5edb067819bed70be89cb872539fbe1bc0b9c5562195095f3f35e6e13919259956c6263c9bd53b20b7010000001976a914594c2e3da92d1904f7e7c856220f8cae5efb556488ac5424000000000000fffffffff3ae23c3fd63a2e0479888f95c7a8ab221b20add6ac819e9d8953edd1a0cd9240000000001000000";
    //         assert_eq!(sighash_all_preimage, sighash_all_preimage_from_article);
    //         } else if bitcoin_address::is_nested_segwit(&input_to_sign.address) {
    //             let sighash_all_preimage_from_article = "0200000099197e88ff743aff3e453e3a7b745abd31937ccbd56f96a179266eba786833e682a7d5bb59fc957ff7f737ca0b8be713c705d6173783ad5edb067819bed70be88012f1ec8aa9a63cf8b200c25ddae2dece42a2495cc473c1758972cfcd84d904010000001976a9146a721dcca372f3c17b2c649b2ba61aa0fda98a9188ac1199f40000000000fffffffff3ae23c3fd63a2e0479888f95c7a8ab221b20add6ac819e9d8953edd1a0cd9240000000001000000";
    //             assert_eq!(sighash_all_preimage, sighash_all_preimage_from_article);
    //         } else {
    //             todo!()
    //         }
    //     let serialized_signature = if bitcoin_address::is_segwit_native(&input_to_sign.address) {
    //         "3045022100f8dac321b0429798df2952d086e763dd5b374d031c7f400d92370ae3c5f57afd0220531207b28b1b137573941c7b3cf5384a3658ef5fc238d26150d8f75b2bcc61e7".to_string()
    //     } else {
    //         // put other here
    //         "304402204ebf033caf3a1a210623e98b49acb41db2220c531843106d5c50736b144b15aa02201a006be1ebc2ffef0927d4458e3bb5e41e5abc7e44fc5ceb920049b46f879711".to_string()
    //     };
    //

    // this should be calculated
    let sighash_type_to_append_to_signature_hex = ext_flag;
    let signature_with_sighash_type_appended = format!(
        "{}{}",
        serialized_signature, sighash_type_to_append_to_signature_hex
    );
    // let signature_with_sighash_type_appended_length = get_byte_length_of_hex(&signature_with_sighash_type_appended);
    //return signature_with_sighash_type_appended;
    println!("SIGGGGG: {}", signature_with_sighash_type_appended);
    // return signature_with_sighash_type_appended;
    return serialized_signature;
    // let public_key_length = get_byte_length_of_hex(&public_key_hex);
    // let signature_script = format!(
    //     "{}{}{}{}{}",
    //     "02", // TODO: This shouldn't be hardcoded! This is two because The number of items is
    //     // two: signature & public key.
    //     signature_with_sighash_type_appended_length,
    //     signature_with_sighash_type_appended,
    //     public_key_length,
    //     public_key_hex
    // );
    // signature_script
}

fn double_sha256_and_sign_hex(
    hex_msg_to_hash_and_sign: &String,
    wif: &String,
    should_use_schnorr: bool,
) -> String {
    // ----------------------------------------
    // from : https://bitcoin.stackexchange.com/questions/114116/how-do-you-commit-to-the-previous-outputs-amount-when-signing-a-segwit-input-wi
    let previous_output = OutPoint::new(
        Txid::from_hex("befc73ebe1a50bbdef00fe745a4ead713d11e6d6caf50a86e7c627676daab07c").unwrap(),
        0,
    );
    let tx_input = TxIn {
        previous_output,
        script_sig: Default::default(),
        sequence: bitcoin::Sequence(0xffffffff),
        witness: Default::default(),
    };

    let s = "51205b9bbd7e213e7294fe3750b7435a0608bb9d96984300695f9038fdff197b6622";
    let tx_output = TxOut {
        value: 29078,
        script_pubkey: Script::from_hex(s).unwrap(), // don't worry about this
    };

    let mut transaction = BitcoinLibTransaction {
        version: 2,
        lock_time: bitcoin::PackedLockTime(0),
        input: vec![tx_input],
        output: vec![tx_output],
    };
    let ser_t = transaction.serialize();
    println!("ser_t: {:#?}", transaction);

    let previous_output_as_tx_out = TxOut {
        value: 29678,
        script_pubkey: Script::from_hex(
            "5120114d89595f72379898785357cbeb3f7a5c0900780ce374d1a4bd72c1d4868a1f",
        )
        .unwrap(),
    };
    let prevouts = vec![previous_output_as_tx_out];

    let mut sighash_cache = bitcoin::util::sighash::SighashCache::new(&transaction);
    println!("sighash_cache: {:#?}", sighash_cache);
    let input_index = 0;

    // taproot_key_spend_signature_hash is the crucial part
    let signature_hash = sighash_cache
        .taproot_key_spend_signature_hash(
            input_index,
            &Prevouts::All(&prevouts),
            bitcoin::SchnorrSighashType::Default,
        )
        .unwrap();
    println!("sig hash from bitcoin library: {}", signature_hash);
    let msg = Message::from_slice(&signature_hash.to_vec()).unwrap();
    println!("bitcoin lib msg as vec: {:#?}", signature_hash.to_vec());
    // ------------------------------------------
    let a = format!(
        "{}{}{}{}{}{}{}{}{}{}{}",
        "00",
        "00",
        "02000000",
        "00000000",
        "e186179664b38e58723ba1ac8d5915f97023f6afc2f2be94459fe9868cf953eb",
        "646b3ee05dcdae994f2d99d94a878d1ad40c3f4b536b76a6a730b4e28b29c385",
        "e00e0a53937928e143c165df361096d6f607d8fe35aa63f4adfe2e73b56cd324",
        "ad95131bc0b799c0b1af477fb14fcf26a6a9f76079e48bf090acb7e8367bfd0e",
        "5ac2b429009184588bf78341f4692a02303a6a3110c2f1a914f3dba9cea091cb",
        "00",
        "00000000"
    );
    println!("a: {}", a);
    let b = sha256_non_hex("TapSighash");
    println!("b: {}", b);
    let c = format!("{}{}{}", b, b, hex_msg_to_hash_and_sign);
    let d = sha256_hex(&c);
    println!("d: {}", d);
    // let transaction_double_sha_256 = double_sha256_hex(hex_msg_to_hash_and_sign);
    let transaction_double_sha_256 = d;
    println!("sighash: {}", transaction_double_sha_256);

    // let transaction_double_sha_256 = sha256_hex(hex_msg_to_hash_and_sign);
    let msg = Message::from_slice(&decode_hex(&transaction_double_sha_256).unwrap()).unwrap();
    println!("msg as bytes: {:#?}", transaction_double_sha_256.as_bytes());
    println!(
        "msg as decoded hex: {:#?}",
        decode_hex(&transaction_double_sha_256).unwrap()
    );
    // https://docs.rs/secp256k1/latest/secp256k1/
    // let msg = Message::from_hashed_data::<sha256::Hash>(msg.as_bytes());
    // println!("newest one {}", msg.to_string());

    // let transaction_double_sha_256 = sha256::Hash::hash(sighash_all_preimage.as_bytes());
    // println!("PREIMAGE DOUBLE NEW WAY!! {}", transaction_double_sha_256);
    // let transaction_double_sha_256 = double_sha256(&sighash_all_preimage);
    // println!("PREIMAGE DOUBLE SHA!! {}", transaction_double_sha_256);

    let secp = Secp256k1::new();
    // let msg = Message::from_slice(&decode_hex(&transaction_double_sha_256).unwrap()).unwrap();

    // TRY THIS:
    // let msg = sha256::Hash::hash(msg);
    // let msg = Message::from_slice(&msg)?;
    // let seckey = SecretKey::from_slice(&seckey)?;
    // Ok(secp.sign_ecdsa(&msg, &seckey))

    let private_key = PrivateKey::from_wif(&wif).unwrap();
    let private_key_hex = convert_wif_to_private_key(&wif);
    let public_key = private_key.public_key(&secp);
    let public_key_hex = public_key.to_string();

    let secret_key = SecretKey::from_str(&private_key_hex).unwrap();
    let pk = PublicKey::from_secret_key(&secp, &secret_key);
    let serialized_signature = if should_use_schnorr {
        // NEW ---------------------------
        println!("USING SCHNORR");
        let kp = KeyPair::from_secret_key(&secp, &secret_key);
        let tweaked_kp = kp.tap_tweak(&secp, None).into_inner();
        let (x_only_public_key, parity) = tweaked_kp.x_only_public_key();
        println!("their x only pk: {}", x_only_public_key);

        let b = get_p2tr_address_from_pubkey(&public_key_hex, bitcoin_utils::Network::Testnet);
        println!("addr: {}", b);
        let a = get_tweaked_x_only_public_key_from_p2tr_address(
            &"tb1p0h4zu3vdatdd6a94hx7n7unp2rqvspe6uwtwauypchzut95przpqttpumv".to_string(),
        );
        println!("my tweak: {}", a);

        let schnorr_sig = secp.sign_schnorr(&msg, &tweaked_kp);
        let taproot_serialized_signature = schnorr_sig.to_string();
        let b = SchnorrSig::from_slice(&decode_hex(&taproot_serialized_signature).unwrap());
        println!("YOOOOOOOOOOOOOOO: {:#?}", b);
        println!("TR serialized signature: {}", taproot_serialized_signature);
        assert!(secp
            .verify_schnorr(&schnorr_sig, &msg, &x_only_public_key)
            .is_ok());
        println!("IS THIS IS?? {}", taproot_serialized_signature);
        taproot_serialized_signature
    // END NEW ---------------------------
    } else {
        println!("NOT USING SCHNORR");
        // OLD ---------------------------
        let sig = secp.sign_ecdsa(&msg, &secret_key);
        let serialized_signature = sig.serialize_der();
        println!("ECDSA serialized signature: {}", serialized_signature);
        assert!(secp.verify_ecdsa(&msg, &sig, &pk).is_ok());
        serialized_signature.to_string()
        // END OLD ---------------------------
    };
    transaction.input[input_index].witness =
        Witness::from_vec(vec![decode_hex(&serialized_signature).unwrap()]);
    println!("ser_t_after: {:#?}", transaction);
    println!("meow: {:#?}", encode_hex(&transaction.serialize()));
    println!("FROM BITCOIN LIB: {}", msg);
    // return "3dfebf3e073dc0207ff67666695c5ea82e9e5f5bd880ab74bf4f65c511f82f6318feb78400c89313534ddb6591e44f85e4c27d7e81f2078954a6efaa46448de5".to_string();
    serialized_signature
}
fn get_signiture_for_legacy_input_at_index(
    transaction_to_sign: &Transaction,
    input_index_to_sign: usize,
    wif: &String,
    should_address_be_in_little_endian: bool,
) -> String {
    let vout_index_to_sign = input_index_to_sign;
    let vout = match &transaction_to_sign {
        Transaction::Legacy(p2pkh_transaction) => &p2pkh_transaction.inputs[vout_index_to_sign],
        Transaction::Segwit(v2_transaction) => &v2_transaction.inputs[vout_index_to_sign],
    };
    let script_pub_key_of_spending_vout = &vout.script_pub_key_hex_of_vout;
    let unsigned_raw_transaction_with_pub_key_of_spending_vout = match &transaction_to_sign {
        Transaction::Legacy(p2pkh_transaction) => p2pkh_transaction
            .get_parts()
            .clone()
            .replace_script_sig_hex_at_index(&script_pub_key_of_spending_vout, &vout_index_to_sign),
        Transaction::Segwit(v2_transaction) => v2_transaction
            .get_parts()
            .clone()
            .replace_script_sig_hex_at_index(&script_pub_key_of_spending_vout, &vout_index_to_sign),
    };
    let unsigned_raw_transaction_hex_with_script_pub_key_inserted =
        unsigned_raw_transaction_with_pub_key_of_spending_vout.get_raw_string(
            true,
            true,
            should_address_be_in_little_endian,
        );

    // append sighash_all
    // Before signing, the transaction has a hash type constant temporarily appended. For a regular transaction, this is SIGHASH_ALL (0x00000001). After signing, this hash type is removed from the end of the transaction and appended to the scriptSig.
    let sighash_all = 1;
    let sighash_type = sighash_all;
    let sighash_type_hex_of_4_bytes = convert_decimal_to_hexadecimal(sighash_type, false, Some(4));
    let sighash_type_hex_in_little_endian =
        convert_big_endian_hex_to_little_endian(&sighash_type_hex_of_4_bytes);

    let sighash_all_preimage = format!(
        "{}{}",
        unsigned_raw_transaction_hex_with_script_pub_key_inserted,
        sighash_type_hex_in_little_endian
    );

    let public_key_hex = get_public_key_from_wif(&wif);

    let serialized_signature = double_sha256_and_sign_hex(&sighash_all_preimage, &wif, false);

    // REMOVE THIS!
    //     let serialized_signature_from_article = "304402200da2c4d8f2f44a8154fe127fe5bbe93be492aa589870fe77eb537681bc29c8ec02201eee7504e37db2ef27fa29afda46b6c331cd1a651bb6fa5fd85dcf51ac01567a";
    //     let serialized_signature = serialized_signature_from_article;
    //     let sighash_all_preimage_from_article = "0200000003ed204affc7519dfce341db0569687569d12b1520a91a9824531c038ad62aa9d1010000001976a914b780d54c6b03b053916333b50a213d566bbedd1388acffffffff9cb872539fbe1bc0b9c5562195095f3f35e6e13919259956c6263c9bd53b20b70100000000ffffffff8012f1ec8aa9a63cf8b200c25ddae2dece42a2495cc473c1758972cfcd84d9040100000000ffffffff01b580f50000000000160014cb61ee4568082cb59ac26bb96ec8fbe0109a4c000000000001000000";
    //     println!("PREIMAGE OR LEGACY!! {}", sighash_all_preimage);
    //     assert_eq!(sighash_all_preimage, sighash_all_preimage_from_article);
    //
    //     println!("serialized sig from article: {}", serialized_signature);
    //     println!();
    // this should be calculated
    let sighash_type_hex_of_1_byte = convert_decimal_to_hexadecimal(sighash_type, false, Some(1));
    let sighash_type_to_append_to_signature_hex = sighash_type_hex_of_1_byte;
    let signature_with_sighash_type_appended = format!(
        "{}{}",
        serialized_signature, sighash_type_to_append_to_signature_hex
    );

    // let signature_with_sighash_type_appended_length = get_byte_length_of_hex(&signature_with_sighash_type_appended);
    // let public_key_length = get_byte_length_of_hex(&public_key_hex);
    // let signature_script = format!(
    //     "{}{}{}{}",
    //     signature_with_sighash_type_appended_length,
    //     signature_with_sighash_type_appended,
    //     public_key_length,
    //     public_key_hex
    // );
    let signature_script = format!("{}", signature_with_sighash_type_appended,);
    signature_script
}

fn create_p2pkh_script_pub_key_hex_from_pub_key_hash(pub_key_hash: &String) -> String {
    // TODO: Why are these the prefix and postfix for a p2pkh script?

    let pub_key_hash_length = get_byte_length_of_hex(pub_key_hash);
    let pub_key_hash_with_length = format!("{}{}", pub_key_hash_length, pub_key_hash);
    let script_start = format!("{}{}", OP_DUP, OP_HASH160);
    let script_end = format!("{}{}", OP_EQUALVERIFY, OP_CHECKSIG);
    format!("{}{}{}", script_start, pub_key_hash_with_length, script_end)
}
fn create_p2sh_script_pub_key_hex_from_sh(sh: &String) -> String {
    // TODO: Why are these the prefix and postfix for a p2pkh script?
    let script_start = format!("{}", OP_HASH160);
    let script_end = format!("{}", OP_EQUAL);
    format!("{}{}{}", script_start, sh, script_end)
}
fn create_p2wpkh_script_pub_key_hex_from_pub_key_hash(pub_key_hash: &String) -> String {
    // TODO: Why are these the prefix and postfix for a p2pkh script?
    let pub_key_hash_length = get_byte_length_of_hex(pub_key_hash);
    let pub_key_hash_with_length = format!("{}{}", pub_key_hash_length, pub_key_hash);
    let script_start = format!("{}", OP_0);
    let prefix = "00";
    format!("{}{}", script_start, pub_key_hash_with_length)
}
fn create_p2tr_script_pub_key_hex_from_tweaked_x_only_public_key(
    tweaked_x_only_public_key: &String,
) -> String {
    // TODO: Why are these the prefix and postfix for a p2pkh script?
    let tweaked_x_only_public_key_length = get_byte_length_of_hex(&tweaked_x_only_public_key);
    let tweaked_x_only_public_key_with_length = format!(
        "{}{}",
        tweaked_x_only_public_key_length, tweaked_x_only_public_key
    );
    let script_start = format!("{}", OP_1);
    let prefix = "00";
    format!("{}{}", script_start, tweaked_x_only_public_key_with_length)
}

// let sighash_components = bip143::SighashComponents::new(&unsigned_tx);

fn get_script_language(script_hex: &String) -> String {
    let script_hex_bytes = decode_hex(script_hex).unwrap();
    let s = Script::from(script_hex_bytes);
    s.asm()
}

// fn sign_with_pubkey_hash(pub_key_hash: &String, wif: &String) -> () {
//     let sig_hash = raw_tx.signature_hash(
//         0,
//         &Script::from(decode("76a9145477d7bfe9bdf17cea9f5b2ecacc7a2577723c7488ac").unwrap()),
//         1,
//     );
//
//     let secp = Secp256k1::new();
//     let msg = Message::from_slice(&sig_hash.into_inner()).unwrap();
//     let sk = PrivateKey::from_wif(wif).unwrap();
//     let pk = sk.public_key(&secp);
//     let mut sig = secp.sign(&msg, &sk.key).serialize_der();
//     sig.push(1); // sign hash type
//
//     let builder1 = Builder::new().push_slice(&sig).push_key(&pk);
// }
// Todos
// - Have a function that returns the parts of the transaction (before signing)
// - Create a function that takes the above transaction, (adds the scriptsig that's equal to the
// script pub key of the vout you're spending), signs it, and returns the parts of the new
//   signed transaction.
// - Split transaction into 2 types: unsigned transaction and signed transaction
//
// How to sign resources:
// - https://github.com/rust-bitcoin/rust-bitcoin/issues/294
// // How to sign p2pkh: https://github.com/rust-bitcoin/rust-bitcoin/issues/294#issuecomment-514599128
// // How to sign with witness: https://github.com/Blockstream/gdk_rpc/blob/9dec80995c170d7fcd5a2aa875609b2e118f9cbc/src/wallet.rs#L361
//
//
//
// expected signed transaction:
// 0100000001a3e28754552da9302821c447986e7796ee6e4f334431682481173bae06272a46000000006a473044022069efc533490c46baf1a82457a01ccf567f80ad473e0ca3d73768140b5d733690022031a05a47a547ea37842f241280ba17fe0494ec3b6934708f329785fd7c5c5187012102cc65acf65de73f023eeb43d15f5203dc39556ccff1d261ba0ec6530f14b86ec2fdffffff0207150000000000001976a9146502c6cd7a86d27306352fdc0d15aa480549e96388ace8030000000000001976a914fe8c68f718a4fa75279f98bf79fae75ed779ae2488ac00000000
fn testing() {
    let secp = Secp256k1::new();
    let alice_secret =
        SecretKey::from_str("2bd806c97f0e00af1a1fc3328fa763a9269723c8db8fac4f93af71db186d6e90")
            .unwrap();
    let bob_secret =
        SecretKey::from_str("cW9GJyGDR5k6hAwwskMt4pCCvMV9h7ahd4BTVvTWCqc5YyFHRSRv").unwrap();
    let internal_secret =
        SecretKey::from_str("1229101a0fcf2104e8808dab35661134aa5903867d44deb73ce1c7e4eb925be8")
            .unwrap();

    let alice = KeyPair::from_secret_key(&secp, &alice_secret);
    let bob = KeyPair::from_secret_key(&secp, &bob_secret);
    let internal = KeyPair::from_secret_key(&secp, &internal_secret);
    let preimage =
        Vec::from_hex("107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f").unwrap();

    let preimage_hash = bitcoin::hashes::sha256::Hash::hash(&preimage);

    println!("alice public key {}", alice.public_key());
    println!("bob public key {}", bob.public_key());
    println!("internal public key {}", internal.public_key());

    println!("preimage {}", preimage_hash.to_string());

    let alice_script = Script::from_hex(
        "029000b275209997a497d964fc1a62885b05a51166a65a90df00492c8d7cf61d6accf54803beac",
    )
    .unwrap();

    let bob_x_only_public_key = &bob.x_only_public_key().0;
    let bob_script = Builder::new()
        .push_opcode(all::OP_SHA256)
        .push_slice(&preimage_hash)
        .push_opcode(all::OP_EQUALVERIFY)
        .push_x_only_key(bob_x_only_public_key)
        .push_opcode(all::OP_CHECKSIG)
        .into_script();

    let builder =
        TaprootBuilder::with_huffman_tree(vec![(1, bob_script.clone()), (1, alice_script.clone())])
            .unwrap();

    let tap_tree = TapTree::from_builder(builder).unwrap();

    let tap_info = tap_tree
        .into_builder()
        .finalize(&secp, *bob_x_only_public_key)
        .unwrap();

    let merkle_root = tap_info.merkle_root();
    let tweak_key_pair = internal.tap_tweak(&secp, merkle_root).into_inner();

    let address = Address::p2tr(
        &secp,
        tap_info.internal_key(),
        tap_info.merkle_root(),
        bitcoin::Network::Testnet,
    );
    // -------------------------------
    let input_index = 0;
    let previous_output = OutPoint::new(
        Txid::from_hex("befc73ebe1a50bbdef00fe745a4ead713d11e6d6caf50a86e7c627676daab07c").unwrap(),
        input_index,
    );
    let tx_input = TxIn {
        previous_output,
        script_sig: Default::default(),
        sequence: bitcoin::Sequence(0xffffffff),
        witness: Default::default(),
    };

    let s = "51205b9bbd7e213e7294fe3750b7435a0608bb9d96984300695f9038fdff197b6622";
    let tx_output = TxOut {
        value: 29078,
        script_pubkey: Script::from_hex(s).unwrap(), // don't worry about this
    };

    let mut tx = BitcoinLibTransaction {
        version: 2,
        lock_time: bitcoin::PackedLockTime(0),
        input: vec![tx_input.clone()],
        output: vec![tx_output],
    };
    let ser_t = tx.serialize();
    println!("ser_t: {:#?}", tx);

    let previous_output_as_tx_out = TxOut {
        value: 29678,
        script_pubkey: Script::from_hex(
            "5120114d89595f72379898785357cbeb3f7a5c0900780ce374d1a4bd72c1d4868a1f",
        )
        .unwrap(),
    };
    let prevouts = vec![previous_output_as_tx_out.clone()];

    // -----------------

    let vec_tx_in = vec![tx_input.clone()];

    let prevouts = Prevouts::One(input_index as usize, previous_output_as_tx_out.clone());

    let sighash_sig = SighashCache::new(&mut tx.clone())
        .taproot_script_spend_signature_hash(
            0,
            &prevouts,
            ScriptPath::with_defaults(&bob_script),
            SchnorrSighashType::AllPlusAnyoneCanPay,
        )
        .unwrap();

    let key_sig = SighashCache::new(&mut tx.clone())
        .taproot_key_spend_signature_hash(0, &prevouts, SchnorrSighashType::AllPlusAnyoneCanPay)
        .unwrap();

    println!("key signing sighash {} ", key_sig);

    println!("script sighash {} ", sighash_sig);

    let sig = secp.sign_schnorr(&Message::from_slice(&sighash_sig).unwrap(), &bob);

    let actual_control = tap_info
        .control_block(&(bob_script.clone(), LeafVersion::TapScript))
        .unwrap();

    let res = actual_control.verify_taproot_commitment(
        &secp,
        tweak_key_pair.x_only_public_key().0,
        &bob_script,
    );

    println!("is taproot committed? {} ", res);

    // println!("control block {} ", actual_control.serialize().to_hex());

    let schnorr_sig = SchnorrSig {
        sig,
        hash_ty: SchnorrSighashType::Default,
    };

    let wit = Witness::from_vec(vec![
        schnorr_sig.to_vec(),
        preimage.clone(),
        bob_script.to_bytes(),
        actual_control.serialize(),
    ]);

    tx.input[0].witness = wit;

    println!("Address: {} ", address.to_string());

    // // this part fails fix me plz !!!
    // let tx_id = client.transaction_broadcast(&tx).unwrap();
    // println!("transaction hash: {}", tx_id.to_string());

    // // sig
    // println!("signature {:#?}", sig.to_hex());
    // println!("Input preimage {}", preimage.to_hex());
    // println!("script {}", bob_script.to_hex());
    // println!("control block {:#?}", actual_control.serialize().to_hex());
}
