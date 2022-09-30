use std::{collections::HashMap, str::FromStr};

use bitcoin::{
    secp256k1::{Message, PublicKey, Secp256k1, SecretKey},
    PrivateKey, Script,
};
use bitcoin_script_opcodes::{OP_0, OP_EQUAL, OP_HASH160};
use bitcoin_utils::{
    convert_wif_to_private_key, double_sha256_hex, get_public_key_from_wif,
    get_public_key_hash_from_address, get_public_key_hash_from_public_key,
    get_script_hash_from_p2sh_address, get_tweaked_x_only_public_key_from_p2tr_address,
};
use hex_utilities::{
    convert_big_endian_hex_to_little_endian, convert_decimal_to_hexadecimal, decode_hex,
};

use crate::utils::{
    get_disabled_locktime_value, get_input_count, get_input_script_sig_length, get_output_amount,
    get_output_count, get_output_script_length, get_output_script_sig_for_p2pkh,
    get_output_script_sig_for_p2sh, get_output_script_sig_for_p2tr,
    get_output_script_sig_for_p2wpkh, get_prev_transaction_hash, get_prev_transaction_output_index,
    get_sequence, get_version_hex_le,
};
use crate::{
    types::{PayFrom, PayTo, Wifs},
    utils::get_byte_length_of_hex,
};
type SignatureScripts = HashMap<u64, String>;

enum Transaction {
    Legacy(LegacyTransaction),
    Segwit(SegwitTransaction),
}

#[derive(Debug, Clone)]
pub struct SegwitTransaction {
    pub version: u8,
    pub inputs: Vec<PayFrom>,
    pub outputs: Vec<PayTo>,
    pub locktime: String,
}

impl SegwitTransaction {
    pub fn new(inputs: Vec<PayFrom>, outputs: Vec<PayTo>, version: u8) -> Self {
        SegwitTransaction {
            version,
            inputs,
            outputs,
            locktime: get_disabled_locktime_value(),
        }
    }

    pub fn get_parts(&self) -> LegacyRawTransaction {
        LegacyRawTransaction {
            version_hex: get_version_hex_le(self.version),
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
                        sequence_hex: get_sequence(true),
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
            version_hex: get_version_hex_le(self.version),
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
                        sequence_hex: get_sequence(true),
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
                    let is_p2sh_address = bitcoin_address::is_p2sh(address);
                    let is_p2wpkh_address = bitcoin_address::is_segwit_native(address);
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
            .iter()
            .enumerate()
            .map(|(index, raw_input)| {
                if index == *at_index {
                    RawInput {
                        script_sig_hex: new_script_sig_hex.to_string(),
                        ..raw_input.to_owned()
                    }
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
                format!(
                    "{}{}{}{}",
                    // TODO: extract this
                    // segwit uses little endian
                    convert_big_endian_hex_to_little_endian(
                        &raw_input.previous_transaction_hash_hex
                    ),
                    raw_input.previous_transaction_output_index_hex,
                    "00",
                    raw_input.sequence_hex,
                )
            } else if bitcoin_address::is_p2sh(&input.address) {
                if bitcoin_address::is_nested_segwit(&input.address) {
                    let redeem_script = format!("{}{}", OP_0, public_key_hash_with_length);
                    let redeem_script_length = get_byte_length_of_hex(&redeem_script);
                    let script = format!("{}{}", redeem_script_length, redeem_script);
                    let script_length = get_byte_length_of_hex(&script);
                    let script_with_length = format!("{}{}", script_length, script);
                    format!(
                        "{}{}{}{}",
                        // TODO: extract this
                        // segwit uses little endian
                        convert_big_endian_hex_to_little_endian(
                            &raw_input.previous_transaction_hash_hex
                        ),
                        raw_input.previous_transaction_output_index_hex,
                        script_with_length,
                        raw_input.sequence_hex,
                    )
                } else {
                    todo!();
                }
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
                get_byte_length_of_hex(script_pub_key_hex),
                &script_pub_key_hex
            )
        })
        .collect::<Vec<String>>()
        .join("");
    let outputs_count_hex =
        convert_decimal_to_hexadecimal(transaction_to_sign.outputs.len() as u64, false, Some(1));
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
            let public_key = get_public_key_from_wif(&wifs[&(index as u64)]);
            let public_key_length = get_byte_length_of_hex(&public_key);
            if is_input_legacy {
                "00".to_string()
            } else {
                let signature = &signature_scripts[&(index as u64)];
                let signature_length = get_byte_length_of_hex(signature);
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
        signed_transaction_before_witness_section, witness_section, transaction_to_sign.locktime
    );
    signature
}

fn get_final_transaction_serialization(
    transaction_to_sign: &SegwitTransaction,
    signature_scripts: SignatureScripts,
    wifs: &Wifs,
) -> String {
    // We then have two new fields, the SegWit marker 0x00 and flag 0x01 , which allow nodes to identify this as a SegWit transaction:
    get_signed_transaction(transaction_to_sign, &signature_scripts, wifs)
}

pub fn sign_segwit_transaction(transaction_to_sign: &SegwitTransaction, wifs: &Wifs) -> String {
    // Source: https://medium.com/coinmonks/creating-and-signing-a-segwit-transaction-from-scratch-ec98577b526a
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
                transaction_to_sign,
                index as u64,
                &wifs[&(index as u64)],
            );
            signature_scripts.insert(index as u64, signature_script);
        }
    }

    get_final_transaction_serialization(transaction_to_sign, signature_scripts, wifs)
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
        .map(|input| get_outpoint_for_input(input))
        .collect::<Vec<String>>()
        .join("");
    let sequences = transaction_to_sign
        .get_parts()
        .inputs
        .iter()
        .map(|raw_input| raw_input.sequence_hex.clone())
        .collect::<Vec<String>>()
        .join("");
    let input_to_sign = &transaction_to_sign.inputs[index as usize];
    let outpoint = get_outpoint_for_input(input_to_sign);
    let hash_prevouts = double_sha256_hex(&prevouts);
    let hash_sequences = double_sha256_hex(&sequences);

    let secp = Secp256k1::new();
    // let msg = Message::from_slice(&decode_hex(&transaction_double_sha_256).unwrap()).unwrap();

    let private_key = PrivateKey::from_wif(wif).unwrap();
    let public_key = private_key.public_key(&secp);
    let public_key_hex = public_key.to_string();
    let public_key_hash = get_public_key_hash_from_public_key(&public_key_hex);
    let address_of_input = &input_to_sign.address;
    let script_code = if bitcoin_address::is_nested_segwit(address_of_input) {
        if is_script_pub_key_a_p2sh_p2wpkh(&input_to_sign.script_pub_key_hex_of_vout) {
            get_output_script_sig_for_p2pkh(public_key_hash)
        } else {
            todo!(
                "Not sure what to do for this script pub key of vout: {}",
                input_to_sign.script_pub_key_hex_of_vout
            );
        }
    } else if bitcoin_address::is_segwit_native(address_of_input) {
        if is_script_pub_key_a_p2wpkh(&input_to_sign.script_pub_key_hex_of_vout) {
            get_output_script_sig_for_p2pkh(public_key_hash)
        } else {
            todo!(
                "Not sure what to do for this script pub key of vout: {}",
                input_to_sign.script_pub_key_hex_of_vout
            );
        }
        // get_output_script_sig_for_p2pkh(public_key_hash)
    } else {
        panic!("ADDRESS TYPE NOT SUPPORTED: {}", &address_of_input);
    };
    let script_code_length = get_byte_length_of_hex(&script_code);
    let script_code_with_length = format!("{}{}", script_code_length, script_code);
    let amount_hex = get_output_amount(input_to_sign.vout_amount_in_sats);
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
                get_byte_length_of_hex(script_pub_key_hex),
                &script_pub_key_hex
            )
        })
        .collect::<Vec<String>>()
        .join("");
    let hash_concated_outputs = double_sha256_hex(&concated_outputs);
    let locktime = &transaction_to_sign.locktime;
    let sighash_all = 1;
    let sighash_type = sighash_all;
    let sighash_type_hex_of_4_bytes = convert_decimal_to_hexadecimal(sighash_type, false, Some(4));
    let sighash_type_hex_in_little_endian =
        convert_big_endian_hex_to_little_endian(&sighash_type_hex_of_4_bytes);

    let sighash_all_preimage = format!(
        "{}{}{}{}{}{}{}{}{}{}",
        n_version_hex,
        hash_prevouts,
        hash_sequences,
        outpoint,
        script_code_with_length,
        amount_hex,
        sequence,
        hash_concated_outputs,
        locktime,
        sighash_type_hex_in_little_endian
    );
    let serialized_signature = double_sha256_and_sign_hex(&sighash_all_preimage, wif);
    let sighash_type_hex_of_1_byte = convert_decimal_to_hexadecimal(sighash_type, false, Some(1));
    let sighash_type_to_append_to_signature_hex = sighash_type_hex_of_1_byte;
    format!(
        "{}{}",
        serialized_signature, sighash_type_to_append_to_signature_hex
    )
}

fn double_sha256_and_sign_hex(hex_msg_to_hash_and_sign: &String, wif: &String) -> String {
    let transaction_double_sha_256 = double_sha256_hex(hex_msg_to_hash_and_sign);
    let msg = Message::from_slice(&decode_hex(&transaction_double_sha_256).unwrap()).unwrap();
    let secp = Secp256k1::new();
    let private_key_hex = convert_wif_to_private_key(wif);
    let secret_key = SecretKey::from_str(&private_key_hex).unwrap();
    let sig = secp.sign_ecdsa(&msg, &secret_key);
    let serialized_signature = sig.serialize_der();
    let pk = PublicKey::from_secret_key(&secp, &secret_key);
    assert!(secp.verify_ecdsa(&msg, &sig, &pk).is_ok());
    serialized_signature.to_string()
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
            .replace_script_sig_hex_at_index(script_pub_key_of_spending_vout, &vout_index_to_sign),
        Transaction::Segwit(v2_transaction) => v2_transaction
            .get_parts()
            .replace_script_sig_hex_at_index(script_pub_key_of_spending_vout, &vout_index_to_sign),
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

    let serialized_signature = double_sha256_and_sign_hex(&sighash_all_preimage, &wif);

    let sighash_type_hex_of_1_byte = convert_decimal_to_hexadecimal(sighash_type, false, Some(1));
    let sighash_type_to_append_to_signature_hex = sighash_type_hex_of_1_byte;
    format!(
        "{}{}",
        serialized_signature, sighash_type_to_append_to_signature_hex
    )
}

// let sighash_components = bip143::SighashComponents::new(&unsigned_tx);

fn is_script_pub_key_a_p2wpkh(script_pub_key: &str) -> bool {
    script_pub_key.starts_with(OP_0)
}
fn is_script_pub_key_a_p2sh_p2wpkh(script_pub_key: &str) -> bool {
    script_pub_key.starts_with(OP_HASH160) && script_pub_key.ends_with(OP_EQUAL)
}
