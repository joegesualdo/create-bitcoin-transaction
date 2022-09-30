use std::{collections::HashMap, str::FromStr};

use bitcoin::{
    secp256k1::{Message, Secp256k1, SecretKey},
    PrivateKey, Script,
};
use bitcoin_utils::{
    convert_wif_to_private_key, double_sha256_hex, get_public_key_hash_from_address,
    get_script_hash_from_p2sh_address, get_tweaked_x_only_public_key_from_p2tr_address,
};
use hex_utilities::{
    convert_big_endian_hex_to_little_endian, convert_decimal_to_hexadecimal, decode_hex,
};

use crate::{
    types::{PayFrom, PayTo, Wifs},
    utils::{
        get_disabled_locktime_value, get_input_count, get_input_script_sig_length,
        get_output_amount, get_output_count, get_output_script_length,
        get_output_script_sig_for_p2pkh, get_output_script_sig_for_p2sh,
        get_output_script_sig_for_p2tr, get_output_script_sig_for_p2wpkh,
        get_prev_transaction_hash, get_prev_transaction_output_index, get_sequence,
        get_version_hex_le,
    },
};

#[derive(Debug, Clone)]
pub struct P2PKHTransaction {
    pub version: u8,
    pub inputs: Vec<PayFrom>,
    pub outputs: Vec<PayTo>,
    pub locktime: String,
}
impl P2PKHTransaction {
    pub fn new(inputs: Vec<PayFrom>, outputs: Vec<PayTo>, version: u8) -> Self {
        P2PKHTransaction {
            version,
            inputs,
            outputs,
            locktime: get_disabled_locktime_value(),
        }
    }

    pub fn get_parts(&self) -> P2PKHRawTransaction {
        P2PKHRawTransaction {
            version_hex: get_version_hex_le(self.version),
            inputs: self
                .inputs
                .iter()
                .map(|input| {
                    P2PKHRawInput {
                        previous_transaction_hash_hex: get_prev_transaction_hash(
                            &input.transaction,
                        ),
                        previous_transaction_output_index_hex: get_prev_transaction_output_index(
                            input.vout_index,
                        ),
                        // TODO: Hardcoding this for unsigned transactions
                        script_sig_hex: "".to_string(),
                        sequence_hex: get_sequence(true),
                    }
                })
                .collect(),
            outputs: self
                .outputs
                .iter()
                .map(|output| {
                    let address = &output.address;
                    let is_legacy_address = bitcoin_address::is_legacy(address);
                    let is_p2sh_address = bitcoin_address::is_p2sh(address);
                    let is_p2wpkh_address = bitcoin_address::is_segwit_native(address);
                    let is_taproot_address = bitcoin_address::is_taproot(address);
                    P2PKHRawOutput {
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
            locktime_hex: self.locktime.clone(),
        }
    }
}
#[derive(Debug, Clone)]
pub struct P2PKHRawInput {
    pub previous_transaction_hash_hex: String,
    pub previous_transaction_output_index_hex: String,
    pub script_sig_hex: String,
    pub sequence_hex: String,
}
impl P2PKHRawInput {
    fn get_script_sig_length_hex(&self) -> String {
        get_input_script_sig_length(&self.script_sig_hex)
    }
    pub fn get_raw_string(&self) -> String {
        format!(
            "{}{}{}{}{}",
            self.previous_transaction_hash_hex,
            self.previous_transaction_output_index_hex,
            self.get_script_sig_length_hex(),
            self.script_sig_hex,
            self.sequence_hex
        )
    }
}

#[derive(Debug, Clone)]
pub struct P2PKHRawOutput {
    pub amount_hex: String,
    pub script_pub_key_hex: String,
}
impl P2PKHRawOutput {
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
pub struct P2PKHRawTransaction {
    pub version_hex: String,
    pub inputs: Vec<P2PKHRawInput>,
    pub outputs: Vec<P2PKHRawOutput>,
    pub locktime_hex: String,
}
impl P2PKHRawTransaction {
    pub fn get_raw_string(&self) -> String {
        format!(
            "{}{}{}{}{}{}",
            self.version_hex,
            self.get_inputs_count_hex(),
            self.inputs.iter().fold(String::new(), |acc, input| format!(
                "{}{}",
                acc,
                &input.get_raw_string()
            )),
            self.get_outputs_count_hex(),
            self.outputs
                .iter()
                .fold(String::new(), |acc, input| format!(
                    "{}{}",
                    acc,
                    &input.get_raw_string()
                )),
            self.locktime_hex
        )
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
                    P2PKHRawInput {
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

pub fn sign_p2pkh_transaction_with_one_input(
    transaction_to_sign: &P2PKHTransaction,
    wifs: &Wifs,
) -> String {
    let unsigned_raw_transaction = transaction_to_sign.get_parts();
    let mut signature_scripts: HashMap<u64, String> = HashMap::new();
    for (index, _input) in transaction_to_sign.inputs.iter().enumerate() {
        let signature_script = get_signiture_script_for_input_at_index(
            transaction_to_sign,
            index,
            &wifs[&(index as u64)],
        );
        signature_scripts.insert(index as u64, signature_script);
    }

    let signed_raw_transaction =
        signature_scripts
            .iter()
            .fold(unsigned_raw_transaction, |acc, sig_script_hash| {
                let (index, sig_script) = sig_script_hash;
                acc.replace_script_sig_hex_at_index(sig_script, &(*index as usize))
            });
    signed_raw_transaction.get_raw_string()
}

fn get_signiture_script_for_input_at_index(
    transaction_to_sign: &P2PKHTransaction,
    input_index_to_sign: usize,
    wif: &String,
) -> String {
    let vout_index_to_sign = input_index_to_sign;
    let vout = &transaction_to_sign.inputs[vout_index_to_sign];
    let script_pub_key_of_spending_vout = &vout.script_pub_key_hex_of_vout;
    let unsigned_raw_transaction_with_pub_key_of_spending_vout = transaction_to_sign
        .get_parts()
        .replace_script_sig_hex_at_index(script_pub_key_of_spending_vout, &vout_index_to_sign);
    let unsigned_raw_transaction_hex_with_script_pub_key_inserted =
        unsigned_raw_transaction_with_pub_key_of_spending_vout.get_raw_string();

    // append sighash_all
    // Before signing, the transaction has a hash type constant temporarily appended. For a regular transaction, this is SIGHASH_ALL (0x00000001). After signing, this hash type is removed from the end of the transaction and appended to the scriptSig.
    let sighash_all = 1;
    let sighash_type = sighash_all;
    let sighash_type_hex_of_4_bytes = convert_decimal_to_hexadecimal(sighash_type, false, Some(4));
    let sighash_type_hex_in_little_endian =
        convert_big_endian_hex_to_little_endian(&sighash_type_hex_of_4_bytes);
    let input_0_sighash_all_preimage = format!(
        "{}{}",
        unsigned_raw_transaction_hex_with_script_pub_key_inserted,
        sighash_type_hex_in_little_endian
    );

    let transaction_double_sha_256 = double_sha256_hex(&input_0_sighash_all_preimage);

    let secp = Secp256k1::new();
    let msg = Message::from_slice(&decode_hex(&transaction_double_sha_256).unwrap()).unwrap();

    let private_key = PrivateKey::from_wif(wif).unwrap();
    let private_key_hex = convert_wif_to_private_key(wif);
    let public_key = private_key.public_key(&secp);
    let public_key_hex = public_key.to_string();

    let secret_key = SecretKey::from_str(&private_key_hex).unwrap();
    let signature = secp.sign_ecdsa(&msg, &secret_key).serialize_der();

    // this should be calculated
    let sighash_type_hex_of_1_byte = convert_decimal_to_hexadecimal(sighash_type, false, Some(1));
    let sighash_type_to_append_to_signature_hex = sighash_type_hex_of_1_byte;
    let signature_with_sighash_type_appended =
        format!("{}{}", signature, sighash_type_to_append_to_signature_hex);
    let signature_with_sighash_type_appended_length =
        get_byte_length_of_hex(&signature_with_sighash_type_appended);
    let public_key_length = get_byte_length_of_hex(&public_key_hex);
    let signature_script = format!(
        "{}{}{}{}",
        signature_with_sighash_type_appended_length,
        signature_with_sighash_type_appended,
        public_key_length,
        public_key_hex
    );
    signature_script
}

fn get_byte_length_of_hex(hex: &str) -> String {
    let hex_as_bytes = decode_hex(hex).unwrap();
    let hex_bytes_count = hex_as_bytes.len();
    convert_decimal_to_hexadecimal(hex_bytes_count as u64, false, Some(1))
}

pub fn get_legacy_unsigned_transaction_hex(transaction: &P2PKHTransaction) -> String {
    let parts = transaction.get_parts();
    parts.get_raw_string()
}
