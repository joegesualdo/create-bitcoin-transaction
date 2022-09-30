use bitcoin_script_opcodes::{
    OP_0, OP_1, OP_CHECKSIG, OP_DUP, OP_EQUAL, OP_EQUALVERIFY, OP_HASH160,
};
use hex_utilities::{
    convert_big_endian_hex_to_little_endian, convert_decimal_to_hexadecimal, decode_hex,
};

pub fn get_byte_length_of_hex(hex: &str) -> String {
    // Hardcoded to the length of our hardcoded input scrip sig below
    // https://mempool.space/testnet/tx/2eabf6f8d63d25005866521c844449765e99e43948cb36dd6bbfad544a3d0f17
    let hex_as_bytes = decode_hex(hex).unwrap();
    let hex_bytes_count = hex_as_bytes.len();
    let length_bytes_in_hex =
        convert_decimal_to_hexadecimal(hex_bytes_count as u64, false, Some(1));
    length_bytes_in_hex
}
pub fn create_p2pkh_script_pub_key_hex_from_pub_key_hash(pub_key_hash: &String) -> String {
    // TODO: Why are these the prefix and postfix for a p2pkh script?

    let pub_key_hash_length = get_byte_length_of_hex(pub_key_hash);
    let pub_key_hash_with_length = format!("{}{}", pub_key_hash_length, pub_key_hash);
    let script_start = format!("{}{}", OP_DUP, OP_HASH160);
    let script_end = format!("{}{}", OP_EQUALVERIFY, OP_CHECKSIG);
    format!("{}{}{}", script_start, pub_key_hash_with_length, script_end)
}
pub fn create_p2sh_script_pub_key_hex_from_sh(sh: &String) -> String {
    // TODO: Why are these the prefix and postfix for a p2pkh script?
    let script_start = format!("{}", OP_HASH160);
    let script_end = format!("{}", OP_EQUAL);
    format!("{}{}{}", script_start, sh, script_end)
}
pub fn create_p2wpkh_script_pub_key_hex_from_pub_key_hash(pub_key_hash: &String) -> String {
    // TODO: Why are these the prefix and postfix for a p2pkh script?
    let pub_key_hash_length = get_byte_length_of_hex(pub_key_hash);
    let pub_key_hash_with_length = format!("{}{}", pub_key_hash_length, pub_key_hash);
    let script_start = format!("{}", OP_0);
    let prefix = "00";
    format!("{}{}", script_start, pub_key_hash_with_length)
}
pub fn create_p2tr_script_pub_key_hex_from_tweaked_x_only_public_key(
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
pub fn get_output_script_sig_for_p2pkh(public_key_hash: String) -> String {
    let public_key_hash_to_send_to = public_key_hash.to_string();
    create_p2pkh_script_pub_key_hex_from_pub_key_hash(&public_key_hash_to_send_to)
}
pub fn get_output_script_sig_for_p2sh(public_key_hash: &String) -> String {
    let length = get_byte_length_of_hex(&public_key_hash);
    // TODO: HARDCODING FOR NOW
    let sh = format!("{}{}", length, public_key_hash.to_string());

    let a = create_p2sh_script_pub_key_hex_from_sh(&sh);
    a
}
pub fn get_output_script_sig_for_p2wpkh(public_key_hash: &String) -> String {
    create_p2wpkh_script_pub_key_hex_from_pub_key_hash(&public_key_hash)
}
pub fn get_output_script_sig_for_p2tr(tweaked_x_only_public_key: &String) -> String {
    create_p2tr_script_pub_key_hex_from_tweaked_x_only_public_key(&tweaked_x_only_public_key)
}
pub fn get_version_hex_le(version: u8) -> String {
    if version > 2 {
        panic!("Version not supported")
    }
    let version = convert_decimal_to_hexadecimal(version as u64, false, Some(4));
    convert_big_endian_hex_to_little_endian(&version)
}
pub fn get_input_count(input_count: u64) -> String {
    // https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer
    // Currently, only works up to 253 inputs
    // Explaination of var-ints: https://thunderbiscuit.com/posts/transactions-legacy/
    if input_count < 253 {
        format!("{:02x}", input_count)
    } else {
        todo!();
    }
}
pub fn get_prev_transaction_hash(prev_output_hash: &String) -> String {
    convert_big_endian_hex_to_little_endian(prev_output_hash)
}
pub fn get_prev_transaction_output_index(index: u64) -> String {
    let hex = convert_decimal_to_hexadecimal(index, false, Some(4));
    convert_big_endian_hex_to_little_endian(&hex)
}

pub fn get_input_script_sig_length(input_script_hex: &str) -> String {
    get_byte_length_of_hex(input_script_hex)
}
pub fn get_disabled_locktime_value() -> String {
    "00000000".to_string()
}

pub fn get_sequence(is_rbf_on: bool) -> String {
    if is_rbf_on {
        "fdffffff".to_string()
    } else {
        "feffffff".to_string()
    }
}

pub fn get_output_count(output_count: u64) -> String {
    // https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer
    // Currently, only works up to 253 inputs
    // Explaination of var-ints: https://thunderbiscuit.com/posts/transactions-legacy/
    if output_count < 253 {
        format!("{:02x}", output_count)
    } else {
        todo!();
    }
}
pub fn get_output_amount(amount_in_sats: u64) -> String {
    let amount_in_sats_hex = convert_decimal_to_hexadecimal(amount_in_sats, false, Some(8));
    convert_big_endian_hex_to_little_endian(&amount_in_sats_hex)
}

pub fn get_output_script_length(output_script_pub_key_hex: &str) -> String {
    get_byte_length_of_hex(output_script_pub_key_hex)
}
