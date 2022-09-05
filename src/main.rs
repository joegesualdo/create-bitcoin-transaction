// Sources:
// - http://www.righto.com/2014/02/bitcoins-hard-wa&y-using-raw-bitcoin.html
// - https://en.bitcoin.it/wiki/Transaction
// - https://en.bitcoin.it/wiki/Protocol_documentation
// - https://developer.bitcoin.org/reference/transactions.html#:~:text=Bitcoin%20transactions%20are%20broadcast%20between,part%20of%20the%20consensus%20rules.
//
// Can check work here: https://bc-2.jp/tools/txeditor2.html
//
use hex_utilities::{
    convert_big_endian_hex_to_little_endian, convert_decimal_to_hexadecimal, decode_hex,
    get_text_for_hex,
};

fn get_version() -> String {
    // currently version 1
    // https://en.bitcoin.it/wiki/Transaction
    let version = "00000001".to_string();

    let little_endian_version_hex = convert_big_endian_hex_to_little_endian(&version);
    little_endian_version_hex
}

fn get_input_count(input_count: u64) -> String {
    // https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer
    // Currently, only works up to 253 inputs
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
fn get_prev_transaction_hash(prev_output_hash: String) -> String {
    let little_endian_prev_output_hash = convert_big_endian_hex_to_little_endian(&prev_output_hash);
    little_endian_prev_output_hash
}
fn get_prev_transaction_output_index(index: u64) -> String {
    let hex = convert_decimal_to_hexadecimal(index, false, Some(4));
    let hex_little_endian = convert_big_endian_hex_to_little_endian(&hex);
    hex_little_endian
}
fn get_input_script_length() -> String {
    // Hardcoded to the length of our hardcoded input scrip sig below
    // https://mempool.space/testnet/tx/2eabf6f8d63d25005866521c844449765e99e43948cb36dd6bbfad544a3d0f17
    "19".to_string()
}
fn get_input_script_sig() -> String {
    // Hardcoded
    // Before signing, the script sig should be set to the spending public script sig.
    // https://mempool.space/testnet/tx/2eabf6f8d63d25005866521c844449765e99e43948cb36dd6bbfad544a3d0f17
    "76a914fee074ce1405ab8cfbacdd898354c736605dfd2b88ac".to_string()
}
// Hardcoding for now
fn get_sequence() -> String {
    "ffffffff".to_string()
}

fn get_output_count(output_count: u64) -> String {
    // https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer
    // Currently, only works up to 253 inputs
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

fn get_output_amount(amount_in_btc: f64) -> String {
    let amount_in_sats = (amount_in_btc * 100000000.0) as u64;
    println!("sats: {}", amount_in_sats);
    let amount_in_sats_hex = convert_decimal_to_hexadecimal(amount_in_sats, false, Some(8));
    let little_endian_amount_in_sats = convert_big_endian_hex_to_little_endian(&amount_in_sats_hex);
    println!("sats le: {}", little_endian_amount_in_sats);
    little_endian_amount_in_sats
}
fn get_output_script_length() -> String {
    "19".to_string()
}
fn get_output_script_sig() -> String {
    let public_key_hash_to_send_to = "f4d6e5314a4c7f40c779239d361bbdc8aedb7d11".to_string();
    format!("76a914{}88ac", public_key_hash_to_send_to)
}
fn get_lock_time() -> String {
    "00000000".to_string()
}

fn main() {
    let transaction = format!(
        "{}{}{}{}{}{}{}{}{}{}{}{}",
        get_version(),
        get_input_count(1),
        get_prev_transaction_hash(
            "2eabf6f8d63d25005866521c844449765e99e43948cb36dd6bbfad544a3d0f17".to_string()
        ),
        get_prev_transaction_output_index(1),
        get_input_script_length(),
        get_input_script_sig(),
        get_sequence(),
        get_output_count(1),
        get_output_amount(0.00005),
        get_output_script_length(),
        get_output_script_sig(),
        get_lock_time(),
    );

    println!();
    println!("{}", transaction)
}
