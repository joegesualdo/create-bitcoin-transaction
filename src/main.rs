// Sources:
// - http://www.righto.com/2014/02/bitcoins-hard-way-using-raw-bitcoin.html
// - https://en.bitcoin.it/wiki/Transaction
// - https://en.bitcoin.it/wiki/Protocol_documentation
// - https://developer.bitcoin.org/reference/transactions.html#:~:text=Bitcoin%20transactions%20are%20broadcast%20between,part%20of%20the%20consensus%20rules.
// - https://thunderbiscuit.com/posts/transactions-legacy/
// - https://medium.com/@ottosch/manually-creating-and-signing-a-bitcoin-transaction-87fbbfe46033
// - https://medium.com/coinmonks/creating-and-signing-a-segwit-transaction-from-scratch-ec98577b526
//
// Can check work here: https://bc-2.jp/tools/txeditor2.html
//
//
use hex_utilities::{
    convert_big_endian_hex_to_little_endian, convert_decimal_to_hexadecimal, decode_hex,
    get_text_for_hex,
};

fn get_version(version: u8) -> String {
    if version != 1 {
        panic!("Version not supported")
    }
    // currently version 1
    // https://en.bitcoin.it/wiki/Transaction
    let version = "00000001".to_string();

    let little_endian_version_hex = convert_big_endian_hex_to_little_endian(&version);
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
fn get_prev_transaction_hash(prev_output_hash: String) -> String {
    let little_endian_prev_output_hash = convert_big_endian_hex_to_little_endian(&prev_output_hash);
    little_endian_prev_output_hash
}
fn get_prev_transaction_output_index(index: u64) -> String {
    let hex = convert_decimal_to_hexadecimal(index, false, Some(4));
    let hex_little_endian = convert_big_endian_hex_to_little_endian(&hex);
    hex_little_endian
}
fn get_input_script_length(input_script_hex: &str) -> String {
    // Hardcoded to the length of our hardcoded input scrip sig below
    // https://mempool.space/testnet/tx/2eabf6f8d63d25005866521c844449765e99e43948cb36dd6bbfad544a3d0f17
    let input_script_hex_as_bytes = decode_hex(input_script_hex).unwrap();
    let input_script_hex_bytes_count = input_script_hex_as_bytes.len();
    let script_length_bytes_in_hex =
        convert_decimal_to_hexadecimal(input_script_hex_bytes_count as u64, false, Some(1));
    script_length_bytes_in_hex
}
// Before signing, the script sig in the transaction should be equal to the script pub key hex from
// the spending vout.
fn get_input_script_sig(script_pub_key: &str) -> String {
    // Hardcoded
    // Before signing, the script sig should be set to the spending public script sig.
    // https://mempool.space/testnet/tx/2eabf6f8d63d25005866521c844449765e99e43948cb36dd6bbfad544a3d0f17
    script_pub_key.to_string()
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

fn get_output_amount(amount_in_btc: f64) -> String {
    let amount_in_sats = (amount_in_btc * 100000000.0) as u64;
    let amount_in_sats_hex = convert_decimal_to_hexadecimal(amount_in_sats, false, Some(8));
    let little_endian_amount_in_sats = convert_big_endian_hex_to_little_endian(&amount_in_sats_hex);
    little_endian_amount_in_sats
}
fn get_output_script_length(public_key_hash: &String) -> String {
    let output_script_sig_hex = get_output_script_sig(public_key_hash.to_string());
    let output_script_sig_hex_as_bytes = decode_hex(&output_script_sig_hex).unwrap();
    let output_script_sig_hex_bytes_count = output_script_sig_hex_as_bytes.len();
    let script_length_bytes_in_hex =
        convert_decimal_to_hexadecimal(output_script_sig_hex_bytes_count as u64, false, Some(1));
    script_length_bytes_in_hex
}
fn get_output_script_sig(public_key_hash: String) -> String {
    let public_key_hash_to_send_to = public_key_hash.to_string();
    format!("76a914{}88ac", public_key_hash_to_send_to)
}
fn get_lock_time() -> String {
    "00000000".to_string()
}

struct PayFrom {
    transaction: String,
    vout_index: u64,
    script_pub_key_hex: String,
}
struct PayTo {
    public_key_hash: String,
    amount_in_btc: f64,
}

fn create_p2kh_transaction(version: u8, pay_froms: Vec<PayFrom>, pay_tos: Vec<PayTo>) -> String {
    let input_count = get_input_count(pay_froms.len() as u64);
    let mut input_part = String::new();
    input_part.push_str(&input_count);
    for pay_from in pay_froms {
        let part = format!(
            "{}{}{}{}{}",
            get_prev_transaction_hash(pay_from.transaction),
            get_prev_transaction_output_index(pay_from.vout_index),
            get_input_script_length(&pay_from.script_pub_key_hex),
            get_input_script_sig(&pay_from.script_pub_key_hex),
            get_sequence("ffffffff"),
        );
        input_part.push_str(&part);
    }
    let output_count = get_output_count(pay_tos.len() as u64);
    let mut output_part = String::new();
    output_part.push_str(&output_count);
    for pay_to in pay_tos {
        let part = format!(
            "{}{}{}",
            get_output_amount(pay_to.amount_in_btc),
            get_output_script_length(&pay_to.public_key_hash),
            get_output_script_sig(pay_to.public_key_hash),
        );
        output_part.push_str(&part);
    }

    let transaction = format!(
        "{}{}{}{}",
        get_version(version),
        input_part,
        output_part,
        get_lock_time(),
    );
    transaction
}

fn main() {
    let transaction = create_p2kh_transaction(
        1,
        vec![PayFrom {
            transaction: "a867c9b65d4262ef4fc9d14c236af1a9a3ad274fb808f27cdffe5e4fdaf2c926"
                .to_string(),
            vout_index: 0,
            script_pub_key_hex: "76a9147576478909598ec9a79aab2ce9cad22eef7cad6888ac".to_string(),
        }],
        vec![
            PayTo {
                public_key_hash: "75a530d4fd70f55e5bc732cd3e20111f5ccbe781".to_string(),
                amount_in_btc: 0.00005,
            },
            PayTo {
                public_key_hash: "34010424a0ad16c98b6cfb3e551217cf5f0c250a".to_string(),
                amount_in_btc: 0.00004,
            },
        ],
    );
    println!("{}", transaction)
}
