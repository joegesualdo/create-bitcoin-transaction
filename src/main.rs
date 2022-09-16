// Sources:
// - http://www.righto.com/2014/02/bitcoins-hard-way-using-raw-bitcoin.html
// - https://bitcoin.stackexchange.com/questions/3374/how-to-redeem-a-basic-tx
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
    create_p2pkh_script_pub_key_hex_from_pub_key_hash(&public_key_hash_to_send_to)
}
fn get_lock_time() -> String {
    "00000000".to_string()
}

struct PayFrom {
    transaction: String,
    vout_index: u64,
    pub_key_hash_hex_of_receiver: String,
}
struct PayTo {
    public_key_hash: String,
    amount_in_btc: f64,
}

fn create_p2kh_transaction(version: u8, pay_froms: Vec<PayFrom>, pay_tos: Vec<PayTo>) -> String {
    let input_count = get_input_count(pay_froms.len() as u64);
    println!("input_count: {}", &input_count);
    let mut input_part = String::new();
    input_part.push_str(&input_count);
    for pay_from in pay_froms {
        println!("payfrom parts --------------------:");
        let prev_transaction_hash = get_prev_transaction_hash(pay_from.transaction);
        println!("    prev_transaction_hash: {}", &prev_transaction_hash);
        let prev_transaction_output_index = get_prev_transaction_output_index(pay_from.vout_index);
        println!(
            "    prev_transaction_output_index: {}",
            &prev_transaction_output_index
        );
        let input_script_sig_for_signing =
            get_input_script_sig_for_signing(&pay_from.pub_key_hash_hex_of_receiver);
        let input_script_length = get_input_script_length(&input_script_sig_for_signing);
        println!("    input_script_length: {}", &input_script_length);
        println!("    input_script_sig: {}", &input_script_sig_for_signing);
        // TODO: Can also use ffffffff. What's the difference. Why does sparrow use fdffffffff
        let sequence = get_sequence("fdffffff");
        println!("    sequence: {}", &sequence);
        let part = format!(
            "{}{}{}{}{}",
            prev_transaction_hash,
            prev_transaction_output_index,
            // NOTE: I think the input script lenght and sig only needs to be added when signing,
            // not for the raw transaction. So instead of putting it here, we do it during the
            // signing process. What we do is put the script from the vout of this input in here.
            input_script_length,
            // TODO: This is what we should sign...
            input_script_sig_for_signing,
            // HARDCODING THE SCRIPT LENGTH TO ZERO FOR TESETING. REMOVE!
            // "00",
            sequence,
        );
        input_part.push_str(&part);
        println!("--------------------");
        println!("payfrom: {}", &part)
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
            transaction: "462a2706ae3b178124683144334f6eee96776e9847c4212830a92d555487e2a3"
                .to_string(),
            vout_index: 0,
            pub_key_hash_hex_of_receiver: "d43181ff75c4ed662b92fd23c007460b1af5fff7".to_string(),
        }],
        vec![
            PayTo {
                public_key_hash: "6502c6cd7a86d27306352fdc0d15aa480549e963".to_string(),
                amount_in_btc: 0.00005383,
            },
            PayTo {
                public_key_hash: "fe8c68f718a4fa75279f98bf79fae75ed779ae24".to_string(),
                amount_in_btc: 0.00001,
            },
        ],
    );
    println!("{}", transaction)
}

fn create_p2pkh_script_pub_key_hex_from_pub_key_hash(pub_key_hash: &String) -> String {
    // TODO: Why are these the prefix and postfix for a p2pkh script?
    let prefix = "76a914";
    let postfix = "88ac";
    format!("{}{}{}", prefix, pub_key_hash, postfix)
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
