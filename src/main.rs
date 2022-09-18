use std::str::FromStr;

use bitcoin::{
    bech32::decode,
    blockdata::script::Builder,
    hashes::{self, sha256, Hash},
    psbt::serialize::Serialize,
    secp256k1::{Message, Secp256k1, SecretKey},
    OutPoint, PrivateKey, Script, Transaction, TxIn, TxOut, Witness,
};
use bitcoin_hd_keys::{
    convert_wif_to_private_key, double_sha256, get_public_key_hash_from_address,
};
use sha2::{Digest, Sha256};
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

// TODO:
// - Sign a transaction with multipl p2pkh vins, not just one
// - Sign other types of transactions, not only p2pkh
use hex_utilities::{
    convert_big_endian_hex_to_little_endian, convert_decimal_to_hexadecimal, decode_hex,
    encode_hex, get_text_for_hex,
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
fn get_output_script_sig(public_key_hash: String) -> String {
    let public_key_hash_to_send_to = public_key_hash.to_string();
    create_p2pkh_script_pub_key_hex_from_pub_key_hash(&public_key_hash_to_send_to)
}
fn get_lock_time() -> String {
    "00000000".to_string()
}

#[derive(Clone)]
struct PayFrom {
    transaction: String,
    vout_index: u64,
    script_pub_key_hex_of_vout: String,
    // pub_key_hash_hex_of_receiver: String,
}
#[derive(Clone)]
struct PayTo {
    address: String,
    amount_in_sats: u64,
}

struct P2PKHTransaction {
    version: u8,
    inputs: Vec<PayFrom>,
    outputs: Vec<PayTo>,
    locktime: String,
}

impl P2PKHTransaction {
    fn new(inputs: Vec<PayFrom>, outputs: Vec<PayTo>) -> Self {
        P2PKHTransaction {
            version: 1,
            inputs,
            outputs,
            locktime: "00000000".to_string(),
        }
    }

    fn get_parts(&self) -> P2PKHRawTransaction {
        P2PKHRawTransaction {
            version_hex: get_version(self.version),
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
                        // TODO: Hardcoding for now
                        sequence_hex: get_sequence("fdffffff"),
                    }
                })
                .collect(),
            outputs: self
                .outputs
                .iter()
                .map(|output| {
                    let public_key_hash = get_public_key_hash_from_address(&output.address);
                    P2PKHRawOutput {
                        amount_hex: get_output_amount(output.amount_in_sats),
                        script_pub_key_hex: get_output_script_sig(public_key_hash),
                    }
                })
                .collect(),
            // TODO: Hardcoded
            locktime_hex: self.locktime.clone(),
        }
    }
}
#[derive(Debug)]
struct P2PKHRawInput {
    previous_transaction_hash_hex: String,
    previous_transaction_output_index_hex: String,
    script_sig_hex: String,
    sequence_hex: String,
}
impl P2PKHRawInput {
    fn get_script_sig_length_hex(&self) -> String {
        get_input_script_sig_length(&self.script_sig_hex)
    }
    fn get_raw_string(&self) -> String {
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
#[derive(Debug)]
struct P2PKHRawOutput {
    amount_hex: String,
    script_pub_key_hex: String,
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
#[derive(Debug)]
struct P2PKHRawTransaction {
    version_hex: String,
    inputs: Vec<P2PKHRawInput>,
    outputs: Vec<P2PKHRawOutput>,
    locktime_hex: String,
}
impl P2PKHRawTransaction {
    fn get_raw_string(&self) -> String {
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
        get_output_count(self.inputs.len() as u64)
    }
}

fn main() {
    let pay_froms = vec![PayFrom {
        transaction: "72e73ef29facc4c758a603c584465336892efb54a374e00711608cabaf544fb3".to_string(),
        vout_index: 0,
        script_pub_key_hex_of_vout: "76a914e10319f137870564be80ad168106a5c542c1263388ac"
            .to_string(),
        // Corresponding public key (not hashed): 02cc65acf65de73f023eeb43d15f5203dc39556ccff1d261ba0ec6530f14b86ec2
        // Corresponding wif: cURSuw4bwH6sxKi936DvxLncT6V5oiSz9oi6W9mP4VRqoosXJopY
        // pub_key_hash_hex_of_receiver: "e10319f137870564be80ad168106a5c542c12633".to_string(),
    }];
    let pay_tos = vec![
        // m/44'/1'/0'/0/4 muFWn6AhQE9Snp2jLr7xqDjtw1vAkJuoZa     96a638a9e0687505f3699b8f5dcc2c94ba329d0d          cUTzJbbFAjgCQVb1P9KnhNKdiZkjSr6RvTSCaFKT8EGmsuJ4pYsY
        PayTo {
            address: "mjwM4pJLaYLAoGenBWdoUoVCccbM1jYqds".to_string(),
            amount_in_sats: 6700,
        },
        // PayTo {
        //     public_key_hash: "fe8c68f718a4fa75279f98bf79fae75ed779ae24".to_string(),
        //     amount_in_btc: 0.00001,
        // },
    ];

    let transaction = P2PKHTransaction::new(pay_froms.clone(), pay_tos.clone());
    let parts = transaction.get_parts();
    let transaction_to_sign = parts.get_raw_string();
    println!("UNSIGNED: {}", transaction_to_sign);
    let wif = "cTCAu1TDXUtS3eifJNd6KQvmpFUGiL29KwJiBCkMvb48PrtfUDri".to_string();
    let sig = sign_transaction_with_bitcoin_lib(&transaction_to_sign, &wif);
    println!("signatureeee! {}", sig);
    sign_p2pkh_transaction_with_one_input(&transaction, &wif);
}

fn sign_segwith_transaction() {
    // Source: https://medium.com/coinmonks/creating-and-signing-a-segwit-transaction-from-scratch-ec98577b526a
    todo!()
}

fn sign_p2pkh_transaction_with_one_input(transaction_to_sign: &P2PKHTransaction, wif: &String) {
    // Source: https://medium.com/@bitaps.com/exploring-bitcoin-signing-the-p2pkh-input-b8b4d5c4809c
    let vout_index_to_sign = 0;
    let vout = &transaction_to_sign.inputs[vout_index_to_sign];
    let script_pub_key_of_spending_vout = &vout.script_pub_key_hex_of_vout;
    // let input_transaction = "5e2383defe7efcbdc9fdd6dba55da148b206617bbb49e6bb93fce7bfbb459d44";
    // let input_transaction_output = 1;
    // let input_amount = 1.3000000;
    //

    let raw_transaction = transaction_to_sign.get_parts();
    let raw_input = &raw_transaction.inputs[vout_index_to_sign];
    let unsigned_raw_transaction_part_before_script_pub_key = format!(
        "{}{}{}{}",
        raw_transaction.version_hex,
        raw_transaction.get_inputs_count_hex(),
        raw_input.previous_transaction_hash_hex,
        raw_input.previous_transaction_output_index_hex
    );
    println!(
        "before: {}",
        unsigned_raw_transaction_part_before_script_pub_key
    );
    let unsigned_raw_transaction_part_after_script_pub_key = format!(
        "{}{}{}{}",
        raw_input.sequence_hex,
        raw_transaction.get_outputs_count_hex(),
        raw_transaction
            .outputs
            .iter()
            .fold(String::new(), |acc, raw_output| {
                format!("{}{}", acc, raw_output.get_raw_string())
            }),
        raw_transaction.locktime_hex,
    );
    println!(
        "after: {}",
        unsigned_raw_transaction_part_after_script_pub_key
    );

    let script_pub_key_placeholder = "00";

    let unsigned_raw_transaction_hex = format!(
        "{}{}{}",
        unsigned_raw_transaction_part_before_script_pub_key,
        script_pub_key_placeholder,
        unsigned_raw_transaction_part_after_script_pub_key
    );
    println!("unsigned_trnsaction: {}", unsigned_raw_transaction_hex);

    let script_pub_key_of_spending_vout_len =
        get_byte_length_of_hex(&script_pub_key_of_spending_vout);
    let script_pub_key_of_spending_vout_with_length_byte = format!(
        "{}{}",
        script_pub_key_of_spending_vout_len, script_pub_key_of_spending_vout
    );
    let unsigned_raw_transaction_hex_with_script_pub_key_inserted = format!(
        "{}{}{}",
        unsigned_raw_transaction_part_before_script_pub_key,
        script_pub_key_of_spending_vout_with_length_byte,
        unsigned_raw_transaction_part_after_script_pub_key,
    );

    // append sighash_all
    // Before signing, the transaction has a hash type constant temporarily appended. For a regular transaction, this is SIGHASH_ALL (0x00000001). After signing, this hash type is removed from the end of the transaction and appended to the scriptSig.
    let sighash_all = 1;
    let sighash_type = sighash_all;
    let sighash_type_hex_of_4_bytes = convert_decimal_to_hexadecimal(sighash_type, false, Some(4));
    let sighash_type_hex_in_little_endian =
        convert_big_endian_hex_to_little_endian(&sighash_type_hex_of_4_bytes);
    println!("{}", sighash_type_hex_in_little_endian);
    let input_0_sighash_all_preimage = format!(
        "{}{}",
        unsigned_raw_transaction_hex_with_script_pub_key_inserted,
        sighash_type_hex_in_little_endian
    );

    let transaction_double_sha_256 = double_sha256(&input_0_sighash_all_preimage);
    println!("s256: {}", transaction_double_sha_256);

    let secp = Secp256k1::new();
    let msg = Message::from_slice(&decode_hex(&transaction_double_sha_256).unwrap()).unwrap();

    let private_key = PrivateKey::from_wif(&wif).unwrap();
    let private_key_hex = convert_wif_to_private_key(&wif);
    println!("privk: {}", private_key_hex);
    let public_key = private_key.public_key(&secp);
    let public_key_hex = public_key.to_string();
    println!("pk: {}", public_key_hex);

    let secret_key = SecretKey::from_str(&private_key_hex).unwrap();
    let mut signature = secp.sign_ecdsa(&msg, &secret_key).serialize_der();
    println!("sig: {}", signature);

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
    let signature_script_length = get_byte_length_of_hex(&signature_script);
    let unsigned_raw_transaction_hex_with_script_pub_key_inserted = format!(
        "{}{}{}{}",
        unsigned_raw_transaction_part_before_script_pub_key,
        signature_script_length,
        signature_script,
        unsigned_raw_transaction_part_after_script_pub_key,
    );
    println!("HEERRRREEE");
    println!("private_key: {}", private_key_hex);
    println!("wif: {}", wif);
    println!("unsigned: {}", unsigned_raw_transaction_hex,);
    println!(
        "signed: {}",
        unsigned_raw_transaction_hex_with_script_pub_key_inserted
    )
}

fn sign_transaction_with_bitcoin_lib(transaction_to_sign: &String, wif: &String) -> String {
    // elements required for signing
    let input_index = 0;
    let input_amount = 0;
    // this will be the scriptPubKey form the vout
    //let script = "..."
    // One step that tripped me up is the hash type. Before signing, the transaction has a hash type constant temporarily appended.
    // For a regular transaction, this is SIGHASH_ALL (0x00000001)
    // After signing, this hash type is removed from the end of the transaction and appended to the scriptSig.
    // let sighash_all_hash_type = "01000000"; // would be 1 in decimal. Hex must this long (32 bytes?)
    // let hash_type_hex = sighash_all_hash_type; // would be 1 in decimal. Hex must this long (32 bytes?)
    // let sig_hash = format!("{}{}", transaction_to_sign, hash_type_hex);

    // let secp = Secp256k1::new();
    // let sig_hash_as_bytes = sig_hash.as_bytes();
    // println!("len: {}", sig_hash_as_bytes.len());
    // let msg = Message::from_hashed_data::<hashes::sha256::Hash>(&sig_hash_as_bytes);
    // // let msg = Message::from_slice(sig_hash_as_bytes).unwrap();
    // let private_key = PrivateKey::from_wif(wif).unwrap();
    // let private_key_hex = convert_wif_to_private_key(wif);
    // let public_key = private_key.public_key(&secp);

    // let secret_key = SecretKey::from_str(&private_key_hex).unwrap();
    // let mut sig = secp.sign_ecdsa(&msg, &secret_key).serialize_der();
    //
    //
    //
    //

    let mut raw_tx = Transaction {
        version: 1,
        lock_time: bitcoin::PackedLockTime(0),
        input: vec![TxIn {
            previous_output: OutPoint::from_str(
                "462a2706ae3b178124683144334f6eee96776e9847c4212830a92d555487e2a3:0",
            )
            .unwrap(),
            script_sig: Script::new(),
            sequence: bitcoin::Sequence(0),
            witness: Witness::default(),
        }],
        output: vec![
            TxOut {
                value: 5383,
                script_pubkey: Script::from(
                    decode_hex("76a9146502c6cd7a86d27306352fdc0d15aa480549e96388ac").unwrap(),
                ),
            },
            TxOut {
                value: 1000,
                script_pubkey: Script::from(
                    decode_hex("76a914fe8c68f718a4fa75279f98bf79fae75ed779ae2488ac").unwrap(),
                ),
            },
        ],
    };

    let input_index = 0;
    let sighash_all_hash_type = 1; // would be "01000000" in hex
    let hash_type = sighash_all_hash_type; // would be 1 in decimal. Hex must this long (32 bytes?)
    let sig_hash = raw_tx.signature_hash(
        input_index,
        &Script::from(decode_hex("76a914d43181ff75c4ed662b92fd23c007460b1af5fff788ac").unwrap()),
        hash_type,
    );

    let secp = Secp256k1::new();
    let msg = Message::from_slice(&sig_hash.into_inner()).unwrap();

    let private_key = PrivateKey::from_wif(wif).unwrap();
    let private_key_hex = convert_wif_to_private_key(wif);
    println!("privk: {}", private_key_hex);
    let public_key = private_key.public_key(&secp);
    let public_key_hex = public_key.to_string();
    println!("pk: {}", public_key_hex);

    let secret_key = SecretKey::from_str(&private_key_hex).unwrap();
    let mut signature = secp.sign_ecdsa(&msg, &secret_key).serialize_der();
    println!("sig: {}", signature);

    let mut signature_bytes = signature.to_vec();
    signature_bytes.push(hash_type as u8);

    // DO WE NEED THIS?!
    // sig.push(1); // sign hash type

    let builder1 = Builder::new()
        .push_slice(&signature_bytes)
        .push_key(&public_key);

    // set the first input signature
    raw_tx.input[0].script_sig = builder1.into_script();

    let serialized = raw_tx.serialize();

    println!("serialized: {:?}", serialized);
    println!("serialized: {:?}", encode_hex(&serialized));
    println!("txHash: {:?}", raw_tx.txid());
    return encode_hex(&serialized);

    //sig.push(1); // sign hash type
}

fn create_p2pkh_script_pub_key_hex_from_pub_key_hash(pub_key_hash: &String) -> String {
    // TODO: Why are these the prefix and postfix for a p2pkh script?
    let prefix = "76a914";
    let postfix = "88ac";
    format!("{}{}{}", prefix, pub_key_hash, postfix)
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
