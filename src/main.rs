mod legacy_transaction;
mod segwit_transaction;
mod types;
use legacy_transaction::get_legacy_unsigned_transaction_hex;
use segwit_transaction::{
    get_unsigned_segwit_transaction, sign_segwit_transaction, SegwitTransaction,
};
use std::collections::HashMap;
use types::Wifs;

use crate::{
    legacy_transaction::{sign_p2pkh_transaction_with_one_input, P2PKHTransaction},
    types::{PayFrom, PayTo},
};

fn get_unsigned_transaction_hex(inputs: &Vec<PayFrom>, outputs: &Vec<PayTo>) -> String {
    let is_legacy_transaction = inputs
        .iter()
        .find(|input| !bitcoin_address::is_legacy(&input.address))
        .is_none();
    if is_legacy_transaction {
        let transaction = P2PKHTransaction::new(inputs.clone(), outputs.clone());
        let unsigned_transaction_hex = get_legacy_unsigned_transaction_hex(&transaction);
        unsigned_transaction_hex
    } else {
        let transaction = SegwitTransaction::new(inputs.clone(), outputs.clone());

        let unsigned_transaction_hex = get_unsigned_segwit_transaction(&transaction);
        unsigned_transaction_hex
    }
}
fn get_signed_transaction_hex(inputs: &Vec<PayFrom>, outputs: &Vec<PayTo>, wifs: &Wifs) -> String {
    let is_legacy_transaction = inputs
        .iter()
        .find(|input| !bitcoin_address::is_legacy(&input.address))
        .is_none();
    if is_legacy_transaction {
        let transaction = P2PKHTransaction::new(inputs.clone(), outputs.clone());
        let signed_transaction_hex = sign_p2pkh_transaction_with_one_input(&transaction, wifs);
        signed_transaction_hex
    } else {
        let transaction = SegwitTransaction::new(inputs.clone(), outputs.clone());

        let signed_transaction_hex = sign_segwit_transaction(&transaction, wifs);
        signed_transaction_hex
    }
}

fn main() {
    let pay_froms = vec![
        // legacy
        PayFrom {
            transaction: "2d0821b1a1ee6d04c5f91b0b400ec38cf7613bdb06a5d43ce658e672ea66d081"
                .to_string(),
            vout_index: 1,
            // Don't need because it's a segwit input
            script_pub_key_hex_of_vout: "001443400caddfaffbb17b130304349384c8ef7e6fa4".to_string(), // without length
            address: "tb1qgdqqetwl4lamz7cnqvzrfyuyerhhumayhhprt2".to_string(), // Placeholder for now
            vout_amount_in_sats: 30000, // Placeholde as it's not needed for legacy
        },
    ];
    let pay_tos = vec![PayTo {
        address: "tb1psmsr8rc6jwl47xsv4zahnt39m2peexxhxrfvprqpw86yf55rkzgq70ycww".to_string(),
        // amount_in_sats: 138178
        amount_in_sats: 29878,
    }];
    let mut wifs: HashMap<u64, String> = HashMap::new();
    wifs.insert(
        0,
        "cSPybNQG6n1LpmxGNiWUHSSseaVfNszVjoPwo7qi4dvRE2Se825q".to_string(),
    );

    let unsigned_transaction_hex = get_unsigned_transaction_hex(&pay_froms, &pay_tos);
    println!("UNSIGNED SEGWIT TRANSACTION: {}", unsigned_transaction_hex);

    let signed_transaction_hex = get_signed_transaction_hex(&pay_froms, &pay_tos, &wifs);
    println!("SIGNED SEGWIT TRANSACTION: {}", signed_transaction_hex);
}
