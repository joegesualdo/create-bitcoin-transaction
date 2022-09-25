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
            transaction: "c0ab3d75e01c3817e5f91a51bfd99761f92718bcd555df9d2f29255fbdf3f01b"
                .to_string(),
            vout_index: 0,
            // Don't need because it's a segwit input
            script_pub_key_hex_of_vout: "76a91460157ac886a0f9e039ae8a5b52e8498a44dbb27e88ac"
                .to_string(), // without length
            address: "mpGztuA4UCcgw1CrGihZSbKpdfXnkR3Wma".to_string(), // Placeholder for now
            vout_amount_in_sats: 4000, // Placeholde as it's not needed for legacy
        },
        PayFrom {
            transaction: "7d0289e6928cf5f43197742c9d39dcc4a26aa380dd78e5eb0e13dcb7ebac9984"
                .to_string(),
            vout_index: 0,
            // Don't need because it's a segwit input
            script_pub_key_hex_of_vout: "001471f137d67e306d77a1b76237fcc63056304b2035".to_string(), // without length
            address: "tb1qw8cn04n7xpkh0gdhvgmle33s2ccykgp4pmupmk".to_string(), // Placeholder for now
            vout_amount_in_sats: 147820, // Placeholde as it's not needed for legacy
        },
    ];
    let pay_tos = vec![PayTo {
        address: "mwL7xEgwbiF9yRVJEgLsCjgzGofG1MtsTH".to_string(),
        // amount_in_sats: 138178
        amount_in_sats: 3808,
    }];
    let mut wifs: HashMap<u64, String> = HashMap::new();
    wifs.insert(
        0,
        "cTmbuD4eHeVETFYAzsiR9Lv5ceU3GRWNsMz6BQmAxrdym4aze4gS".to_string(),
    );

    wifs.insert(
        1,
        "cQ53CdMtSqStbHdnLozmMLGeLs2aT8hEdHRDs2xkWkhDzVwEWKL6".to_string(),
    );
    let unsigned_transaction_hex = get_unsigned_transaction_hex(&pay_froms, &pay_tos);
    println!("UNSIGNED SEGWIT TRANSACTION: {}", unsigned_transaction_hex);

    let signed_transaction_hex = get_signed_transaction_hex(&pay_froms, &pay_tos, &wifs);
    println!("SIGNED SEGWIT TRANSACTION: {}", signed_transaction_hex);
}
