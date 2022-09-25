use std::collections::HashMap;

use crate::legacy_transaction::{
    sign_p2pkh_transaction_with_one_input, P2PKHTransaction, PayFrom as LegacyPayFrom,
    PayTo as LegacyPayTo,
};

mod legacy_transaction;
fn main() {
    let pay_froms = vec![LegacyPayFrom {
        transaction: "97ab2e6039c829b0feafc8e78cf7dd9b7f86d3c5cd9e4c54ff0b22ab75b0e13c".to_string(),
        vout_index: 0,
        script_pub_key_hex_of_vout: "76a914f8a74b2613129e4fbd174852216a4d1d1992263d88ac"
            .to_string(),
    }];
    let pay_tos = vec![LegacyPayTo {
        address: "2MuvJWP5uKxXLgUyTaTxjzSbDY6sR3H9jME".to_string(),
        amount_in_sats: 138447,
    }];

    let transaction = P2PKHTransaction::new(pay_froms.clone(), pay_tos.clone());
    let parts = transaction.get_parts();
    let transaction_to_sign = parts.get_raw_string();

    // let wif_for_first_input = "cMfZwtqGDcPCFoiLvnkGcAvnFp3DxUYxUDYNPvbmZizf9XxHXaPV".to_string();
    // let wif_for_second_input = "cNw9uGe8mZyXBgrb9hcx892h4Uj8fjeTVbechBngzPPqdmdtsmPb".to_string();
    // let bitcoin_lib_signature = sign_transaction_with_bitcoin_lib(
    //     &transaction,
    //     &wif_for_first_input,
    //     &wif_for_second_input,
    // );
    let mut wifs: HashMap<u64, String> = HashMap::new();
    wifs.insert(
        0,
        "cSYMJxgaNbRqUGecNQX8b7NcqsHT1Lm4bH4SJaL3RS1t4pEJQJFy".to_string(),
    );

    let signature = sign_p2pkh_transaction_with_one_input(&transaction, wifs);
    println!("UNSIGNED transaction: \n{}", transaction_to_sign);
    println!();
    // println!("Signature (bitcoin lib): \n{}", bitcoin_lib_signature);
    println!();
    println!("Signature: \n{}", signature);
    println!();
    // assert_eq!(bitcoin_lib_signature, signature);
}
