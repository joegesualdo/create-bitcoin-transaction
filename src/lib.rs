mod legacy_transaction;
mod segwit_transaction;
mod types;

use legacy_transaction::get_legacy_unsigned_transaction_hex;
use segwit_transaction::{
    get_unsigned_segwit_transaction, sign_segwit_transaction, SegwitTransaction,
};

use crate::legacy_transaction::{sign_p2pkh_transaction_with_one_input, P2PKHTransaction};

pub use crate::types::PayFrom;
pub use crate::types::PayTo;
pub use crate::types::Wifs;

pub fn get_unsigned_transaction_hex(inputs: &Vec<PayFrom>, outputs: &Vec<PayTo>) -> String {
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

pub fn get_signed_transaction_hex(
    inputs: &Vec<PayFrom>,
    outputs: &Vec<PayTo>,
    wifs: &Wifs,
) -> String {
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
