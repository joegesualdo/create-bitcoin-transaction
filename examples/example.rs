use create_bitcoin_transaction::{
    get_signed_transaction_hex, get_unsigned_transaction_hex, PayFrom, PayTo, Wifs,
};

fn main() {
    let pay_froms = vec![PayFrom {
        transaction: "befc73ebe1a50bbdef00fe745a4ead713d11e6d6caf50a86e7c627676daab07c".to_string(),
        vout_index: 0,
        script_pub_key_hex_of_vout:
            "5120114d89595f72379898785357cbeb3f7a5c0900780ce374d1a4bd72c1d4868a1f".to_string(), // without length
        address: "tb1pz9xcjk2lwgme3xrc2dtuh6el0fwqjqrcpn3hf5dyh4evr4yx3g0sa23jde".to_string(), // Placeholder for now
        vout_amount_in_sats: 29678, // Placeholde as it's not needed for legacy
    }];
    let pay_tos = vec![PayTo {
        address: "tb1ptwdm6l3p8eeffl3h2zm5xksxpzaem95cgvqxjhus8r7l7xtmvc3qen55vc".to_string(),
        amount_in_sats: 29078,
    }];
    let mut wifs: Wifs = Wifs::new();
    wifs.insert(
        0,
        "cW9GJyGDR5k6hAwwskMt4pCCvMV9h7ahd4BTVvTWCqc5YyFHRSRv".to_string(),
    );

    let unsigned_transaction_hex = get_unsigned_transaction_hex(&pay_froms, &pay_tos);
    println!("UNSIGNED SEGWIT TRANSACTION: {}", unsigned_transaction_hex);

    let signed_transaction_hex = get_signed_transaction_hex(&pay_froms, &pay_tos, &wifs);
    println!("SIGNED SEGWIT TRANSACTION: {}", signed_transaction_hex);
}
