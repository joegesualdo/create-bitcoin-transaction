mod legacy_transaction;
mod segwit_transaction;
use segwit_transaction::{
    sign_segwit_transaction, PayFrom as SegwitPayFrom, PayTo as SegwitPayTo, SegwitTransaction,
};
use std::collections::HashMap;

use crate::legacy_transaction::{
    get_unsigned_transaction_hex, sign_p2pkh_transaction_with_one_input, P2PKHTransaction,
    PayFrom as LegacyPayFrom, PayTo as LegacyPayTo,
};

fn legacy_transaction() {
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
    let unsigned_transaction_hex = get_unsigned_transaction_hex(&transaction);
    println!("UNSIGNED transaction: \n{}", unsigned_transaction_hex);
    println!();

    let mut wifs: HashMap<u64, String> = HashMap::new();
    wifs.insert(
        0,
        "cSYMJxgaNbRqUGecNQX8b7NcqsHT1Lm4bH4SJaL3RS1t4pEJQJFy".to_string(),
    );
    let signed_transaction_hex = sign_p2pkh_transaction_with_one_input(&transaction, wifs);

    println!("Signature: \n{}", signed_transaction_hex);
    println!();
}

fn segwit_transaction() {
    // from article
    // Here's the mempoo transaction: https://mempool.space/testnet/tx/65eb5594eda20b3a2437c2e2c28ba7633f0492cbb33f62ee31469b913ce8a5ca
    let pay_froms = vec![
        //legacy
        // mempool: https://mempool.space/testnet/tx/d1a92ad68a031c5324981aa920152bd16975686905db41e3fc9d51c7ff4a20edj
        SegwitPayFrom {
            transaction: "d1a92ad68a031c5324981aa920152bd16975686905db41e3fc9d51c7ff4a20ed"
                .to_string(),
            vout_index: 1,
            script_pub_key_hex_of_vout: "76a914b780d54c6b03b053916333b50a213d566bbedd1388ac"
                .to_string(),
            address: "mxFEHeSxxKjy9YcmFzXNpuE3FFJyby56jA".to_string(), // Placeholder for now
            vout_amount_in_sats: 52000, // Placeholde as it's not needed for legacy
        },
        // native segwit
        // mempool vout: https://mempool.space/testnet/tx/b7203bd59b3c26c65699251939e1e6353f5f09952156c5b9c01bbe9f5372b89c
        SegwitPayFrom {
            transaction: "b7203bd59b3c26c65699251939e1e6353f5f09952156c5b9c01bbe9f5372b89c"
                .to_string(),
            vout_index: 1,
            // Don't need because it's a segwit input
            script_pub_key_hex_of_vout: "0014594c2e3da92d1904f7e7c856220f8cae5efb5564".to_string(),
            address: "tb1qt9xzu0df95vsfal8eptzyruv4e00k4ty6d8zhh".to_string(), // Placeholder for now
            vout_amount_in_sats: 9300, // Placeholde as it's not needed for legacy
        },
        // //nested_segwit
        // mempool vout: https://mempool.space/testnet/tx/04d984cdcf728975c173c45c49a242cedee2da5dc200b2f83ca6a98aecf11280
        SegwitPayFrom {
            transaction: "04d984cdcf728975c173c45c49a242cedee2da5dc200b2f83ca6a98aecf11280"
                .to_string(),
            vout_index: 1,
            // Don't need because it's a segwit input
            script_pub_key_hex_of_vout: "a914809b71783f1b55eeadeb1678baef0c994adc425987"
                .to_string(),
            address: "2N4yEhDwic9Tm4BRN9EP1hnSu9f6cWJrU31".to_string(), // Placeholder for now
            vout_amount_in_sats: 16029969, // Placeholde as it's not needed for legacy
        },
    ];
    let pay_tos = vec![SegwitPayTo {
        address: "tb1qeds7u3tgpqkttxkzdwukaj8muqgf5nqq6w05ak".to_string(),
        amount_in_sats: 16089269,
    }];
    let mut wifs: HashMap<u64, String> = HashMap::new();
    wifs.insert(
        0,
        "cUxM1d52z426Mr8EPQMhSJyKYRWNhJh17SQ6DQ6feGPsJnAEH6dT".to_string(),
    );
    wifs.insert(
        1,
        "cNtTKNbNhz94XesU5cNhTtZ9E2QgGTDNgXjCHkYYKZaLZgmP3wKL".to_string(),
    );
    wifs.insert(
        2,
        "cUrhNhmnpFBrKAfrrwSxnrk9XiDxtiigDG5phTKtbtY88rkgyMGv".to_string(),
    );
    // mine
    let pay_froms = vec![
        // legacy
        SegwitPayFrom {
            transaction: "c0ab3d75e01c3817e5f91a51bfd99761f92718bcd555df9d2f29255fbdf3f01b"
                .to_string(),
            vout_index: 0,
            // Don't need because it's a segwit input
            script_pub_key_hex_of_vout: "76a91460157ac886a0f9e039ae8a5b52e8498a44dbb27e88ac"
                .to_string(), // without length
            address: "mpGztuA4UCcgw1CrGihZSbKpdfXnkR3Wma".to_string(), // Placeholder for now
            vout_amount_in_sats: 4000, // Placeholde as it's not needed for legacy
        },
        // bech32
        SegwitPayFrom {
            transaction: "7d0289e6928cf5f43197742c9d39dcc4a26aa380dd78e5eb0e13dcb7ebac9984"
                .to_string(),
            vout_index: 0,
            // Don't need because it's a segwit input
            script_pub_key_hex_of_vout: "001471f137d67e306d77a1b76237fcc63056304b2035".to_string(), // without length
            address: "tb1qw8cn04n7xpkh0gdhvgmle33s2ccykgp4pmupmk".to_string(), // Placeholder for now
            vout_amount_in_sats: 147820, // Placeholde as it's not needed for legacy
        },
        //legacy
        // PayFrom {
        //     transaction: "769e23f594d6794e72ce316c884bc636795848c1cc83d5225fae7f25a3dcb4ae"
        //         .to_string(),
        //     vout_index: 0,
        //     script_pub_key_hex_of_vout: "a9146475cffe4c9091303e0e1281776a343dac8faedc87"
        //         .to_string(),
        //     address: "2N2QQhDnMq3kkg5SZB8Z73y2pztsMWFjoG6".to_string(), // Placeholder for now
        //     vout_amount_in_sats: 138312, // Placeholde as it's not needed for legacy
        // },
        // native
        // PayFrom {
        //     transaction: "769e23f594d6794e72ce316c884bc636795848c1cc83d5225fae7f25a3dcb4ae"
        //         .to_string(),
        //     vout_index: 0,
        //     script_pub_key_hex_of_vout: "a9146475cffe4c9091303e0e1281776a343dac8faedc87".to_string(),
        //     address: "2N2QQhDnMq3kkg5SZB8Z73y2pztsMWFjoG6".to_string(), // Placeholder for now
        //     vout_amount_in_sats: 138312, // Placeholde as it's not needed for legacy
        // },
    ];
    let pay_tos = vec![SegwitPayTo {
        address: "tb1q73av5es7v0m46fzdscgpkdk0kezhlcu8qkc0tg".to_string(),
        // amount_in_sats: 138178
        amount_in_sats: 147500,
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
    // wifs.insert(
    //     2,
    //     "cVhEcjV4cx3zUjXr6ttKUm67tZLtUf3iz4fxaCNjnjgodGCtegzH".to_string(),
    // );

    let transaction = SegwitTransaction::new(pay_froms.clone(), pay_tos.clone());

    let signature = sign_segwit_transaction(&transaction, wifs);
}
fn main() {
    legacy_transaction();
    segwit_transaction()
}
