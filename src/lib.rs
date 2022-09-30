mod legacy_transaction;
mod segwit_transaction;
mod types;

use legacy_transaction::get_legacy_unsigned_transaction_hex;
use segwit_transaction::{
    get_unsigned_segwit_transaction, sign_segwit_transaction, SegwitTransaction,
};

use crate::legacy_transaction::{sign_p2pkh_transaction_with_one_input, P2PKHTransaction};

mod utils;
pub use crate::types::PayFrom;
pub use crate::types::PayTo;
pub use crate::types::Wifs;

pub fn get_unsigned_transaction_hex(
    inputs: &Vec<PayFrom>,
    outputs: &Vec<PayTo>,
    version: u8,
) -> String {
    let is_legacy_transaction = inputs
        .iter()
        .any(|input| bitcoin_address::is_legacy(&input.address));
    if is_legacy_transaction {
        let transaction = P2PKHTransaction::new(inputs.clone(), outputs.clone(), version);
        get_legacy_unsigned_transaction_hex(&transaction)
    } else {
        let transaction = SegwitTransaction::new(inputs.clone(), outputs.clone(), version);
        get_unsigned_segwit_transaction(&transaction)
    }
}

pub fn get_signed_transaction_hex(
    inputs: &Vec<PayFrom>,
    outputs: &Vec<PayTo>,
    wifs: &Wifs,
    version: u8,
) -> String {
    let is_legacy_transaction = inputs
        .iter()
        .any(|input| bitcoin_address::is_legacy(&input.address));
    if is_legacy_transaction {
        let transaction = P2PKHTransaction::new(inputs.clone(), outputs.clone(), version);
        sign_p2pkh_transaction_with_one_input(&transaction, wifs)
    } else {
        let transaction = SegwitTransaction::new(inputs.clone(), outputs.clone(), version);
        sign_segwit_transaction(&transaction, wifs)
    }
}

#[cfg(test)]
mod tests {
    use crate::*;
    #[test]
    fn single_input_p2wpkh_to_p2tr() {
        let version = 2;
        let pay_froms = vec![PayFrom {
            transaction: "2d0821b1a1ee6d04c5f91b0b400ec38cf7613bdb06a5d43ce658e672ea66d081"
                .to_string(),
            vout_index: 1,
            script_pub_key_hex_of_vout: "001443400caddfaffbb17b130304349384c8ef7e6fa4".to_string(), // without length
            address: "tb1qgdqqetwl4lamz7cnqvzrfyuyerhhumayhhprt2".to_string(), // Placeholder for now
            vout_amount_in_sats: 30000, // Placeholde as it's not needed for legacy
        }];
        let pay_tos = vec![PayTo {
            address: "tb1psmsr8rc6jwl47xsv4zahnt39m2peexxhxrfvprqpw86yf55rkzgq70ycww".to_string(),
            amount_in_sats: 29878,
        }];
        let mut wifs: Wifs = Wifs::new();
        wifs.insert(
            0,
            "cSPybNQG6n1LpmxGNiWUHSSseaVfNszVjoPwo7qi4dvRE2Se825q".to_string(),
        );

        let unsigned_transaction_hex = get_unsigned_transaction_hex(&pay_froms, &pay_tos, version);
        assert_eq!(unsigned_transaction_hex, "020000000181d066ea72e658e63cd4a506db3b61f78cc30e400b1bf9c5046deea1b121082d0100000000fdffffff01b67400000000000022512086e0338f1a93bf5f1a0ca8bb79ae25da839c98d730d2c08c0171f444d283b09000000000");
        let signed_transaction_hex =
            get_signed_transaction_hex(&pay_froms, &pay_tos, &wifs, version);
        assert_eq!(signed_transaction_hex, "0200000000010181d066ea72e658e63cd4a506db3b61f78cc30e400b1bf9c5046deea1b121082d0100000000fdffffff01b67400000000000022512086e0338f1a93bf5f1a0ca8bb79ae25da839c98d730d2c08c0171f444d283b09002483045022100854b7174c8864486538eacc53f3b77598bc9a5f1e0db69ac6a07fcdf73e2cd250220761703fd3b724a0b7431754c498bafa1046cdf41c0b5ecfd985a5a534c4cea93012102e3cbeaf1c32b9838fe5de49ffffd15b57fa12e99a3c08486e9eb5a35e8ac387700000000");
    }
    #[test]
    fn single_input_p2wpkh_to_p2wpkh() {
        let version = 2;
        let pay_froms = vec![PayFrom {
            transaction: "13b10f1fcb38a55c065d2605c87aa44fce9e81dd9d2b745d506c3dac3c3f35ec"
                .to_string(),
            vout_index: 1,
            script_pub_key_hex_of_vout: "00140dda001b81ce9a2b0a22a1d6e253f583d8aaeff9".to_string(), // without length
            address: "tb1qphdqqxupe6dzkz3z58twy5l4s0v24mle5gkp99".to_string(), // Placeholder for now
            vout_amount_in_sats: 30000, // Placeholde as it's not needed for legacy
        }];
        let pay_tos = vec![PayTo {
            address: "tb1qtzexd3yncgyacpz0775h5u48lvjdz98g29fq05".to_string(),
            amount_in_sats: 29890,
        }];
        let mut wifs: Wifs = Wifs::new();
        wifs.insert(
            0,
            "cRFjsTSi8azdDPVTzdkjNe2HWRy9oVFtbPEPEGJZenhHeQj8ibNy".to_string(),
        );

        let unsigned_transaction_hex = get_unsigned_transaction_hex(&pay_froms, &pay_tos, version);
        assert_eq!(unsigned_transaction_hex, "0200000001ec353f3cac3d6c505d742b9ddd819ece4fa47ac805265d065ca538cb1f0fb1130100000000fdffffff01c27400000000000016001458b266c493c209dc044ff7a97a72a7fb24d114e800000000");
        let signed_transaction_hex =
            get_signed_transaction_hex(&pay_froms, &pay_tos, &wifs, version);
        assert_eq!(signed_transaction_hex, "02000000000101ec353f3cac3d6c505d742b9ddd819ece4fa47ac805265d065ca538cb1f0fb1130100000000fdffffff01c27400000000000016001458b266c493c209dc044ff7a97a72a7fb24d114e802463043021f2fe907abb689b76301cb1ec673148e9bdf6ea358b09d84241d134be7c84b76022050c193826beeffced46d5ad0477c7e054b3cce132bef64482775917605eb40f901210230b8887b22c02acc2aa15d5d12859eb673f7c94f4f08b7daa205e13a6391ffc500000000");
    }
    #[test]
    fn single_input_p2wpkh_to_p2sh() {
        let version = 2;
        let pay_froms = vec![PayFrom {
            transaction: "13b10f1fcb38a55c065d2605c87aa44fce9e81dd9d2b745d506c3dac3c3f35ec"
                .to_string(),
            vout_index: 1,
            script_pub_key_hex_of_vout: "00140dda001b81ce9a2b0a22a1d6e253f583d8aaeff9".to_string(), // without length
            address: "tb1qphdqqxupe6dzkz3z58twy5l4s0v24mle5gkp99".to_string(), // Placeholder for now
            vout_amount_in_sats: 30000, // Placeholde as it's not needed for legacy
        }];
        let pay_tos = vec![PayTo {
            address: "2Mvn45VLAhg1TVjFrKjuyMRkoapoPNQS5Mf".to_string(),
            amount_in_sats: 29889,
        }];
        let mut wifs: Wifs = Wifs::new();
        wifs.insert(
            0,
            "cRFjsTSi8azdDPVTzdkjNe2HWRy9oVFtbPEPEGJZenhHeQj8ibNy".to_string(),
        );

        let unsigned_transaction_hex = get_unsigned_transaction_hex(&pay_froms, &pay_tos, version);
        assert_eq!(unsigned_transaction_hex, "0200000001ec353f3cac3d6c505d742b9ddd819ece4fa47ac805265d065ca538cb1f0fb1130100000000fdffffff01c17400000000000017a91426bcffdf80a7e00c8a829f8eca55fcc1d4d65c468700000000");
        let signed_transaction_hex =
            get_signed_transaction_hex(&pay_froms, &pay_tos, &wifs, version);
        assert_eq!(signed_transaction_hex, "02000000000101ec353f3cac3d6c505d742b9ddd819ece4fa47ac805265d065ca538cb1f0fb1130100000000fdffffff01c17400000000000017a91426bcffdf80a7e00c8a829f8eca55fcc1d4d65c46870247304402207ae40decea8ef2414f799b18f299ffcac8a39da0fa6445df1c96aaf71d82e045022035152d798bd0186b2f807ea29737baea04c351974208a45ec1b68cc5731a6b8001210230b8887b22c02acc2aa15d5d12859eb673f7c94f4f08b7daa205e13a6391ffc500000000");
    }
    #[test]
    fn single_input_p2wpkh_to_p2pkh() {
        let version = 2;
        let pay_froms = vec![PayFrom {
            transaction: "13b10f1fcb38a55c065d2605c87aa44fce9e81dd9d2b745d506c3dac3c3f35ec"
                .to_string(),
            vout_index: 1,
            script_pub_key_hex_of_vout: "00140dda001b81ce9a2b0a22a1d6e253f583d8aaeff9".to_string(), // without length
            address: "tb1qphdqqxupe6dzkz3z58twy5l4s0v24mle5gkp99".to_string(), // Placeholder for now
            vout_amount_in_sats: 30000, // Placeholde as it's not needed for legacy
        }];
        let pay_tos = vec![PayTo {
            address: "mtveoXKcb1EjpspMmhPAJ6RkGeewbzWYDd".to_string(),
            amount_in_sats: 29887,
        }];
        let mut wifs: Wifs = Wifs::new();
        wifs.insert(
            0,
            "cRFjsTSi8azdDPVTzdkjNe2HWRy9oVFtbPEPEGJZenhHeQj8ibNy".to_string(),
        );

        let unsigned_transaction_hex = get_unsigned_transaction_hex(&pay_froms, &pay_tos, version);
        assert_eq!(unsigned_transaction_hex, "0200000001ec353f3cac3d6c505d742b9ddd819ece4fa47ac805265d065ca538cb1f0fb1130100000000fdffffff01bf740000000000001976a9149315044ac5f815df5fc9bd3fbecff8ad1dfc01ab88ac00000000");
        let signed_transaction_hex =
            get_signed_transaction_hex(&pay_froms, &pay_tos, &wifs, version);
        assert_eq!(signed_transaction_hex, "02000000000101ec353f3cac3d6c505d742b9ddd819ece4fa47ac805265d065ca538cb1f0fb1130100000000fdffffff01bf740000000000001976a9149315044ac5f815df5fc9bd3fbecff8ad1dfc01ab88ac02483045022100c7249d685fcbc2d7e30b684a76a09eb24eb6579daa0ad9e7bece9464bbc4e73e02207d6b7c7cdb2054797a3ba43e5ba124c9576c29b04103e25ae72f61528423b2d101210230b8887b22c02acc2aa15d5d12859eb673f7c94f4f08b7daa205e13a6391ffc500000000");
    }
    #[test]
    fn single_input_p2sh_to_p2wpkh() {
        let version = 2;
        let pay_froms = vec![PayFrom {
            transaction: "f97db528e307a5928097692d1b9c2c4ee1ca4e1f57b1453c5e4699447b825fec"
                .to_string(),
            vout_index: 0,
            script_pub_key_hex_of_vout: "a9144c0e2d95060d095c9600a983a8a4fd8639e77adb87"
                .to_string(), // without length
            address: "2MzBNKyJjx44BDJfwEevVzS3Q9Z5kSEYUZB".to_string(), // Placeholder for now
            vout_amount_in_sats: 30000, // Placeholde as it's not needed for legacy
        }];
        let pay_tos = vec![PayTo {
            address: "tb1qtzexd3yncgyacpz0775h5u48lvjdz98g29fq05".to_string(),
            amount_in_sats: 29867,
        }];
        let mut wifs: Wifs = Wifs::new();
        wifs.insert(
            0,
            "cUB9G7V8KBsoj7qQpqBooYUkpr1EoD1jmoXiCg1Bb61dbG7hN6js".to_string(),
        );

        let unsigned_transaction_hex = get_unsigned_transaction_hex(&pay_froms, &pay_tos, version);
        assert_eq!(unsigned_transaction_hex, "0200000001ec5f827b4499465e3c45b1571f4ecae14e2c9c1b2d69978092a507e328b57df90000000000fdffffff01ab7400000000000016001458b266c493c209dc044ff7a97a72a7fb24d114e800000000");
        let signed_transaction_hex =
            get_signed_transaction_hex(&pay_froms, &pay_tos, &wifs, version);
        assert_eq!(signed_transaction_hex, "02000000000101ec5f827b4499465e3c45b1571f4ecae14e2c9c1b2d69978092a507e328b57df9000000001716001428ee3db8eefa6096355504b6d7b4151604d79856fdffffff01ab7400000000000016001458b266c493c209dc044ff7a97a72a7fb24d114e802483045022100b6cd893987850748bbcf60b239bbe882f0815aa43f3238058cffa8701761b750022021a81c333e9815000030e55bab8cb25ef457940600d69bad4e64dd431fc6b9b6012102968b0c598585659784517e1532c055f4f4e784a8f8ffde0b32063d715936833f00000000");
    }
    #[test]
    fn single_input_p2sh_to_p2sh() {
        let version = 2;
        let pay_froms = vec![PayFrom {
            transaction: "f97db528e307a5928097692d1b9c2c4ee1ca4e1f57b1453c5e4699447b825fec"
                .to_string(),
            vout_index: 0,
            script_pub_key_hex_of_vout: "a9144c0e2d95060d095c9600a983a8a4fd8639e77adb87"
                .to_string(), // without length
            address: "2MzBNKyJjx44BDJfwEevVzS3Q9Z5kSEYUZB".to_string(), // Placeholder for now
            vout_amount_in_sats: 30000, // Placeholde as it's not needed for legacy
        }];
        let pay_tos = vec![PayTo {
            address: "2Mvn45VLAhg1TVjFrKjuyMRkoapoPNQS5Mf".to_string(),
            amount_in_sats: 29866,
        }];
        let mut wifs: Wifs = Wifs::new();
        wifs.insert(
            0,
            "cUB9G7V8KBsoj7qQpqBooYUkpr1EoD1jmoXiCg1Bb61dbG7hN6js".to_string(),
        );

        let unsigned_transaction_hex = get_unsigned_transaction_hex(&pay_froms, &pay_tos, version);
        assert_eq!(unsigned_transaction_hex, "0200000001ec5f827b4499465e3c45b1571f4ecae14e2c9c1b2d69978092a507e328b57df90000000000fdffffff01aa7400000000000017a91426bcffdf80a7e00c8a829f8eca55fcc1d4d65c468700000000");
        let signed_transaction_hex =
            get_signed_transaction_hex(&pay_froms, &pay_tos, &wifs, version);
        assert_eq!(signed_transaction_hex, "02000000000101ec5f827b4499465e3c45b1571f4ecae14e2c9c1b2d69978092a507e328b57df9000000001716001428ee3db8eefa6096355504b6d7b4151604d79856fdffffff01aa7400000000000017a91426bcffdf80a7e00c8a829f8eca55fcc1d4d65c468702483045022100b3edf02595e8af7aa5bca019fb44e896f38e9723bb01a81012ef796b0e3208ff022011a9f8332a86e37b11f414fd3fe1c8a6a480343525726fc9ab7bb65991bc760c012102968b0c598585659784517e1532c055f4f4e784a8f8ffde0b32063d715936833f00000000");
    }
    #[test]
    fn single_input_p2sh_to_p2pkh() {
        let version = 2;
        let pay_froms = vec![PayFrom {
            transaction: "f97db528e307a5928097692d1b9c2c4ee1ca4e1f57b1453c5e4699447b825fec"
                .to_string(),
            vout_index: 0,
            script_pub_key_hex_of_vout: "a9144c0e2d95060d095c9600a983a8a4fd8639e77adb87"
                .to_string(), // without length
            address: "2MzBNKyJjx44BDJfwEevVzS3Q9Z5kSEYUZB".to_string(), // Placeholder for now
            vout_amount_in_sats: 30000, // Placeholde as it's not needed for legacy
        }];
        let pay_tos = vec![PayTo {
            address: "mtveoXKcb1EjpspMmhPAJ6RkGeewbzWYDd".to_string(),
            amount_in_sats: 29863,
        }];
        let mut wifs: Wifs = Wifs::new();
        wifs.insert(
            0,
            "cUB9G7V8KBsoj7qQpqBooYUkpr1EoD1jmoXiCg1Bb61dbG7hN6js".to_string(),
        );

        let unsigned_transaction_hex = get_unsigned_transaction_hex(&pay_froms, &pay_tos, version);
        assert_eq!(unsigned_transaction_hex, "0200000001ec5f827b4499465e3c45b1571f4ecae14e2c9c1b2d69978092a507e328b57df90000000000fdffffff01a7740000000000001976a9149315044ac5f815df5fc9bd3fbecff8ad1dfc01ab88ac00000000");
        let signed_transaction_hex =
            get_signed_transaction_hex(&pay_froms, &pay_tos, &wifs, version);
        assert_eq!(signed_transaction_hex, "02000000000101ec5f827b4499465e3c45b1571f4ecae14e2c9c1b2d69978092a507e328b57df9000000001716001428ee3db8eefa6096355504b6d7b4151604d79856fdffffff01a7740000000000001976a9149315044ac5f815df5fc9bd3fbecff8ad1dfc01ab88ac0247304402203de8eac0d844ff9a6c2f97648d6ea882547821b12aeca44e7ddcb6904b53132e02202d00856ef69719c23690390513150d987a74265db6d5b682c5defeea28ca856a012102968b0c598585659784517e1532c055f4f4e784a8f8ffde0b32063d715936833f00000000");
    }
    #[test]
    fn single_input_p2sh_to_p2tr() {
        let version = 2;
        let pay_froms = vec![PayFrom {
            transaction: "f97db528e307a5928097692d1b9c2c4ee1ca4e1f57b1453c5e4699447b825fec"
                .to_string(),
            vout_index: 0,
            script_pub_key_hex_of_vout: "a9144c0e2d95060d095c9600a983a8a4fd8639e77adb87"
                .to_string(), // without length
            address: "2MzBNKyJjx44BDJfwEevVzS3Q9Z5kSEYUZB".to_string(), // Placeholder for now
            vout_amount_in_sats: 30000, // Placeholde as it's not needed for legacy
        }];
        let pay_tos = vec![PayTo {
            address: "tb1ptwdm6l3p8eeffl3h2zm5xksxpzaem95cgvqxjhus8r7l7xtmvc3qen55vc".to_string(),
            amount_in_sats: 29854,
        }];
        let mut wifs: Wifs = Wifs::new();
        wifs.insert(
            0,
            "cUB9G7V8KBsoj7qQpqBooYUkpr1EoD1jmoXiCg1Bb61dbG7hN6js".to_string(),
        );

        let unsigned_transaction_hex = get_unsigned_transaction_hex(&pay_froms, &pay_tos, version);
        assert_eq!(unsigned_transaction_hex, "0200000001ec5f827b4499465e3c45b1571f4ecae14e2c9c1b2d69978092a507e328b57df90000000000fdffffff019e740000000000002251205b9bbd7e213e7294fe3750b7435a0608bb9d96984300695f9038fdff197b662200000000");
        let signed_transaction_hex =
            get_signed_transaction_hex(&pay_froms, &pay_tos, &wifs, version);
        assert_eq!(signed_transaction_hex, "02000000000101ec5f827b4499465e3c45b1571f4ecae14e2c9c1b2d69978092a507e328b57df9000000001716001428ee3db8eefa6096355504b6d7b4151604d79856fdffffff019e740000000000002251205b9bbd7e213e7294fe3750b7435a0608bb9d96984300695f9038fdff197b662202473044022049ec43b2659e4501437b21ad2c031ebd6856199bf889c55fb3cf1c928c78eb9a02201e246bf98d42dee12391c2f01178845d3407eeea0d8497c26d75c7b8247b95cd012102968b0c598585659784517e1532c055f4f4e784a8f8ffde0b32063d715936833f00000000");
    }
    #[test]
    fn single_input_p2pkh_to_p2pkh() {
        let version = 2;
        let pay_froms = vec![PayFrom {
            transaction: "57bded0a2734620ddd416f59d98260dc8646a990c5a901acc00a3d17a911e174"
                .to_string(),
            vout_index: 0,
            script_pub_key_hex_of_vout: "76a914ad757fd3afbdae593efdf799912f969d16337ef788ac"
                .to_string(), // without length
            address: "mwL7xEgwbiF9yRVJEgLsCjgzGofG1MtsTH".to_string(), // Placeholder for now
            vout_amount_in_sats: 28000, // Placeholde as it's not needed for legacy
        }];
        let pay_tos = vec![PayTo {
            address: "mtveoXKcb1EjpspMmhPAJ6RkGeewbzWYDd".to_string(),
            amount_in_sats: 27600,
        }];
        let mut wifs: Wifs = Wifs::new();
        wifs.insert(
            0,
            "cVGvNsrgfgENrjLRrGy4dUPTTpmRsZnUdhoiMzwvbLRXTu6zq5y7".to_string(),
        );

        let unsigned_transaction_hex = get_unsigned_transaction_hex(&pay_froms, &pay_tos, version);
        assert_eq!(unsigned_transaction_hex, "020000000174e111a9173d0ac0ac01a9c590a94686dc6082d9596f41dd0d6234270aedbd570000000000fdffffff01d06b0000000000001976a9149315044ac5f815df5fc9bd3fbecff8ad1dfc01ab88ac00000000");
        let signed_transaction_hex =
            get_signed_transaction_hex(&pay_froms, &pay_tos, &wifs, version);
        assert_eq!(signed_transaction_hex, "020000000174e111a9173d0ac0ac01a9c590a94686dc6082d9596f41dd0d6234270aedbd57000000006b483045022100c353a28d44bddf6cdd019fec458180a119053ec6a326573c071cd3aca0ac6cdd022001bdcfbd8a883f9996d38975ee1ba54cf5b8dddfd64ecfc1b474bd405eb81635012102693cfb0a49a9e4006255ccefef7bee362c0f3fb2c41d7066d9d11e10053fb9abfdffffff01d06b0000000000001976a9149315044ac5f815df5fc9bd3fbecff8ad1dfc01ab88ac00000000");
    }
    #[test]
    fn single_input_p2pkh_to_p2sh() {
        let version = 2;
        let pay_froms = vec![PayFrom {
            transaction: "57bded0a2734620ddd416f59d98260dc8646a990c5a901acc00a3d17a911e174"
                .to_string(),
            vout_index: 0,
            script_pub_key_hex_of_vout: "76a914ad757fd3afbdae593efdf799912f969d16337ef788ac"
                .to_string(), // without length
            address: "mwL7xEgwbiF9yRVJEgLsCjgzGofG1MtsTH".to_string(), // Placeholder for now
            vout_amount_in_sats: 28000, // Placeholde as it's not needed for legacy
        }];
        let pay_tos = vec![PayTo {
            address: "2Mvn45VLAhg1TVjFrKjuyMRkoapoPNQS5Mf".to_string(),
            amount_in_sats: 27600,
        }];
        let mut wifs: Wifs = Wifs::new();
        wifs.insert(
            0,
            "cVGvNsrgfgENrjLRrGy4dUPTTpmRsZnUdhoiMzwvbLRXTu6zq5y7".to_string(),
        );

        let unsigned_transaction_hex = get_unsigned_transaction_hex(&pay_froms, &pay_tos, version);
        assert_eq!(unsigned_transaction_hex, "020000000174e111a9173d0ac0ac01a9c590a94686dc6082d9596f41dd0d6234270aedbd570000000000fdffffff01d06b00000000000017a91426bcffdf80a7e00c8a829f8eca55fcc1d4d65c468700000000");
        let signed_transaction_hex =
            get_signed_transaction_hex(&pay_froms, &pay_tos, &wifs, version);
        assert_eq!(signed_transaction_hex, "020000000174e111a9173d0ac0ac01a9c590a94686dc6082d9596f41dd0d6234270aedbd57000000006a473044022042c0cae7224669274f0acddd297dbe685125b5a6b6976b83ca72d8fbe571604402200624c3c302a4eee0feed3f728a34edf1516204f8a436c33dc0eabe63eb7c60c6012102693cfb0a49a9e4006255ccefef7bee362c0f3fb2c41d7066d9d11e10053fb9abfdffffff01d06b00000000000017a91426bcffdf80a7e00c8a829f8eca55fcc1d4d65c468700000000");
    }
    #[test]
    fn single_input_p2pkh_to_p2wpkh() {
        let version = 2;
        let pay_froms = vec![PayFrom {
            transaction: "57bded0a2734620ddd416f59d98260dc8646a990c5a901acc00a3d17a911e174"
                .to_string(),
            vout_index: 0,
            script_pub_key_hex_of_vout: "76a914ad757fd3afbdae593efdf799912f969d16337ef788ac"
                .to_string(), // without length
            address: "mwL7xEgwbiF9yRVJEgLsCjgzGofG1MtsTH".to_string(), // Placeholder for now
            vout_amount_in_sats: 28000, // Placeholde as it's not needed for legacy
        }];
        let pay_tos = vec![PayTo {
            address: "tb1qtzexd3yncgyacpz0775h5u48lvjdz98g29fq05".to_string(),
            amount_in_sats: 27600,
        }];
        let mut wifs: Wifs = Wifs::new();
        wifs.insert(
            0,
            "cVGvNsrgfgENrjLRrGy4dUPTTpmRsZnUdhoiMzwvbLRXTu6zq5y7".to_string(),
        );

        let unsigned_transaction_hex = get_unsigned_transaction_hex(&pay_froms, &pay_tos, version);
        assert_eq!(unsigned_transaction_hex, "020000000174e111a9173d0ac0ac01a9c590a94686dc6082d9596f41dd0d6234270aedbd570000000000fdffffff01d06b00000000000016001458b266c493c209dc044ff7a97a72a7fb24d114e800000000");
        let signed_transaction_hex =
            get_signed_transaction_hex(&pay_froms, &pay_tos, &wifs, version);
        assert_eq!(signed_transaction_hex, "020000000174e111a9173d0ac0ac01a9c590a94686dc6082d9596f41dd0d6234270aedbd57000000006b483045022100bf47e43542ed1d50d90ccbcf2b900ce441af351e9d7fec996862930fbbd9a3c4022008203489d37249c87820cdb33a71bb2385fc759c6f7740b51c4dde2655029060012102693cfb0a49a9e4006255ccefef7bee362c0f3fb2c41d7066d9d11e10053fb9abfdffffff01d06b00000000000016001458b266c493c209dc044ff7a97a72a7fb24d114e800000000");
    }
    #[test]
    fn single_input_p2pkh_to_p2tr() {
        let version = 2;
        let pay_froms = vec![PayFrom {
            transaction: "57bded0a2734620ddd416f59d98260dc8646a990c5a901acc00a3d17a911e174"
                .to_string(),
            vout_index: 0,
            script_pub_key_hex_of_vout: "76a914ad757fd3afbdae593efdf799912f969d16337ef788ac"
                .to_string(), // without length
            address: "mwL7xEgwbiF9yRVJEgLsCjgzGofG1MtsTH".to_string(), // Placeholder for now
            vout_amount_in_sats: 28000, // Placeholde as it's not needed for legacy
        }];
        let pay_tos = vec![PayTo {
            address: "tb1ptwdm6l3p8eeffl3h2zm5xksxpzaem95cgvqxjhus8r7l7xtmvc3qen55vc".to_string(),
            amount_in_sats: 27600,
        }];
        let mut wifs: Wifs = Wifs::new();
        wifs.insert(
            0,
            "cVGvNsrgfgENrjLRrGy4dUPTTpmRsZnUdhoiMzwvbLRXTu6zq5y7".to_string(),
        );

        let unsigned_transaction_hex = get_unsigned_transaction_hex(&pay_froms, &pay_tos, version);
        assert_eq!(unsigned_transaction_hex, "020000000174e111a9173d0ac0ac01a9c590a94686dc6082d9596f41dd0d6234270aedbd570000000000fdffffff01d06b0000000000002251205b9bbd7e213e7294fe3750b7435a0608bb9d96984300695f9038fdff197b662200000000");
        let signed_transaction_hex =
            get_signed_transaction_hex(&pay_froms, &pay_tos, &wifs, version);
        assert_eq!(signed_transaction_hex, "020000000174e111a9173d0ac0ac01a9c590a94686dc6082d9596f41dd0d6234270aedbd57000000006a47304402200d51086e7fe52d63d57bc258d4c8846a549f9c02e141c3e26e546a04396497420220509e50be312d1ee884ed7bd19e4a70b4def3161f4301b164e878687c7d0f3c15012102693cfb0a49a9e4006255ccefef7bee362c0f3fb2c41d7066d9d11e10053fb9abfdffffff01d06b0000000000002251205b9bbd7e213e7294fe3750b7435a0608bb9d96984300695f9038fdff197b662200000000");
    }
}
