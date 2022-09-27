# Create Bitcoin Transaction 
> Satiate my need to understand how the engine works, not just that it works.

Personal testing ground for learning and experimenting with how various bitcoin transactions are created.

---

**⚠️ This is experimental. Please use at your own risk.⚠️**

---

## Install
> Add package to Cargo.toml file
```rust
[dependencies]
create_bitcoin_transaction = "0.1.2"
```

## Usage:
```rust
use create_bitcoin_transaction::{
    get_signed_transaction_hex, get_unsigned_transaction_hex, PayFrom, PayTo, Wifs,
};

fn main() {
    let pay_froms = vec![PayFrom {
        transaction: "2d0821b1a1ee6d04c5f91b0b400ec38cf7613bdb06a5d43ce658e672ea66d081".to_string(),
        vout_index: 1,
        script_pub_key_hex_of_vout: "001443400caddfaffbb17b130304349384c8ef7e6fa4".to_string(), 
        address: "tb1qgdqqetwl4lamz7cnqvzrfyuyerhhumayhhprt2".to_string(), 
        vout_amount_in_sats: 30000, // 
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

    let unsigned_transaction_hex = get_unsigned_transaction_hex(&pay_froms, &pay_tos);
    println!("Unsigned transaction: {}", unsigned_transaction_hex);

    let signed_transaction_hex = get_signed_transaction_hex(&pay_froms, &pay_tos, &wifs);
    println!("Signed transaction: {}", signed_transaction_hex);
}
```
## Resources
To read various resources used to learn how to create and sign transactions, see the [RESOURCES.md](./RESOURCES.md)

