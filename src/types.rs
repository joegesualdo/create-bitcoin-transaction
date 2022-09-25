use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct PayFrom {
    pub transaction: String,
    pub vout_index: u64,
    pub script_pub_key_hex_of_vout: String,
    pub address: String,          // native or wrapped,
    pub vout_amount_in_sats: u64, // native or wrapped,
}
#[derive(Debug, Clone)]
pub struct PayTo {
    pub address: String,
    pub amount_in_sats: u64,
}
pub type Wifs = HashMap<u64, String>;
