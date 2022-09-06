⚠️  WARNING: extremley insecure and not meant for use outside experimentation ⚠️

# Create Bitcoin Transaction 
> Satiate my need to understand how the engine works, not just that it works.

Personal testing ground for learning and experimenting with how various bitcoin transactions are created.

⚠️  Do. Not. Use. Unless you want to expose you private keys and lose all your imaginary money ⚠️  

### How to use
1. Create a transaction hex by filling in the required field in the main function
2. Decode the resulting transaction hex using bitcoin-cli and verify: `bitcoin-cli decoderawtransaction <transaction_hex>`
3. Sign the transaction using bitcoin-cli and get the signed transaction hex: `bitcoin-cli signrawtransactionwithwallet <transaction_hex>`
4. Send the signed transaction hex to the network using bitcoin-cli: `bitcoin-cli sendrawtransaction <signeded_transaction_hex>`
