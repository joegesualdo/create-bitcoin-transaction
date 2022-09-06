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

### Resources
 - http://www.righto.com/2014/02/bitcoins-hard-way-using-raw-bitcoin.html
 - https://en.bitcoin.it/wiki/Transaction
 - https://en.bitcoin.it/wiki/Protocol_documentation
 - https://developer.bitcoin.org/reference/transactions.html#:~:text=Bitcoin%20transactions%20are%20broadcast%20between,part%20of%20the%20consensus%20rules.
 - https://thunderbiscuit.com/posts/transactions-legacy/
 - https://medium.com/@ottosch/manually-creating-and-signing-a-bitcoin-transaction-87fbbfe46033
 - https://medium.com/coinmonks/creating-and-signing-a-segwit-transaction-from-scratch-ec98577b526
 - https://bc-2.jp/tools/txeditor2.html

