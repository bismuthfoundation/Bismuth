# Validity checks for Blocks and tx digestion

| Test   |  Cost |   Legacy      |  V2 | Comment |
|----------|:------:|-------------|------|-------
| Sanitize |  middle | sort_transactions() and process_transactions() | Transaction.from_legacy_params()| checks field sizes and reformats floats to canonical format | 
| Detect token ops | light | sort_transactions()   | Block class, cached |  That flag is not a validity check but allows to trigger token scan at the end of digest. |
| Coinbase tx has 0 amount| light | sort_transactions() | Block, _check_tx() | Do not allow coinbase tx to also move regular coins.
| Coinbase address is RSA| light | sort_transactions() | Block, _check_tx() | More a convention, but enforced.| 
| No future transaction | light | transaction_validate() | Block, _check_tx() | Transaction timestamp can't be in the future compared to current time or coinbase timestamp.|
| No old transaction | light | transaction_validate() and process_transactions()|Block, _check_tx()  | Transactions older than 2 hours can't make it to a block.|
| No negative amount | light | transaction_validate() | Transaction.from_legacy_params() | Do not allow to spend a negative amount|
| No negative fees | light | N/A | Transaction.from_legacy_params() | Do not allow negative fees. Recalc'd anyway, but still|
| No negative reward | light | N/A | Transaction.from_legacy_params() | Do not allow negative reward. Recalc'd anyway, but still|
| Sender and Recipient Address validity | light/middle | transaction_validate() | Block.validate_mid() | Both addresses must have a valid format. This is only a regexp match, not a requirement for a known - as "in chain" address. |
| Check tx signature | heavy | transaction_validate() | | Check the signature matches the tx content and related pubkey. Buffer is rebuilt from tx properties then polysign does the low level crypto job. |
| Check Block timestamp | light | digest_block(), after sort_transactions and transaction_validate | Block, _check_tx()  | Make sure the new block timestamp is greater than last known block |
| No empty sig | light | check_signature_on_block() | | a tx signature can't be empty |
| No dup sig on chain | middle/heavy | check_signature_on_block() | | a tx signature can't already be on chain db or ram |
| No dup sig in new block| light | check_signature_on_block() | | A block can't have dup tx signatures |
| Rebuild block hash| middle | rebuild_block_hash() | | Rebuild block hash from list of transactions, do not trust a hash that would be sent by a peer without verifying. In our case, hash is not part of the provided data anyway.|
| Block hash is unique| middle/heavy | check_dup_block_hash() | | Query the chain to make sure block hash is unique |
| Diff matches| middle | mining_heavy3.check_block() | | Calc diff of block and make sure it matches the required diff |
| Fees and reward calculation| middle | process_transactions() | | Recomputes full miner reward from block height and list of transactions|
| Mirror hash | middle/heavy | calc_mirror_hash(), every block | | Computes mirror hash for use in mirror rewards|
| Mirror rewards| middle | calc_mirror_rewards, once every 10 blocks | | Compute HN and Dev fund rewards as mirror block|



# Legacy digest_block flow

```
digest_block()
    sort_transactions()
        transaction_validate()
    check block timestamp()
    check_signature_on_block()
    rebuild_block_hash()
    check_dup_block_hash()
    mining_heavy3.check_block()
    process_transactions()
    calc_mirror_hash()
    calc_mirror_rewards()
```

