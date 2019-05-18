
regtest add
2c57b1d58f79a4cf821a5ce2b77d5ddf45961ebde33ea48ff7a40439


# Get some cash
python3 commands.py generate 2
# check our balance (address likely not that one)
python3 commands.py balanceget 2c57b1d58f79a4cf821a5ce2b77d5ddf45961ebde33ea48ff7a40439
# Send one to the test vector ecdsa address
python3 send_nogui.py 1 Bis1SAk19HCWpDAThwFiaP9xA6zWjzsga7Hog
# Mine one block so the tx goes in
python3 commands.py generate 1
# Check our ecdsa address
python3 commands.py balanceget Bis1SAk19HCWpDAThwFiaP9xA6zWjzsga7Hog
# send back some BIS to the RSA address
python3 ecdsa_send_regtest.py

# send to ed25519 address
python3 send_nogui.py 1 Bis13AbAZwMeY1C5GuFuVuVKLSjr3RdKG63g4CEx6epwSbhpuDU3rj
# Mine one block so the tx goes in
python3 commands.py generate 1
# Check our ecdsa address
python3 commands.py balanceget Bis13AbAZwMeY1C5GuFuVuVKLSjr3RdKG63g4CEx6epwSbhpuDU3rj
# send back some BIS to the RSA address
python3 ed25519_send_regtest.py
# Mine one block so the tx goes in
python3 commands.py generate 1
# Check our ecdsa address
python3 commands.py balanceget Bis13AbAZwMeY1C5GuFuVuVKLSjr3RdKG63g4CEx6epwSbhpuDU3rj


- Enforce RSA for coinbase
