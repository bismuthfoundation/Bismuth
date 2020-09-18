import sys
sys.path.append("../")

from bismuthcore.transaction import Transaction
from bismuthcore.compat import quantize_eight

AMOUNT_LEGACY = "5.12208909"

if __name__ == "__main__":
    int_amount = Transaction.f8_to_int(AMOUNT_LEGACY)
    legacy_amount = f"{quantize_eight(AMOUNT_LEGACY):0.8f}"
    print(int_amount, legacy_amount, Transaction.int_to_f8(int_amount))
    test = Transaction.from_legacy_params(amount=AMOUNT_LEGACY)
    print(test.to_tuple())
