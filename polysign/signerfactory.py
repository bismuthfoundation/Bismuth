import re
from os import urandom
from typing import Type, Union

from polysign.signer import Signer, SignerType, SignerSubType
from polysign.signer_btc import SignerBTC
from polysign.signer_crw import SignerCRW
from polysign.signer_rsa import SignerRSA
from polysign.signer_ecdsa import SignerECDSA
from polysign.signer_ed25519 import SignerED25519

RE_RSA_ADDRESS = re.compile(r"[abcdef0123456789]{56}")
# TODO: improve that ECDSA one
RE_ECDSA_ADDRESS = re.compile(r"^Bis")


def signer_for_type(signer_type: SignerType) -> Union[Type[Signer], None]:
    """Returns the class matching a signer type."""
    links = {SignerType.RSA: SignerRSA, SignerType.ED25519: SignerED25519,
             SignerType.ECDSA: SignerECDSA, SignerType.BTC: SignerBTC,
             SignerType.CRW: SignerCRW,
             }
    return links.get(signer_type, None)


class SignerFactory:
    """"""

    @classmethod
    def from_private_key(cls, private_key: Union[bytes, str], signer_type: SignerType=SignerType.RSA,
                         subtype: SignerSubType=SignerSubType.MAINNET_REGULAR) -> Signer:
        """Detect the type of the key, creates and return the matching signer"""
        # TODO: detect by private_key
        signer_class = signer_for_type(signer_type)
        if signer_class is None:
            raise ValueError("Unsupported Key type")
        signer = signer_class()
        signer.from_private_key(private_key, subtype)
        return signer

    @classmethod
    def from_full_info(cls, private_key: Union[bytes, str], public_key: Union[bytes, str]=b'', address: str='',
                       signer_type: SignerType=SignerType.RSA, subtype: SignerSubType=SignerSubType.MAINNET_REGULAR,
                       verify: bool=True) -> Signer:
        pass

    @classmethod
    def address_to_signer(cls, address: str) -> Type[Signer]:
        if RE_RSA_ADDRESS.match(address):
            return SignerRSA
        elif RE_ECDSA_ADDRESS.match(address):
            if len(address) > 50:
                return SignerED25519
            else:
                return SignerECDSA

        raise ValueError("Unsupported Address type")


    @classmethod
    def address_is_valid(cls, address: str) -> bool:
        if RE_RSA_ADDRESS.match(address):
            # RSA, 56 hex
            return True
        elif RE_ECDSA_ADDRESS.match(address):
            if 50 < len(address) < 60:
                # ED25519, around 54
                return True
            if 30 < len(address) < 50:
                # ecdsa, around 37
                return True
        return False

    @classmethod
    def address_is_rsa(cls, address: str) -> bool:
        """Returns wether the given address is a legacy RSA one"""
        return RE_RSA_ADDRESS.match(address)

    @classmethod
    def from_seed(cls, seed: str='', signer_type: SignerType=SignerType.RSA,
                  subtype: SignerSubType=SignerSubType.MAINNET_REGULAR) -> Signer:
        if seed == '':
            seed = urandom(32).hex()
        signer_class = signer_for_type(signer_type)
        if signer_class is None:
            raise ValueError("Unsupported Key type")
        signer = signer_class()
        signer.from_seed(seed, subtype)
        return signer

    @classmethod
    def verify_bis_signature(cls, signature: str, public_key: str, buffer: bytes, address: str) -> None:
        """Verify signature from bismuth tx network format"""
        # Find the right signer class
        verifier = cls.address_to_signer(address)
        # let it do the job
        verifier.verify_bis_signature(signature, public_key, buffer, address)
