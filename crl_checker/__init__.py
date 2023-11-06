from warnings import warn

from pki_tools import Certificate, Chain, crl


class Error(Exception):
    pass


class Revoked(Error):
    pass


def check_revoked(cert_pem: str, crl_issuer_pem: str):
    warn(
        "'check_revoked' function is deprecated, "
        "please migrate to 'pki_tools.is_revoked' instead.",
        DeprecationWarning,
        stacklevel=2,
    )

    cert = Certificate.from_pem_string(cert_pem)
    chain = Chain.from_pem_string(crl_issuer_pem)

    if not crl._is_revoked(cert, chain):
        raise Revoked()


def check_revoked_crypto_cert(crypto_cert, crypto_crl_issuer):
    warn(
        "'check_revoked_crypto_cert' function is deprecated, "
        "please migrate to 'pki_tools.is_revoked' instead.",
        DeprecationWarning,
        stacklevel=2,
    )

    cert = Certificate.from_cryptography(crypto_cert)
    chain = Chain.from_cryptography([crypto_crl_issuer])

    if not crl._is_revoked(cert, chain):
        raise Revoked()
