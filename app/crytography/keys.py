import json
import traceback
from typing import Any, cast

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jwcrypto import jwe
from jwcrypto.jwk import JWK
from jwcrypto.jwt import JWT

from app.utils.common import get_js_timestamp


class Cipher:
    def __init__(self, public_key: bytes, private_key: bytes, password: bytes):
        self.private_key: JWK = JWK.from_pem(private_key, password=password)
        self.public_key: JWK = JWK.from_pem(public_key)

    @property
    def kid(self):
        return self.public_key.thumbprint()

    def encrypt(self, payload: str) -> str:
        protected_header = {
            "alg": "ECDH-ES+A256KW",
            "enc": "A256GCM",
            "typ": "JWE",
            "kid": self.kid,
        }
        jwetoken = jwe.JWE(
            payload.encode("utf-8"),
            recipient=self.public_key,  # type: ignore
            protected=protected_header,  # type: ignore
        )
        enc = jwetoken.serialize(compact=True)
        return enc

    def private_jwe_decrypt(self, data: str | bytes) -> bytes:
        jwetoken = jwe.JWE()
        jwetoken.deserialize(data, self.private_key)
        return jwetoken.payload

    def get_public_key(self):
        key = self.public_key.export_public(as_dict=True)
        return key


class Signer:
    ALG = "EdDSA"

    def __init__(self, public_key: bytes, private_key: bytes, password: bytes):
        self.private_key: JWK = JWK.from_pem(private_key, password=password)
        self.public_key: JWK = JWK.from_pem(public_key)

    @property
    def kid(self):
        return self.public_key.thumbprint()

    def sign(self, data: dict[str, Any] | str) -> str:
        header = {
            "alg": self.ALG,
            "kid": self.kid,
        }
        jwt = JWT(header=header, claims=data)
        jwt.make_signed_token(self.private_key)
        return jwt.serialize()

    def verify(self, token: str, check_claims: dict | None = None) -> dict[str, Any]:
        claims_to_check = check_claims

        if not claims_to_check:
            claims_to_check = {
                "exp": get_js_timestamp(),
            }

        jwt = JWT(
            jwt=token,
            expected_type="JWS",
            check_claims=claims_to_check,
            algs=[self.ALG],
        )
        jwt.validate(self.public_key)
        return json.loads(jwt.claims)

    def get_public_key(self) -> dict:
        key = cast(dict, self.public_key.export_public(as_dict=True))
        key["alg"] = "EdDSA"
        key["kid"] = self.kid
        return key


class CommitmentPubKey:
    def __init__(self, public_key: bytes):
        self.public_key = Ed25519PublicKey.from_public_bytes(public_key)

    def verify(self, payload: bytes, signature: bytes) -> bool:
        try:
            self.public_key.verify(signature, payload)
            return True
        except Exception:
            traceback.print_exc()
            return False
