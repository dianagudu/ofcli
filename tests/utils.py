from datetime import datetime, timedelta
from cryptojwt.jwk.rsa import new_rsa_key
from cryptojwt.jwt import JWT
from cryptojwt.key_jar import KeyJar


def sign_and_return_jwt(payload, key):
    key_jar = KeyJar()
    key_jar.import_jwks({"keys": [key.serialize(private=True)]}, key.kid)
    packer = JWT(key_jar=key_jar, iss=key.kid)
    return packer.pack(payload=payload, kid=key.kid, issuer_id=key.kid)


class MockTA:
    def __init__(self, entity_id, authority_hints=[]):
        self.entity_id = entity_id
        self.keys = new_rsa_key(use="sig")
        self.metadata = {
            "federation_entity": {
                "enrollment_endpoint": f"{entity_id}/enroll",
                "federation_fetch_endpoint": f"{entity_id}/fetch",
                "federation_list_endpoint": f"{entity_id}/list",
                "organization_name": f"Mock TA {entity_id}",
            }
        }
        self.authority_hints = authority_hints

    def get_entity_configuration(self):
        config = {
            "sub": self.entity_id,
            "iss": self.entity_id,
            "metadata": self.metadata,
            "exp": (datetime.now() + timedelta(days=1)).timestamp(),
            "iat": datetime.now().timestamp(),
            "jwks": {"keys": [self.keys.serialize(private=False)]},
        }
        if len(self.authority_hints) > 0:
            config["authority_hints"] = self.authority_hints

        return sign_and_return_jwt(config, self.keys)
