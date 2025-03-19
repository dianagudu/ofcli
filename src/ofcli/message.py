"""Classes and functions used to describe information in an OpenID Connect Federation."""

__author__ = "Roland Hedberg"
__license__ = "Apache 2.0"
__version__ = ""

import logging

from cryptojwt.exception import Expired
from cryptojwt.jwt import utc_time_sans_frac
from oidcmsg.exception import MissingRequiredAttribute
from oidcmsg.message import Message
from oidcmsg.message import OPTIONAL_LIST_OF_SP_SEP_STRINGS
from oidcmsg.message import OPTIONAL_LIST_OF_STRINGS
from oidcmsg.message import OPTIONAL_MESSAGE
from oidcmsg.message import SINGLE_OPTIONAL_ANY
from oidcmsg.message import SINGLE_OPTIONAL_INT
from oidcmsg.message import SINGLE_OPTIONAL_JSON
from oidcmsg.message import SINGLE_OPTIONAL_STRING
from oidcmsg.message import SINGLE_REQUIRED_INT
from oidcmsg.message import SINGLE_REQUIRED_STRING
from oidcmsg.message import msg_ser
from oidcmsg.oidc import JsonWebToken
from oidcmsg.oidc import ProviderConfigurationResponse
from oidcmsg.oidc import RegistrationResponse
from oidcmsg.oidc import SINGLE_OPTIONAL_BOOLEAN
from oidcmsg.oidc import SINGLE_OPTIONAL_DICT
from oidcmsg.oidc import deserialize_from_one_of
from oidcmsg.oidc import dict_deser
from oidcmsg.oidc import msg_ser_json


SINGLE_REQUIRED_DICT = (dict, True, msg_ser_json, dict_deser, False)

LOGGER = logging.getLogger(__name__)


class FedException(Exception):
    pass


def registration_response_deser(val, sformat="json"):
    """Deserializes a JSON object (most likely) into a RegistrationResponse."""
    return deserialize_from_one_of(val, RegistrationResponse, sformat)


def provider_info_deser(val, sformat="json"):
    """Deserializes a JSON object (most likely) into a ProviderConfigurationResponse."""
    return deserialize_from_one_of(val, ProviderConfigurationResponse, sformat)


OPTIONAL_CLIENT_METADATA = (Message, False, msg_ser, registration_response_deser, False)
OPTIONAL_PROVIDER_METADATA = (Message, False, msg_ser, provider_info_deser, False)


class AuthorizationServerMetadata(Message):
    """Metadata for an OAuth2 Authorization Server."""

    c_param = {
        "issuer": SINGLE_REQUIRED_STRING,
        "authorization_endpoint": SINGLE_OPTIONAL_STRING,
        "token_endpoint": SINGLE_OPTIONAL_STRING,
        "jwks_uri": SINGLE_OPTIONAL_STRING,
        "registration_endpoint": SINGLE_OPTIONAL_STRING,
        "scopes_supported": SINGLE_OPTIONAL_JSON,
        "response_types_supported": SINGLE_OPTIONAL_JSON,
        "response_modes_supported": SINGLE_OPTIONAL_JSON,
        "grant_types_supported": SINGLE_OPTIONAL_JSON,
        "token_endpoint_auth_methods_supported": SINGLE_OPTIONAL_JSON,
        "token_endpoint_auth_signing_alg_values_supported": SINGLE_OPTIONAL_JSON,
        "service_documentation": SINGLE_OPTIONAL_STRING,
        "ui_locales_supported": SINGLE_OPTIONAL_JSON,
        "op_policy_uri": SINGLE_OPTIONAL_STRING,
        "revocation_endpoint": SINGLE_OPTIONAL_STRING,
        "revocation_endpoint_auth_methods_supported": SINGLE_OPTIONAL_JSON,
        "revocation_endpoint_auth_signing_alg_values_supported": SINGLE_OPTIONAL_JSON,
        "introspection_endpoint": SINGLE_OPTIONAL_STRING,
        "introspection_endpoint_auth_methods_supported": SINGLE_OPTIONAL_JSON,
        "introspection_endpoint_auth_signing_alg_values_supported": SINGLE_OPTIONAL_JSON,
        "code_challenge_methods_supported": SINGLE_OPTIONAL_JSON,
    }


def auth_server_info_deser(val, sformat="json"):
    """Deserializes a JSON object (most likely) into an AuthorizationServerMetadata."""
    return deserialize_from_one_of(val, AuthorizationServerMetadata, sformat)


OPTIONAL_AUTH_SERVER_METADATA = (Message, False, msg_ser, auth_server_info_deser, False)


class NamingConstraints(Message):
    """Class representing naming constraints."""

    c_param = {
        "permitted": OPTIONAL_LIST_OF_STRINGS,
        "excluded": OPTIONAL_LIST_OF_STRINGS,
    }


def naming_constraints_deser(val, sformat="json"):
    """Deserializes a JSON object (most likely) into an NamingConstraints."""
    return deserialize_from_one_of(val, NamingConstraints, sformat)


SINGLE_OPTIONAL_NAMING_CONSTRAINTS = (
    Message,
    False,
    msg_ser,
    naming_constraints_deser,
    False,
)


class FederationEntity(Message):
    """Class representing a Federation Entity."""

    c_param = {
        "federation_fetch_endpoint": SINGLE_REQUIRED_STRING,
        "federation_list_endpoint": SINGLE_OPTIONAL_STRING,
        "federation_evaluate_endpoint": SINGLE_OPTIONAL_STRING,
        "federation_status_endpoint": SINGLE_OPTIONAL_STRING,
        "name": SINGLE_OPTIONAL_STRING,
        "contacts": OPTIONAL_LIST_OF_STRINGS,
        "policy_url": SINGLE_OPTIONAL_STRING,
        "homepage_uri": SINGLE_OPTIONAL_STRING,
        "trust_marks": SINGLE_OPTIONAL_JSON,
    }


def federation_entity_deser(val, sformat="json"):
    """Deserializes a JSON object (most likely) into a FederationEntity."""
    return deserialize_from_one_of(val, FederationEntity, sformat)


OPTIONAL_FEDERATION_ENTITY_METADATA = (
    Message,
    False,
    msg_ser,
    federation_entity_deser,
    False,
)


class OauthClientMetadata(Message):
    """Metadata for an OAuth2 Client."""

    c_param = {
        "redirect_uris": OPTIONAL_LIST_OF_STRINGS,
        "token_endpoint_auth_method": SINGLE_OPTIONAL_STRING,
        "grant_type": OPTIONAL_LIST_OF_STRINGS,
        "response_types": OPTIONAL_LIST_OF_STRINGS,
        "client_name": SINGLE_OPTIONAL_STRING,
        "client_uri": SINGLE_OPTIONAL_STRING,
        "logo_uri": SINGLE_OPTIONAL_STRING,
        "scope": OPTIONAL_LIST_OF_SP_SEP_STRINGS,
        "contacts": OPTIONAL_LIST_OF_STRINGS,
        "tos_uri": SINGLE_OPTIONAL_STRING,
        "policy_uri": SINGLE_OPTIONAL_STRING,
        "jwks_uri": SINGLE_OPTIONAL_STRING,
        "jwks": SINGLE_OPTIONAL_JSON,
        "software_id": SINGLE_OPTIONAL_STRING,
        "software_version": SINGLE_OPTIONAL_STRING,
    }


def oauth_client_metadata_deser(val, sformat="json"):
    """Deserializes a JSON object (most likely) into a OauthClientMetadata."""
    return deserialize_from_one_of(val, OauthClientMetadata, sformat)


OPTIONAL_OAUTH_CLIENT_METADATA = (
    Message,
    False,
    msg_ser,
    oauth_client_metadata_deser,
    False,
)


class OauthClientInformationResponse(OauthClientMetadata):
    """The information returned by a OAuth2 Server about an OAuth2 client."""

    c_param = OauthClientMetadata.c_param.copy()
    c_param.update(
        {
            "client_id": SINGLE_REQUIRED_STRING,
            "client_secret": SINGLE_OPTIONAL_STRING,
            "client_id_issued_at": SINGLE_OPTIONAL_INT,
            "client_secret_expires_at": SINGLE_OPTIONAL_INT,
        }
    )

    def verify(self, **kwargs):
        super(OauthClientInformationResponse, self).verify(**kwargs)

        if "client_secret" in self:
            if "client_secret_expires_at" not in self:
                raise MissingRequiredAttribute(
                    "client_secret_expires_at is a MUST if client_secret is present"
                )


class TrustMarkIssuerMetadata(Message):
    """Metadata for a Trust Issuer Client."""

    c_param = {"status_endpoint": SINGLE_REQUIRED_STRING}


def trust_mark_issuer_metadata_deser(val, sformat="json"):
    """Deserializes a JSON object (most likely) into a OauthClientMetadata."""
    return deserialize_from_one_of(val, TrustMarkIssuerMetadata, sformat)


OPTIONAL_TRUST_MARK_ISSUER_METADATA = (
    Message,
    False,
    msg_ser,
    trust_mark_issuer_metadata_deser,
    False,
)


class Metadata(Message):
    """The different types of metadata that an entity in a federation can belong to."""

    c_param = {
        "openid_relying_party": OPTIONAL_CLIENT_METADATA,
        "openid_provider": OPTIONAL_PROVIDER_METADATA,
        "oauth_authorization_server": OPTIONAL_AUTH_SERVER_METADATA,
        "oauth_client": OPTIONAL_OAUTH_CLIENT_METADATA,
        "federation_entity": OPTIONAL_FEDERATION_ENTITY_METADATA,
        "trust_mark_issuer": OPTIONAL_TRUST_MARK_ISSUER_METADATA,
    }


def metadata_deser(val, sformat="json"):
    """Deserializes a JSON object (most likely) into a MetadataPolicy."""
    return deserialize_from_one_of(val, Metadata, sformat)


SINGLE_REQUIRED_METADATA = (Message, True, msg_ser, metadata_deser, False)
SINGLE_OPTIONAL_METADATA = (Message, False, msg_ser, metadata_deser, False)


class Policy(Message):
    """The metadata policy verbs."""

    c_param = {
        "subset_of": OPTIONAL_LIST_OF_STRINGS,
        "one_of": OPTIONAL_LIST_OF_STRINGS,
        "superset_of": OPTIONAL_LIST_OF_STRINGS,
        "add": OPTIONAL_LIST_OF_STRINGS,
        "value": SINGLE_OPTIONAL_ANY,
        "default": SINGLE_OPTIONAL_ANY,
        "essential": SINGLE_OPTIONAL_BOOLEAN,
    }

    def verify(self, **kwargs):
        _extra_parameters = list(self.extra().keys())
        if _extra_parameters:
            _critical = kwargs.get("policy_language_crit")
            if _critical is None:
                pass
            elif not _critical:
                raise ValueError("Empty list not allowed for 'policy_language_crit'")
            else:
                _musts = set(_critical).intersection(_extra_parameters)
                _known = kwargs.get("known_policy_extensions")
                if _known:
                    if set(_known).issuperset(set(_musts)) is False:
                        raise FedException(_musts.difference(set(_known)))
                else:
                    raise FedException(_musts.intersection(_extra_parameters))


def policy_deser(val, sformat="json"):
    """Deserializes a JSON object (most likely) into a MetadataPolicy."""
    return deserialize_from_one_of(val, Policy, sformat)


SINGLE_REQUIRED_POLICY = (Message, True, msg_ser, policy_deser, False)
SINGLE_OPTIONAL_POLICY = (Message, False, msg_ser, policy_deser, False)


class MetadataPolicy(Message):
    """The different types of metadata that an entity in a federation can belong to."""

    c_param = {
        "openid_relying_party": OPTIONAL_MESSAGE,
        "openid_provider": OPTIONAL_MESSAGE,
        "oauth_authorization_server": OPTIONAL_MESSAGE,
        "oauth_client": OPTIONAL_MESSAGE,
        "federation_entity": OPTIONAL_MESSAGE,
        "trust_mark_issuer": OPTIONAL_MESSAGE,
    }

    def verify(self, **kwargs):
        for typ, _policy in self.items():
            for attr, item in _policy.items():
                _p = Policy(**item)
                _p.verify(**kwargs)


def metadata_policy_deser(val, sformat="json"):
    """Deserializes a JSON object (most likely) into a MetadataPolicy."""
    return deserialize_from_one_of(val, MetadataPolicy, sformat)


SINGLE_REQUIRED_METADATA_POLICY = (Message, True, msg_ser, metadata_policy_deser, False)
SINGLE_OPTIONAL_METADATA_POLICY = (
    Message,
    False,
    msg_ser,
    metadata_policy_deser,
    False,
)


class Constraints(Message):
    """The types of constraints that can be applied to a trust chain."""

    c_param = {
        "max_path_length": SINGLE_OPTIONAL_INT,
        "naming_constraints": SINGLE_OPTIONAL_NAMING_CONSTRAINTS,
    }


def constrains_deser(val, sformat="json"):
    """Deserializes a JSON object (most likely) into a Constraints."""
    return deserialize_from_one_of(val, Constraints, sformat)


SINGLE_REQUIRED_CONSTRAINS = (Message, True, msg_ser, constrains_deser, False)
SINGLE_OPTIONAL_CONSTRAINS = (Message, False, msg_ser, constrains_deser, False)


class EntityStatement(JsonWebToken):
    """The Entity Statement"""

    c_param = JsonWebToken.c_param.copy()
    c_param.update(
        {
            "sub": SINGLE_REQUIRED_STRING,
            "iss": SINGLE_REQUIRED_STRING,
            "exp": SINGLE_REQUIRED_INT,
            "iat": SINGLE_REQUIRED_INT,
            "jwks": SINGLE_OPTIONAL_DICT,
            "aud": SINGLE_OPTIONAL_STRING,
            "jti": SINGLE_OPTIONAL_STRING,
            "authority_hints": OPTIONAL_LIST_OF_STRINGS,
            "metadata": SINGLE_OPTIONAL_METADATA,
            "metadata_policy": SINGLE_OPTIONAL_METADATA_POLICY,
            "constraints": SINGLE_OPTIONAL_CONSTRAINS,
            "crit": OPTIONAL_LIST_OF_STRINGS,
            "policy_language_crit": OPTIONAL_LIST_OF_STRINGS,
            "trust_marks": SINGLE_OPTIONAL_DICT,
            "trust_anchor_id": SINGLE_OPTIONAL_STRING,
        }
    )

    def verify(self, **kwargs):
        super(EntityStatement, self).verify(**kwargs)

        _extra_parameters = list(self.extra().keys())
        if _extra_parameters:
            _critical = self.get("crit")
            if _critical is None:
                pass
            elif not _critical:
                raise ValueError("Empty list not allowed for 'crit'")
            else:
                _musts = set(_critical).intersection(_extra_parameters)
                _known = kwargs.get("known_extensions")
                if _known:
                    if set(_known).issuperset(set(_musts)) is False:
                        raise FedException(_musts.difference(set(_known)))
                else:
                    raise FedException(_musts.intersection(_extra_parameters))

        _metadata_policy = self.get("metadata_policy")
        if _metadata_policy:
            _crit = self.get("policy_language_crit")
            if _crit:
                _metadata_policy.verify(policy_language_crit=_crit, **kwargs)


class TrustMark(JsonWebToken):
    c_param = JsonWebToken.c_param.copy()
    c_param.update(
        {
            "sub": SINGLE_REQUIRED_STRING,
            "iss": SINGLE_REQUIRED_STRING,
            "iat": SINGLE_REQUIRED_INT,
            "id": SINGLE_REQUIRED_STRING,
            "mark": SINGLE_OPTIONAL_STRING,
            "exp": SINGLE_OPTIONAL_INT,
            "ref": SINGLE_OPTIONAL_STRING,
        }
    )

    def verify(self, **kwargs):
        super(TrustMark, self).verify(**kwargs)

        entity_id = kwargs.get("entity_id")

        if entity_id is not None and entity_id != self["sub"]:
            raise FedException(
                "Mismatch between subject in trust mark and entity_id of entity"
            )

        exp = kwargs.get("exp", 0)
        if exp:
            _now = utc_time_sans_frac()
            if _now > exp:  # have passed the time of expiration
                raise Expired()

        return True
