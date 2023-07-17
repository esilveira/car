"""Tokens for the Career Center.

This module contains the tokens for the Career Center. The tokens are used
to authenticate the user to the Career Center.

The tokens are encoded as JWTs, conforming to RFC 7519.
The JWTs are signed with a secret key, and the signature is verified when
decoding the JWTs.

For more information about JWTs, see https://jwt.io/introduction.
For more information about the RFC, see https://tools.ietf.org/html/rfc7519.
For more information about the Python library used to encode and decode JWTs,
see https://pyjwt.readthedocs.io/en/stable/.
For more information about the JWT public claims, see
https://www.iana.org/assignments/jwt/jwt.xhtml.
"""
import time as _time
from dataclasses import dataclass as _dataclass
from dataclasses import field as _field
from typing import Type as _Type
from typing import Final as _Final
from typing import TypeVar as _TypeVar

import jwt as _jwt

from app import gitlab_facade as _gitlab
from app.serialize import from_dict as _from_dict
from app.serialize import to_dict as _to_dict

__all__ = ["CareerCenterToken", "CareerCenterRefreshToken", "decode_token",
           "encode_token"]

AUDIENCE: _Final = "careercenter"  # Audience for the token
ISSUER: _Final = AUDIENCE  # Issuer of the token
ALGORITHM: _Final = "HS256"  # Sign tokens using HMAC with SHA-256


@_dataclass
class CareerCenterToken:
    """A Career Center token.

    Attributes:
        gitlab_token: Gitlab token.
        exp: Seconds since epoch for expiration date.
        sub: ID of the user.
        aud: Audience.
        iss: Issuer.
        iat: Seconds since epoch for issue date.
    """
    gitlab_access_token: _gitlab.GitlabAccessToken
    exp: int
    sub: int
    aud: str = AUDIENCE
    iss: str = ISSUER
    iat: int = _field(
        default_factory=lambda: int(_time.time()))
    # Can add jti if we want to revoke tokens.


@_dataclass
class CareerCenterRefreshToken:
    """A Career Center refresh token.

    Attributes:
        gitlab_refresh_token: Gitlab refresh token.
        exp: Seconds since epoch for expiration date.
        aud: Audience.
        iss: Issuer.
        iat: Seconds since epoch for issue date.
    """
    gitlab_refresh_token: _gitlab.GitlabRefreshToken
    exp: int
    aud: str = AUDIENCE
    iss: str = ISSUER
    iat: int = _field(
        default_factory=lambda: int(_time.time()))
    # Can add jti if we want to revoke tokens.


Token = _TypeVar("Token", CareerCenterToken, CareerCenterRefreshToken)


def encode_token(
        token: Token,
        secret: str) -> str:
    """Encode a Career Center token to a JWT.

    Args:
        token: Token to encode.
        secret: Secret to use for encoding.

    Returns:
        A JWT.
    """
    return _jwt.encode(
        payload=_to_dict(token),
        key=secret,
        algorithm=ALGORITHM
    )


def decode_token(token: str, secret: str, *,
                 token_cls: _Type[Token]
                 ) -> Token:
    """Decode a Career Center token from a JWT.

    Args:
        token: JWT to decode.
        secret: Secret to use for decoding.
        token_cls: Class of the token to decode.

    Returns:
        A Career Center token.

    Raises:
        ValueError: If the token is invalid.
    """
    try:
        decoded: Token = _from_dict(token_cls, _jwt.decode(
            jwt=token,
            key=secret,
            algorithms=[ALGORITHM],
            audience=AUDIENCE,
            issuer=ISSUER
        ))
    except _jwt.ExpiredSignatureError:
        raise ValueError("Token expired.") from None

    except _jwt.InvalidAudienceError:
        raise ValueError("Invalid audience.") from None

    except _jwt.InvalidIssuerError:
        raise ValueError("Invalid issuer.") from None

    except _jwt.InvalidSignatureError:
        raise ValueError("Invalid signature.") from None

    except _jwt.exceptions.InvalidTokenError as exc:
        raise ValueError("Invalid token.") from exc

    return decoded
