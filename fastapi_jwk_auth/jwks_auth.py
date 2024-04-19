from typing import Any, Dict, List
import logging

import jwt
import requests
from fastapi import Depends, HTTPException, Request, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.types import ASGIApp
from starlette.responses import JSONResponse

__all__ = ["jwk_validator", "JWKMiddleware"]

security = HTTPBearer()

ALGORITHMS = ("RS256", "HS256")
"""
Default supported algorithms for JWT token validation.
"""

logger = logging.getLogger(__name__)


# Function to fetch the JSON Web Key Set (JWKS) from the JWKS URI
def fetch_jwks(jwks_uri: str) -> Dict[str, Any]:
    """
    This function fetches the JSON Web Key Set (JWKS) from the JWKS URI.

    Args:
        jwks_uri (str): The URI to fetch the JWKS from.

    Raises:
        HTTPException: If the JWKS URI is invalid or the JWKS is invalid.

    Returns:
        Dict[str, Any]: The JSON Web Key Set (JWKS) fetched from the JWKS URI.
    """
    try:
        logger.debug("Fetching JWKS from %s", jwks_uri)
        jwks_response = requests.get(jwks_uri)
        jwks_response.raise_for_status()
    except requests.RequestException as e:
        logger.error("Invalid JWKS URI")
        raise HTTPException(status_code=503, detail="Invalid JWKS URI") from e
    jwks: Dict[str, Any] = jwks_response.json()
    if "keys" not in jwks:
        logger.error("Invalid JWKS")
        raise HTTPException(status_code=503, detail="Invalid JWKS")
    return jwks


def get_validated_payload(
    token: str,
    jwks_uri: str,
    options: dict[str, Any] | None = None,
    algorithms: List = ALGORITHMS,
) -> Any:
    """
    This function validates the jwt token and extracts
    the payload from it.

    Args:
        token (str): A valid JWT token
        jwks_uri (str): The URI to fetch the JWKS from.
        options (dict|None): Options to pass to the JWT library for decoding the token. Defaults to None.
        algorithms (List): A list of supported algorithms. Defaults to ALGORITHMS.

    Raises:
        HTTPException: If the token is invalid or has expired.

    Returns:
        Any: The payload of the validated JWT token.
    """
    jwks = fetch_jwks(jwks_uri)
    public_key = None
    try:
        logger.debug("Validating token")
        logger.debug("Supported algorithms: %s", ", ".join(algorithms))
        header = jwt.get_unverified_header(token)
        kid = header["kid"]
        if header["alg"] not in algorithms:
            logger.debug("Unsupported algorithm: %s", header["alg"])
            raise HTTPException(
                status_code=401, detail="Invalid token: Unsupported algorithm"
            )
        logger.debug("Validating token with kid: %s", kid)
        for key in jwks["keys"]:
            if key["kid"] == kid:
                public_key = jwt.algorithms.get_default_algorithms()[
                    header["alg"]
                ].from_jwk(key)
                break
        if public_key is None:
            logger.debug("Token kid not found in JWKS")
            raise HTTPException(
                status_code=401, detail="Invalid token: kid not found in JWKS"
            )
        return jwt.decode(
            token, public_key, algorithms=[header["alg"]], options=options
        )
    except jwt.ExpiredSignatureError as e:
        raise HTTPException(status_code=401, detail=f"Token has expired: {e}") from e
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}") from e
    except KeyError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}") from e


# JWT Token Validation Middleware
def jwk_validator(
    request: Request,
    jwks_uri: str,
    options: dict[str, Any] | None = None,
    credentials: HTTPAuthorizationCredentials = Depends(security),
    algorithms: List = ALGORITHMS,
) -> Request:
    """
    This dependency function validates the JWT token using the JSON Web Key Set (JWKS)
    fetched from the JWKS URI.

    Args:
        request (Request): The request object.
        jwks_uri (str): The URI to fetch the JWKS from.
        options (dict|None): Options to pass to the JWT library for decoding the token. Defaults to None.
        credentials (HTTPAuthorizationCredentials): The HTTP Authorization credentials.
        algorithms (list): A list of supported algorithms.

    Raises:
        HTTPException: If the token is invalid or has expired.

    Returns:
        Request: The request object with the payload of the validated JWT token.
    """
    token = credentials.credentials
    if credentials.scheme != "Bearer" or not token:
        raise HTTPException(
            status_code=401, detail="Invalid token: Missing Bearer token"
        )
    request.state.payload = get_validated_payload(token, jwks_uri, options, algorithms)
    return request


# JWT Token Validation Middleware
class JWKMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app: ASGIApp,
        jwks_uri: str,
        options: dict[str, Any] | None = None,
        algorithms: List = ALGORITHMS,
    ):
        """
        This middleware validates the JWT token using the JSON Web Key Set (JWKS)
        fetched from the JWKS URI.

        Args:
            app (ASGIApp): The ASGI application.
            jwks_uri (str): The URI to fetch the JWKS from.
            options (dict|None): Options to pass to the JWT library for decoding the token. Defaults to None.
            algorithms (list): A list of supported algorithms.
        """
        self.jwks_uri = jwks_uri
        self.algorithms = algorithms
        self.options = options
        super().__init__(app)

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        bearer_token = request.headers.get("authorization") or request.headers.get(
            "Authorization"
        )
        try:
            if not bearer_token or not bearer_token.startswith("Bearer "):
                raise HTTPException(
                    status_code=401, detail="Invalid token: Missing Bearer token"
                )
            token = bearer_token[7:]
            request.state.payload = get_validated_payload(
                token, self.jwks_uri, self.options, self.algorithms
            )
        # if starlette middleware is to raise any exception (even HTTPException),
        # it has to be caught and parsed to a Response, otherwise it will create
        # an internal server error and return 500
        # even if the status code in HTTPException is set to other than 500
        except HTTPException as e:
            logger.debug("JWT validation failed: %s", e.detail)
            return JSONResponse(
                content={"detail": e.detail, "status": e.status_code},
                status_code=e.status_code,
            )
        except Exception as e:
            logger.error(
                "JWT validation failed because of unexpected internal error: %s", e
            )
            return JSONResponse(
                content={"detail": "Internal Server Error", "status": 500},
                status_code=500,
            )
        response = await call_next(request)
        return response
