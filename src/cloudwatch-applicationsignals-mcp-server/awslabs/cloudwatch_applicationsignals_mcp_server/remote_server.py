# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""CloudWatch Application Signals MCP Server - Remote Streamable HTTP Server."""

import hashlib
import hmac
import json
import os
import sys
from datetime import datetime
from urllib.parse import quote

import boto3
import uvicorn
from loguru import logger
from mcp.server.sse import SseServerTransport
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route

# Import the FastMCP instance from the existing server
from .arc_validator import FASCredentials, get_arc_validator
from .local_credential_extractor import extract_credentials_from_sigv4
from .server import AWS_REGION, mcp

# Server configuration
PORT = int(os.environ.get("MCP_PORT", 8080))
HOST = os.environ.get("MCP_HOST", "0.0.0.0")

# Authentication configuration
MCP_API_KEY = os.environ.get("MCP_API_KEY")  # Optional API key for simple auth
DISABLE_AUTH = os.environ.get("DISABLE_AUTH", "false").lower() == "true"  # Disable all auth for local testing
USE_ARC = os.environ.get("USE_ARC", "false").lower() == "true"  # Enable ARC validation and FAS credentials
USE_LOCAL_CREDS = os.environ.get("USE_LOCAL_CREDS", "false").lower() == "true"  # Extract customer creds from SigV4 (local testing only)

# SSL/TLS configuration (default to HTTP mode for ALB/CloudFront)
DISABLE_SSL = os.environ.get("DISABLE_SSL", "true").lower() == "true"
SSL_KEYFILE = os.environ.get("SSL_KEYFILE", "/home/ec2-user/ssl/server.key")
SSL_CERTFILE = os.environ.get("SSL_CERTFILE", "/home/ec2-user/ssl/server.crt")

# Logging configuration
log_level = os.environ.get("MCP_CLOUDWATCH_APPLICATIONSIGNALS_LOG_LEVEL", "INFO").upper()

# SigV4 configuration
SERVICE_NAME = "execute-api"  # For API Gateway compatibility
ALGORITHM = "AWS4-HMAC-SHA256"


def verify_sigv4_format(request: Request) -> tuple[bool, str]:
    """Verify AWS SigV4 signature format (basic validation).
    
    Returns:
        tuple: (is_valid, error_message)
    """
    try:
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("AWS4-HMAC-SHA256"):
            return False, "Invalid authorization header format"

        # Parse authorization header
        parts = {}
        for part in auth_header.replace("AWS4-HMAC-SHA256 ", "").split(", "):
            key, value = part.split("=", 1)
            parts[key] = value

        credential = parts.get("Credential", "")
        signed_headers = parts.get("SignedHeaders", "")
        signature = parts.get("Signature", "")

        if not all([credential, signed_headers, signature]):
            return False, "Missing required authorization components"

        access_key_id = credential.split("/")[0]

        # Basic format validation
        if not access_key_id or len(access_key_id) < 16:
            return False, "Invalid access key format"
        
        if not access_key_id.startswith(("AKIA", "ASIA")):
            return False, "Invalid access key prefix"
        
        if not signature or len(signature) != 64:
            return False, "Invalid signature format"
        
        try:
            int(signature, 16)
        except ValueError:
            return False, "Signature must be hexadecimal"
        
        logger.info(f"SigV4 format validated for access key: {access_key_id[:8]}...")
        return True, ""

    except Exception as e:
        logger.error(f"Error parsing SigV4 header: {e}")
        return False, f"Invalid authorization header: {str(e)}"


async def verify_sigv4_with_arc(request: Request) -> tuple[bool, str, Optional[FASCredentials]]:
    """Verify AWS SigV4 signature using ARC and get FAS credentials.
    
    Returns:
        tuple: (is_valid, error_message, fas_credentials)
    """
    try:
        auth_header = request.headers.get("Authorization", "")
        security_token = request.headers.get("X-Amz-Security-Token")
        date_header = request.headers.get("X-Amz-Date", "")
        host = request.headers.get("Host", "")
        
        if not auth_header.startswith("AWS4-HMAC-SHA256"):
            return False, "Invalid authorization header format", None
        
        # Check if using local credential extraction (for testing)
        if USE_LOCAL_CREDS:
            logger.warning("⚠️  Using LOCAL credential extraction - NOT for production!")
            body = await request.body()
            fas_credentials = extract_credentials_from_sigv4(
                authorization_header=auth_header,
                security_token=security_token,
                date_header=date_header,
                http_method=request.method,
                uri=request.url.path,
                body=body,
                host=host
            )
            
            if not fas_credentials:
                return False, "Failed to extract credentials from SigV4", None
            
            logger.info(f"Extracted customer credentials for account: {fas_credentials.customer_account_id}")
            return True, "", fas_credentials
        
        # Use real ARC validation
        arc_validator = get_arc_validator()
        body = await request.body()
        
        fas_credentials = await arc_validator.validate_and_get_fas_credentials(
            authorization_header=auth_header,
            security_token=security_token,
            date_header=date_header,
            http_method=request.method,
            uri=request.url.path,
            body=body,
            headers=dict(request.headers)
        )
        
        if not fas_credentials:
            return False, "SigV4 validation failed", None
        
        logger.info(f"SigV4 validated via ARC for account: {fas_credentials.customer_account_id}")
        return True, "", fas_credentials
        
    except Exception as e:
        logger.error(f"Error validating SigV4 with ARC: {e}")
        return False, f"ARC validation error: {str(e)}", None


async def auth_middleware(request: Request, call_next):
    """Authentication middleware supporting API key, SigV4, and ARC+FAS.
    
    Skips auth for:
    - /health endpoint
    - GET /mcp (SSE handshake)
    - All endpoints when DISABLE_AUTH=true
    
    Supports:
    - API Key: Authorization: Bearer <key> OR X-API-Key: <key>
    - SigV4 (basic): Format validation only
    - SigV4 + ARC: Full validation with FAS credentials (when USE_ARC=true)
    """
    # Skip auth for health check and SSE handshake
    if request.url.path == "/health" or (
        request.url.path == "/mcp" and request.method == "GET"
    ):
        return await call_next(request)
    
    # Skip all auth if disabled (local testing mode)
    if DISABLE_AUTH:
        logger.debug("Authentication disabled - allowing request")
        return await call_next(request)

    auth_header = request.headers.get("Authorization", "")
    
    # Check for SigV4 authentication
    if auth_header.startswith("AWS4-HMAC-SHA256"):
        if USE_ARC:
            # Full ARC validation with FAS credentials
            is_valid, error_msg, fas_credentials = await verify_sigv4_with_arc(request)
            if not is_valid:
                logger.warning(f"ARC validation failed: {error_msg}")
                return JSONResponse(
                    {"error": f"SigV4 authentication failed: {error_msg}"},
                    status_code=401,
                    headers={"WWW-Authenticate": 'AWS4-HMAC-SHA256'},
                )
            # Store FAS credentials in request state for use by handlers
            request.state.fas_credentials = fas_credentials
            logger.info(f"Request authenticated via ARC for account: {fas_credentials.customer_account_id}")
        else:
            # Basic format validation only
            is_valid, error_msg = verify_sigv4_format(request)
            if not is_valid:
                logger.warning(f"SigV4 format validation failed: {error_msg}")
                return JSONResponse(
                    {"error": f"SigV4 authentication failed: {error_msg}"},
                    status_code=401,
                    headers={"WWW-Authenticate": 'AWS4-HMAC-SHA256'},
                )
        # SigV4 valid, proceed
        return await call_next(request)
    
    # Check for API key authentication
    if MCP_API_KEY:
        api_key = request.headers.get("X-API-Key", "")
        provided_key = auth_header.replace("Bearer ", "") if auth_header else api_key

        if not provided_key or provided_key != MCP_API_KEY:
            return JSONResponse(
                {"error": "Invalid or missing authentication credentials"},
                status_code=401,
                headers={"WWW-Authenticate": 'Bearer realm="MCP Server"'},
            )
        # API key valid, proceed
        return await call_next(request)
    
    # No valid authentication provided - reject
    logger.warning(f"Request to {request.url.path} rejected - no valid authentication")
    return JSONResponse(
        {"error": "Authentication required. Provide SigV4 signature or API key."},
        status_code=401,
        headers={"WWW-Authenticate": 'AWS4-HMAC-SHA256'},
    )


async def health_check(request: Request):
    """Health check endpoint for load balancers."""
    return JSONResponse(
        {
            "status": "healthy",
            "service": "cloudwatch-applicationsignals-mcp-server",
            "version": "1.0.0",
            "region": AWS_REGION,
            "transport": "streamable-http",
        }
    )


async def server_info(request: Request):
    """Server information endpoint."""
    return JSONResponse(
        {
            "name": "cloudwatch-applicationsignals-mcp-server",
            "description": "AWS CloudWatch Application Signals MCP Server",
            "version": "1.0.0",
            "transport": "streamable-http",
            "region": AWS_REGION,
            "endpoints": {
                "health": "/health",
                "info": "/info",
                "mcp": "/mcp",
            },
            "authentication": "disabled" if DISABLE_AUTH else ("sigv4+local-creds" if USE_LOCAL_CREDS else ("sigv4+arc+fas" if USE_ARC else ("sigv4+apikey" if MCP_API_KEY else "sigv4"))),
        }
    )


def create_app() -> Starlette:
    """Create the Starlette application with MCP SSE transport."""
    # Create SSE transport
    sse = SseServerTransport("/messages/")

    async def handle_sse_get(scope, receive, send):
        """Handle SSE GET requests for establishing bidirectional connection."""
        logger.info(f"New SSE connection from {scope.get('client')}")
        async with sse.connect_sse(scope, receive, send) as streams:
            await mcp._mcp_server.run(
                streams[0],  # read stream
                streams[1],  # write stream
                mcp._mcp_server.create_initialization_options(),
            )

    async def handle_mcp_post(request: Request):
        """Handle POST requests to /mcp endpoint (stateless mode)."""
        logger.info(f"MCP POST request from {request.client}")

        try:
            body = await request.body()
            message = json.loads(body.decode("utf-8"))

            method = message.get("method")
            params = message.get("params", {})
            request_id = message.get("id")

            if method == "initialize":
                response = {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "protocolVersion": "2025-03-26",
                        "capabilities": {"tools": {}},
                        "serverInfo": {
                            "name": "cloudwatch-applicationsignals-mcp-server",
                            "version": "1.0.0",
                        },
                    },
                }
            elif method == "tools/list":
                tools = await mcp.list_tools()
                tools_list = []
                for tool in tools:
                    tool_dict = tool.model_dump()
                    if "outputSchema" in tool_dict:
                        del tool_dict["outputSchema"]
                    tools_list.append(tool_dict)

                response = {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {"tools": tools_list},
                }
            elif method == "tools/call":
                tool_name = params.get("name")
                tool_args = params.get("arguments", {})
                result = await mcp.call_tool(tool_name, tool_args)

                # Serialize FastMCP result tuple: (content_list, metadata_dict)
                if isinstance(result, tuple) and len(result) == 2:
                    content_list, metadata_dict = result
                    serialized_content = []
                    for content in content_list:
                        if hasattr(content, "model_dump"):
                            serialized_content.append(content.model_dump())
                        else:
                            serialized_content.append(content)

                    result_dict = {
                        "content": serialized_content,
                        "isError": False,
                        **{k: v for k, v in metadata_dict.items() if k != "result"},
                    }
                else:
                    result_dict = result

                response = {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": result_dict,
                }
            else:
                response = {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32601, "message": f"Method not found: {method}"},
                }

            return JSONResponse(response)

        except json.JSONDecodeError as e:
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": "Parse error", "data": str(e)},
                },
                status_code=400,
            )
        except Exception as e:
            logger.error(f"Error processing MCP request: {e}", exc_info=True)
            return JSONResponse(
                {
                    "jsonrpc": "2.0",
                    "id": message.get("id") if "message" in locals() else None,
                    "error": {"code": -32603, "message": "Internal error", "data": str(e)},
                },
                status_code=500,
            )

    async def handle_mcp_endpoint(scope, receive, send):
        """Combined ASGI app for /mcp that routes based on HTTP method."""
        method = scope.get("method", "")

        if method == "GET":
            await handle_sse_get(scope, receive, send)
        elif method == "POST":
            from starlette.requests import Request

            request = Request(scope, receive, send)
            response = await handle_mcp_post(request)
            if response:
                await response(scope, receive, send)
        else:
            from starlette.responses import Response

            response = Response("Method not allowed", status_code=405)
            await response(scope, receive, send)

    # Create Starlette app
    app = Starlette(
        debug=log_level == "DEBUG",
        routes=[
            Route("/health", endpoint=health_check, methods=["GET"]),
            Route("/info", endpoint=server_info, methods=["GET"]),
            Mount("/mcp", app=handle_mcp_endpoint),
            Mount("/messages/", app=sse.handle_post_message),
        ],
    )

    # Add authentication middleware
    app.middleware("http")(auth_middleware)

    return app


def main():
    """Run the remote MCP server."""
    logger.remove()
    logger.add(sys.stderr, level=log_level)

    ssl_enabled = (
        not DISABLE_SSL
        and os.path.exists(SSL_KEYFILE)
        and os.path.exists(SSL_CERTFILE)
    )
    protocol = "https" if ssl_enabled else "http"

    logger.info("Starting CloudWatch Application Signals MCP Remote Server")
    logger.info(f"Server: {HOST}:{PORT}")
    logger.info(f"Region: {AWS_REGION}")
    logger.info(f"Protocol: {protocol.upper()}")
    logger.info("Transport: Streamable HTTP (MCP SSE)")
    if DISABLE_AUTH:
        logger.warning("⚠️  Authentication: DISABLED (local testing only - NOT for production!)")
    elif USE_LOCAL_CREDS:
        logger.warning("⚠️  Authentication: SigV4 + LOCAL credential extraction (testing only - NOT for production!)")
        logger.warning("⚠️  This extracts customer credentials from SigV4 requests to simulate FAS")
    elif USE_ARC:
        logger.info("Authentication: SigV4 + ARC + FAS (production mode with customer impersonation)")
    elif MCP_API_KEY:
        logger.info("Authentication: SigV4 + API Key (dual mode)")
    else:
        logger.info("Authentication: SigV4 only (format validation)")

    if ssl_enabled:
        logger.info("SSL/TLS: enabled")
    else:
        logger.info("SSL/TLS: disabled (HTTP mode for ALB/CloudFront)")

    logger.info("Endpoints:")
    logger.info(f"  Health Check: {protocol}://{HOST}:{PORT}/health")
    logger.info(f"  Server Info: {protocol}://{HOST}:{PORT}/info")
    logger.info(f"  MCP Endpoint: {protocol}://{HOST}:{PORT}/mcp")
    logger.info("")
    logger.info("Client Configuration:")
    logger.info("  aws-mcp-proxy: uvx mcp-proxy-for-aws@latest https://your-server/mcp")
    if MCP_API_KEY:
        logger.info("  API Key: Authorization: Bearer <key> OR X-API-Key: <key>")

    app = create_app()

    try:
        if ssl_enabled:
            uvicorn.run(
                app,
                host=HOST,
                port=PORT,
                log_level=log_level.lower(),
                ssl_keyfile=SSL_KEYFILE,
                ssl_certfile=SSL_CERTFILE,
            )
        else:
            uvicorn.run(app, host=HOST, port=PORT, log_level=log_level.lower())
    except KeyboardInterrupt:
        logger.info("Server shutdown by user")
    except Exception as e:
        logger.error(f"Server error: {e}", exc_info=True)
        raise


if __name__ == "__main__":
    main()
