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

"""AWS AuthRuntime Client (ARC) integration for SigV4 validation and FAS credentials."""

import os
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from loguru import logger


@dataclass
class FASCredentials:
    """Forward Access Session credentials for customer impersonation."""

    access_key_id: str
    secret_access_key: str
    session_token: str
    customer_account_id: str
    expiration: datetime


class ARCValidator:
    """Validates SigV4 signatures using AWS AuthRuntime Client (ARC).
    
    This class integrates with ARC to:
    1. Validate customer SigV4 signatures
    2. Extract customer identity (account ID, principal)
    3. Generate Forward Access Session (FAS) credentials
    4. Enable AWS API calls on behalf of customers
    """

    def __init__(self, service_principal: str):
        """Initialize ARC validator.
        
        Args:
            service_principal: MCP service principal (must end with -mcp)
                             Example: 'applicationsignals-mcp.amazonaws.com'
        """
        if not service_principal.endswith('-mcp.amazonaws.com'):
            raise ValueError(
                f'Service principal must end with -mcp.amazonaws.com, got: {service_principal}'
            )

        self.service_principal = service_principal
        self._arc_client = None
        logger.info(f'ARC validator initialized with service principal: {service_principal}')

    def _get_arc_client(self):
        """Lazy load ARC client.
        
        Note: This is a placeholder for actual ARC integration.
        In production, this would import and initialize the real ARC client.
        """
        if self._arc_client is None:
            # TODO: Replace with actual ARC client initialization
            # from aws_auth_runtime import AuthRuntimeClient
            # self._arc_client = AuthRuntimeClient(
            #     service_principal=self.service_principal
            # )
            logger.warning('ARC client not available - using mock validation')
            self._arc_client = 'mock'  # Placeholder
        return self._arc_client

    async def validate_and_get_fas_credentials(
        self,
        authorization_header: str,
        security_token: Optional[str],
        date_header: str,
        http_method: str,
        uri: str,
        body: bytes,
        headers: dict,
    ) -> Optional[FASCredentials]:
        """Validate SigV4 signature and generate FAS credentials.
        
        Args:
            authorization_header: Authorization header with SigV4 signature
            security_token: X-Amz-Security-Token header (for temporary credentials)
            date_header: X-Amz-Date header
            http_method: HTTP method (GET, POST, etc.)
            uri: Request URI path
            body: Request body bytes
            headers: All request headers
            
        Returns:
            FASCredentials if validation succeeds, None otherwise
        """
        try:
            # Parse authorization header to extract access key
            if not authorization_header.startswith('AWS4-HMAC-SHA256'):
                logger.warning('Invalid authorization header format')
                return None

            # Extract credential from header
            # Format: AWS4-HMAC-SHA256 Credential=AKID/date/region/service/aws4_request, ...
            parts = {}
            for part in authorization_header.replace('AWS4-HMAC-SHA256 ', '').split(', '):
                key, value = part.split('=', 1)
                parts[key] = value

            credential = parts.get('Credential', '')
            access_key_id = credential.split('/')[0]

            # TODO: Replace with actual ARC validation
            # arc_client = self._get_arc_client()
            # auth_result = await arc_client.authenticate(
            #     authorization_header=authorization_header,
            #     security_token=security_token,
            #     date=date_header,
            #     http_method=http_method,
            #     uri=uri,
            #     body=body,
            #     headers=headers
            # )
            #
            # if not auth_result.is_authenticated:
            #     logger.warning('SigV4 validation failed')
            #     return None
            #
            # # ARC automatically generates FAS credentials
            # fas_creds = auth_result.forward_access_credentials
            #
            # return FASCredentials(
            #     access_key_id=fas_creds.access_key_id,
            #     secret_access_key=fas_creds.secret_access_key,
            #     session_token=fas_creds.session_token,
            #     customer_account_id=auth_result.account_id,
            #     expiration=fas_creds.expiration
            # )

            # MOCK IMPLEMENTATION - For testing only
            # In production, this would be replaced with actual ARC validation
            logger.warning('Using MOCK FAS credentials - replace with ARC in production')

            # Basic format validation
            if not access_key_id or len(access_key_id) < 16:
                return None

            if not access_key_id.startswith(('AKIA', 'ASIA')):
                return None

            # Return mock FAS credentials
            # In production, these would come from ARC
            return FASCredentials(
                access_key_id='ASIA' + 'X' * 16,  # Mock temporary credentials
                secret_access_key='mock_secret_key',
                session_token='mock_session_token',
                customer_account_id='123456789012',  # Mock account ID
                expiration=datetime.now(),
            )

        except Exception as e:
            logger.error(f'Error validating SigV4 with ARC: {e}')
            return None


# Singleton instance
_arc_validator: Optional[ARCValidator] = None


def get_arc_validator() -> ARCValidator:
    """Get or create the ARC validator singleton.
    
    Returns:
        ARCValidator instance
    """
    global _arc_validator
    if _arc_validator is None:
        service_principal = os.environ.get(
            'MCP_SERVICE_PRINCIPAL', 'applicationsignals-mcp.amazonaws.com'
        )
        _arc_validator = ARCValidator(service_principal)
    return _arc_validator
