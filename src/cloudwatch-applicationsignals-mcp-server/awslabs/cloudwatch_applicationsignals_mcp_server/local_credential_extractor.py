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

"""Local testing: Extract customer credentials from SigV4 request.

⚠️ WARNING: This is for LOCAL TESTING ONLY!
This simulates FAS by extracting credentials from the SigV4 request.
In production, ARC generates FAS credentials - never extract credentials like this.
"""

import base64
import hashlib
import hmac
import os
from datetime import datetime
from typing import Optional

import boto3
from loguru import logger

from .arc_validator import FASCredentials


def extract_credentials_from_sigv4(
    authorization_header: str,
    security_token: Optional[str],
    date_header: str,
    http_method: str,
    uri: str,
    body: bytes,
    host: str,
) -> Optional[FASCredentials]:
    """Extract customer credentials from SigV4 request for local testing.
    
    ⚠️ LOCAL TESTING ONLY - DO NOT USE IN PRODUCTION!
    
    This simulates what ARC+FAS would do by:
    1. Extracting the access key from the Authorization header
    2. Looking up the credentials in the local environment
    3. Verifying the signature matches
    4. Returning credentials in FAS format
    
    In production, ARC validates the signature and generates FAS credentials.
    
    Args:
        authorization_header: Authorization header with SigV4 signature
        security_token: X-Amz-Security-Token (for temporary credentials)
        date_header: X-Amz-Date header
        http_method: HTTP method
        uri: Request URI
        body: Request body
        host: Host header
        
    Returns:
        FASCredentials if validation succeeds, None otherwise
    """
    try:
        logger.warning('⚠️  Using LOCAL credential extraction - NOT for production!')

        # Parse authorization header
        # Format: AWS4-HMAC-SHA256 Credential=AKID/date/region/service/aws4_request, SignedHeaders=..., Signature=...
        parts = {}
        for part in authorization_header.replace('AWS4-HMAC-SHA256 ', '').split(', '):
            key, value = part.split('=', 1)
            parts[key] = value

        credential = parts.get('Credential', '')
        signed_headers = parts.get('SignedHeaders', '')
        provided_signature = parts.get('Signature', '')

        # Extract components
        access_key_id = credential.split('/')[0]
        date_stamp = credential.split('/')[1]
        region = credential.split('/')[2]
        service = credential.split('/')[3]

        logger.info(f'Extracted access key: {access_key_id[:8]}...')
        logger.info(f'Region: {region}, Service: {service}')

        # Try to get credentials from local environment
        # This simulates what the customer's mcp-proxy-for-aws is using
        session = boto3.Session()
        creds = session.get_credentials()

        if not creds:
            logger.error('No AWS credentials found in local environment')
            return None

        # Check if the access key matches
        if creds.access_key != access_key_id:
            logger.warning(
                f'Access key mismatch: request={access_key_id[:8]}..., local={creds.access_key[:8]}...'
            )
            # In local testing, we'll still proceed to simulate FAS
            # In production, ARC would reject this

        # Verify the signature (optional but recommended for testing)
        try:
            # Reconstruct canonical request
            canonical_uri = uri
            canonical_querystring = ''
            canonical_headers = f'host:{host}\nx-amz-date:{date_header}\n'
            if security_token:
                canonical_headers += f'x-amz-security-token:{security_token}\n'

            payload_hash = hashlib.sha256(body).hexdigest()

            canonical_request = (
                f'{http_method}\n'
                f'{canonical_uri}\n'
                f'{canonical_querystring}\n'
                f'{canonical_headers}\n'
                f'{signed_headers}\n'
                f'{payload_hash}'
            )

            # Create string to sign
            algorithm = 'AWS4-HMAC-SHA256'
            credential_scope = f'{date_stamp}/{region}/{service}/aws4_request'
            string_to_sign = (
                f'{algorithm}\n'
                f'{date_header}\n'
                f'{credential_scope}\n'
                f'{hashlib.sha256(canonical_request.encode()).hexdigest()}'
            )

            # Calculate signature
            k_date = hmac.new(
                f'AWS4{creds.secret_key}'.encode(), date_stamp.encode(), hashlib.sha256
            ).digest()
            k_region = hmac.new(k_date, region.encode(), hashlib.sha256).digest()
            k_service = hmac.new(k_region, service.encode(), hashlib.sha256).digest()
            k_signing = hmac.new(k_service, b'aws4_request', hashlib.sha256).digest()
            calculated_signature = hmac.new(
                k_signing, string_to_sign.encode(), hashlib.sha256
            ).hexdigest()

            if calculated_signature == provided_signature:
                logger.info('✅ Signature verified successfully')
            else:
                logger.warning('⚠️  Signature mismatch - proceeding anyway for local testing')

        except Exception as e:
            logger.warning(f'Could not verify signature: {e} - proceeding anyway')

        # Get account ID from STS
        try:
            sts = boto3.client('sts')
            identity = sts.get_caller_identity()
            account_id = identity['Account']
            logger.info(f'Customer account ID: {account_id}')
        except Exception as e:
            logger.warning(f'Could not get account ID: {e}')
            account_id = '123456789012'  # Fallback

        # Return credentials in FAS format
        # In production, these would be temporary FAS credentials from ARC
        # For local testing, we use the customer's actual credentials
        return FASCredentials(
            access_key_id=creds.access_key,
            secret_access_key=creds.secret_key,
            session_token=creds.token if creds.token else '',
            customer_account_id=account_id,
            expiration=datetime.now(),
        )

    except Exception as e:
        logger.error(f'Error extracting credentials from SigV4: {e}')
        return None
