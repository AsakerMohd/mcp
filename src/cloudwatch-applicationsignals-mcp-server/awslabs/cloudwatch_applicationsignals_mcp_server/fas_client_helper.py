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

"""Helper functions to create AWS clients using FAS credentials."""

import boto3
from botocore.config import Config
from loguru import logger

from .arc_validator import FASCredentials


def create_customer_session(fas_credentials: FASCredentials, region: str) -> boto3.Session:
    """Create boto3 session using FAS credentials.
    
    This session will:
    - Use customer's IAM permissions
    - Consume customer's quotas
    - Log to customer's CloudTrail with MCP context keys
    
    Args:
        fas_credentials: FAS credentials from ARC validation
        region: AWS region
        
    Returns:
        boto3.Session configured with FAS credentials
    """
    logger.info(
        f'Creating customer session for account: {fas_credentials.customer_account_id}'
    )

    return boto3.Session(
        aws_access_key_id=fas_credentials.access_key_id,
        aws_secret_access_key=fas_credentials.secret_access_key,
        aws_session_token=fas_credentials.session_token,
        region_name=region,
    )


def create_customer_clients(fas_credentials: FASCredentials, region: str) -> dict:
    """Create boto3 clients using FAS credentials.
    
    These clients will make AWS API calls on behalf of the customer with:
    - Customer's IAM permissions enforced
    - Customer's quotas consumed
    - CloudTrail logs showing customer as caller with MCP context keys:
      - aws:CalledViaAWSMCP = "true"
      - aws:ViaAWSMCPService = "applicationsignals-mcp.amazonaws.com"
      - aws:IsMcpServiceAction = "true"
    
    Args:
        fas_credentials: FAS credentials from ARC validation
        region: AWS region
        
    Returns:
        Dict of boto3 clients for various AWS services
    """
    session = create_customer_session(fas_credentials, region)

    config = Config(
        user_agent_extra='awslabs.cloudwatch-applicationsignals-mcp-server/0.1.27'
    )

    logger.info(
        f'Creating AWS clients for customer account: {fas_credentials.customer_account_id}'
    )

    return {
        'applicationsignals': session.client('application-signals', config=config),
        'cloudwatch': session.client('cloudwatch', config=config),
        'logs': session.client('logs', config=config),
        'xray': session.client('xray', config=config),
        'synthetics': session.client('synthetics', config=config),
        's3': session.client('s3', config=config),
        'iam': session.client('iam', config=config),
    }
