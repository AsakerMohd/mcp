#!/bin/bash

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

# CloudWatch Application Signals MCP Remote Server Startup Script

# Ensure uv is in PATH
export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"

echo "======================================"
echo "CloudWatch Application Signals MCP"
echo "Remote Server Startup"
echo "======================================"
echo ""

# ========================================
# AWS Credentials Configuration
# ========================================
# Option 1: Use explicit AWS credentials (recommended for remote deployment)
export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-}"
export AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-}"
# export AWS_SESSION_TOKEN="${AWS_SESSION_TOKEN:-}"  # Uncomment for temporary credentials

# Option 2: Use AWS Profile (alternative)
# export AWS_PROFILE="your-profile-name"

# Option 3: Use EC2 IAM Role (no credentials needed if running on EC2 with IAM role)
# Just set AWS_REGION and leave AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY unset

# ========================================
# AWS Region
# ========================================
export AWS_REGION="${AWS_REGION:-us-east-1}"

# ========================================
# Server Configuration
# ========================================
export MCP_PORT="${MCP_PORT:-8080}"
export MCP_HOST="${MCP_HOST:-0.0.0.0}"

# ========================================
# Authentication Configuration
# ========================================
# Three authentication modes:
#
# Mode 1: DISABLED (local testing only - NOT for production)
#   export DISABLE_AUTH="true"
#   - No authentication required
#   - Use for local development and testing only
#
# Mode 2: SigV4 Only (default - production ready)
#   unset DISABLE_AUTH
#   unset MCP_API_KEY
#   - AWS SigV4 authentication via aws-mcp-proxy
#   - Recommended for production with agentic IDEs
#
# Mode 3: SigV4 + API Key (dual mode)
#   unset DISABLE_AUTH
#   export MCP_API_KEY="your-secret-key"
#   - Both SigV4 AND API key authentication
#   - Use when you need both aws-mcp-proxy and direct API access
#
export DISABLE_AUTH="${DISABLE_AUTH:-false}"
export MCP_API_KEY="${MCP_API_KEY:-}"

# ========================================
# Logging Configuration
# ========================================
# Options: DEBUG, INFO, WARNING, ERROR
export MCP_CLOUDWATCH_APPLICATIONSIGNALS_LOG_LEVEL="${MCP_CLOUDWATCH_APPLICATIONSIGNALS_LOG_LEVEL:-INFO}"

# ========================================
# Display Configuration
# ========================================
echo "Configuration:"
echo "  AWS Region: $AWS_REGION"
echo "  Server Host: $MCP_HOST"
echo "  Server Port: $MCP_PORT"
echo "  Log Level: $MCP_CLOUDWATCH_APPLICATIONSIGNALS_LOG_LEVEL"

if [ "$DISABLE_AUTH" = "true" ]; then
    echo "  Authentication: ⚠️  DISABLED (local testing only - NOT for production!)"
elif [ -n "$MCP_API_KEY" ]; then
    echo "  Authentication: SigV4 + API Key (dual mode)"
else
    echo "  Authentication: SigV4 only (aws-mcp-proxy compatible)"
fi

if [ -n "$AWS_ACCESS_KEY_ID" ]; then
    echo "  AWS Credentials: Using explicit access keys"
elif [ -n "$AWS_PROFILE" ]; then
    echo "  AWS Credentials: Using profile '$AWS_PROFILE'"
else
    echo "  AWS Credentials: Using default credential chain (IAM role/instance profile)"
fi

echo ""
echo "Server endpoints will be available at:"
echo "  Health Check: http://$MCP_HOST:$MCP_PORT/health"
echo "  Server Info:  http://$MCP_HOST:$MCP_PORT/info"
echo "  MCP Endpoint: http://$MCP_HOST:$MCP_PORT/mcp"
echo ""

# ========================================
# Verify AWS Credentials (Optional)
# ========================================
echo "Verifying AWS credentials..."
if command -v aws &> /dev/null; then
    if aws sts get-caller-identity &> /dev/null; then
        echo "✓ AWS credentials verified successfully"
        aws sts get-caller-identity
        echo ""
    else
        echo "✗ Warning: AWS credentials verification failed"
        echo "  The server may not be able to access AWS services"
        echo ""
    fi
else
    echo "⚠ AWS CLI not found - skipping credential verification"
    echo ""
fi

# ========================================
# Start the Server
# ========================================
echo "Starting MCP Remote Server..."
echo "Press Ctrl+C to stop the server"
echo ""
echo "======================================"
echo ""

# Start the server using uv
uv run python -m awslabs.cloudwatch_applicationsignals_mcp_server.remote_server
