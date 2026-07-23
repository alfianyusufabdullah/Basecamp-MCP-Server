"""
Flask application for handling the Basecamp 3 OAuth 2.0 authorization flow with Multi-User support.
"""

import os
import sys
import json
import secrets
import logging
from flask import Flask, request, redirect, url_for, session, render_template_string, jsonify
from dotenv import load_dotenv
from basecamp_oauth import BasecampOAuth
from basecamp_client import BasecampClient
from search_utils import BasecampSearch
import token_storage

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("oauth_app.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Check for required environment variables
required_vars = ['BASECAMP_CLIENT_ID', 'BASECAMP_CLIENT_SECRET', 'BASECAMP_REDIRECT_URI', 'USER_AGENT']
missing_vars = [var for var in required_vars if not os.getenv(var)]
if missing_vars:
    logger.error(f"Missing required environment variables: {', '.join(missing_vars)}")
    logger.error("Please set these variables in your .env file or environment")
    sys.exit(1)

# Create Flask app
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', secrets.token_hex(16))

# HTML template for displaying multi-user dashboard
DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Basecamp MCP - Multi-User OAuth Dashboard</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 0; padding: 20px; background: #f8fafc; color: #1e293b; }
        .container { max-width: 900px; margin: 0 auto; background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); }
        h1 { margin-top: 0; color: #0f172a; border-bottom: 2px solid #e2e8f0; padding-bottom: 12px; }
        .user-card { border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; margin-bottom: 16px; display: flex; justify-content: space-between; align-items: center; background: #ffffff; }
        .user-card.default { border-color: #22c55e; background: #f0fdf4; }
        .user-info h3 { margin: 0 0 6px 0; color: #0f172a; font-size: 1.1em; }
        .user-info p { margin: 2px 0; color: #64748b; font-size: 0.9em; }
        .badge { display: inline-block; padding: 3px 8px; border-radius: 9999px; font-size: 0.75em; font-weight: 600; text-transform: uppercase; }
        .badge-default { background: #dcfce7; color: #15803d; }
        .badge-expired { background: #fee2e2; color: #b91c1c; }
        .badge-valid { background: #e0f2fe; color: #0369a1; }
        .button { display: inline-block; background-color: #2563eb; color: white; padding: 8px 16px; text-decoration: none; border-radius: 6px; font-weight: 500; font-size: 0.9em; margin-left: 8px; border: none; cursor: pointer; }
        .button-secondary { background-color: #64748b; }
        .button-danger { background-color: #ef4444; }
        .button-success { background-color: #16a34a; }
        .actions { display: flex; align-items: center; }
        pre { background-color: #0f172a; color: #f8fafc; padding: 12px; border-radius: 6px; overflow-x: auto; font-size: 0.85em; }
        .add-account { margin-top: 24px; padding-top: 20px; border-top: 1px solid #e2e8f0; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Basecamp MCP Multi-User Dashboard</h1>
        
        {% if users %}
            <h2>Authenticated Accounts ({{ users|length }})</h2>
            {% for user in users %}
                <div class="user-card {% if user.is_default %}default{% endif %}">
                    <div class="user-info">
                        <h3>
                            {{ user.name or 'Basecamp User' }} 
                            {% if user.is_default %}
                                <span class="badge badge-default">Active / Default</span>
                            {% endif %}
                            {% if user.is_expired %}
                                <span class="badge badge-expired">Token Expired</span>
                            {% else %}
                                <span class="badge badge-valid">Token Active</span>
                            {% endif %}
                        </h3>
                        <p><strong>User ID / Account ID:</strong> {{ user.user_id }} (Account: {{ user.account_id }})</p>
                        <p><strong>Email:</strong> {{ user.email or 'N/A' }}</p>
                        <p><strong>API Key:</strong> <code>{{ user.api_key }}</code></p>
                    </div>
                    <div class="actions">
                        {% if not user.is_default %}
                            <a href="/switch/{{ user.user_id }}" class="button button-secondary">Set as Default</a>
                        {% endif %}
                        <a href="/logout/{{ user.user_id }}" class="button button-danger" onclick="return confirm('Remove session for this user?')">Remove</a>
                    </div>
                </div>
            {% endfor %}
        {% else %}
            <p>No Basecamp accounts are currently authenticated.</p>
        {% endif %}

        <div class="add-account">
            {% if auth_url %}
                <a href="{{ auth_url }}" class="button button-success" style="font-size: 1.1em; padding: 12px 24px;">➕ Authenticate New Basecamp Account</a>
            {% endif %}
        </div>

        {% if default_user %}
            <h2 style="margin-top: 30px;">🖥️ MCP Client Configuration for Active User ({{ default_user.name or default_user.user_id }})</h2>
            <p>Set <code>BASECAMP_USER_ID</code> environment variable in your client config to route requests to this account:</p>
            <pre>
BASECAMP_USER_ID={{ default_user.user_id }}
BASECAMP_ACCOUNT_ID={{ default_user.account_id }}
            </pre>
        {% endif %}
    </div>
</body>
</html>
"""


def get_oauth_client():
    """Get a configured OAuth client."""
    client_id = os.getenv('BASECAMP_CLIENT_ID')
    client_secret = os.getenv('BASECAMP_CLIENT_SECRET')
    redirect_uri = os.getenv('BASECAMP_REDIRECT_URI')
    user_agent = os.getenv('USER_AGENT')

    return BasecampOAuth(
        client_id=client_id,
        client_secret=client_secret,
        redirect_uri=redirect_uri,
        user_agent=user_agent
    )


@app.route('/')
def home():
    """Multi-User Dashboard."""
    users = token_storage.list_users()
    default_user = token_storage.get_user_token(None)

    auth_url = None
    try:
        oauth_client = get_oauth_client()
        auth_url = oauth_client.get_authorization_url()
    except Exception as e:
        logger.error(f"Error generating auth url: {e}")

    return render_template_string(
        DASHBOARD_TEMPLATE,
        users=users,
        default_user=default_user,
        auth_url=auth_url
    )


@app.route('/switch/<user_id>')
def switch_user(user_id):
    """Switch default active user."""
    token_storage.set_default_user(user_id)
    return redirect(url_for('home'))


@app.route('/logout/<user_id>')
def logout_user(user_id):
    """Remove specific user token."""
    token_storage.remove_user_token(user_id)
    return redirect(url_for('home'))


@app.route('/auth/callback')
def auth_callback():
    """Handle the OAuth callback from Basecamp."""
    logger.info("OAuth callback called with args: %s", request.args)

    code = request.args.get('code')
    error = request.args.get('error')

    if error or not code:
        return redirect(url_for('home'))

    try:
        oauth_client = get_oauth_client()
        token_data = oauth_client.exchange_code_for_token(code)

        access_token = token_data.get('access_token')
        refresh_token = token_data.get('refresh_token')
        expires_in = token_data.get('expires_in')

        if not access_token:
            logger.error("No access token in response")
            return redirect(url_for('home'))

        # Fetch user identity and accounts from Launchpad
        user_id = None
        account_id = os.getenv('BASECAMP_ACCOUNT_ID')
        email = None
        name = None

        try:
            identity = oauth_client.get_identity(access_token)
            logger.info("Identity response: %s", identity)

            user_info = identity.get('identity', {})
            user_id = str(user_info.get('id') or '')
            email = user_info.get('email_address')
            name = f"{user_info.get('first_name', '')} {user_info.get('last_name', '')}".strip()

            # Find first Basecamp 3 account if account_id not set
            if identity.get('accounts'):
                for account in identity['accounts']:
                    if account.get('product') == 'bc3':
                        account_id = str(account['id'])
                        break
        except Exception as e:
            logger.error(f"Error fetching identity: {e}")

        if not user_id:
            user_id = account_id or f"user_{secrets.token_hex(4)}"

        token_storage.store_user_token(
            user_id=user_id,
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=expires_in,
            account_id=account_id,
            email=email,
            name=name,
            set_as_default=True
        )

        logger.info(f"Successfully authenticated user {name} ({user_id})")
        return redirect(url_for('home'))
    except Exception as e:
        logger.error(f"Error in OAuth callback: {e}", exc_info=True)
        return redirect(url_for('home'))


@app.route('/api/users', methods=['GET'])
def get_users_api():
    """API endpoint to list authenticated users."""
    return jsonify({
        "status": "success",
        "users": token_storage.list_users()
    })


@app.route('/health')
def health_check():
    """Health check endpoint."""
    return jsonify({
        "status": "ok",
        "service": "basecamp-oauth-app"
    })


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8000))
    is_debug = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(host='0.0.0.0', port=port, debug=is_debug, use_reloader=is_debug)
