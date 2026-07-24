"""
Flask application for handling the Basecamp 3 OAuth 2.0 authorization flow.
Styled with modern Shadcn UI aesthetics and single active-user profile view.
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

# Modern Shadcn UI Template
SHADCN_DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html lang="en" class="h-full bg-slate-950 text-slate-100 dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Basecamp MCP Server - Authentication</title>
    <!-- Tailwind CSS CDN -->
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    colors: {
                        border: 'hsl(217.2 32.6% 17.5%)',
                        input: 'hsl(217.2 32.6% 17.5%)',
                        ring: 'hsl(224.3 76.3% 48%)',
                        background: 'hsl(222.2 84% 4.9%)',
                        foreground: 'hsl(210 40% 98%)',
                        primary: {
                            DEFAULT: 'hsl(217.2 91.2% 59.8%)',
                            foreground: 'hsl(222.2 47.4% 11.2%)'
                        },
                        secondary: {
                            DEFAULT: 'hsl(217.2 32.6% 17.5%)',
                            foreground: 'hsl(210 40% 98%)'
                        },
                        destructive: {
                            DEFAULT: 'hsl(0 62.8% 30.6%)',
                            foreground: 'hsl(210 40% 98%)'
                        },
                        muted: {
                            DEFAULT: 'hsl(217.2 32.6% 17.5%)',
                            foreground: 'hsl(215 20.2% 65.1%)'
                        },
                        accent: {
                            DEFAULT: 'hsl(217.2 32.6% 17.5%)',
                            foreground: 'hsl(210 40% 98%)'
                        },
                        card: {
                            DEFAULT: 'hsl(222.2 84% 4.9%)',
                            foreground: 'hsl(210 40% 98%)'
                        }
                    }
                }
            }
        }
    </script>
    <!-- Google Fonts Inter -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        body { font-family: 'Inter', sans-serif; }
        code, pre { font-family: 'JetBrains Mono', monospace; }
    </style>
</head>
<body class="min-h-full flex flex-col justify-center py-12 px-4 sm:px-6 lg:px-8 bg-slate-950 text-slate-100 antialiased">
    <!-- Toast Notification -->
    <div id="toast" class="fixed bottom-5 right-5 z-50 transform translate-y-20 opacity-0 transition-all duration-300 ease-in-out bg-emerald-600 text-white px-4 py-3 rounded-lg shadow-xl flex items-center gap-2 border border-emerald-500">
        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path></svg>
        <span id="toast-message" class="text-sm font-medium">Copied to clipboard!</span>
    </div>

    <div class="sm:mx-auto sm:w-full sm:max-w-2xl">
        <!-- Logo & Header -->
        <div class="flex justify-center items-center gap-3 mb-6">
            <div class="w-12 h-12 rounded-xl bg-gradient-to-tr from-emerald-500 to-teal-400 flex items-center justify-center shadow-lg shadow-emerald-500/20 ring-1 ring-white/20">
                <svg class="w-7 h-7 text-slate-950" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"></path></svg>
            </div>
            <div>
                <h2 class="text-2xl font-bold tracking-tight text-white">Basecamp MCP Server</h2>
                <p class="text-xs text-slate-400 font-mono">Model Context Protocol • 79 Tools</p>
            </div>
        </div>

        {% if current_user %}
        <!-- LOGGED IN USER CARD -->
        <div class="bg-slate-900/80 backdrop-blur-xl border border-slate-800 rounded-2xl shadow-2xl p-6 sm:p-8 space-y-6">
            
            <!-- User Header Row -->
            <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-slate-800">
                <div class="flex items-center gap-4">
                    <!-- Avatar Initials -->
                    <div class="w-14 h-14 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-xl font-bold text-emerald-400 shadow-inner">
                        {{ (current_user.name or current_user.email or 'U')[:2]|upper }}
                    </div>
                    <div>
                        <div class="flex items-center gap-2">
                            <h3 class="text-xl font-semibold text-white tracking-tight">{{ current_user.name or 'Basecamp User' }}</h3>
                            <span class="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                                <span class="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span> Active Session
                            </span>
                        </div>
                        <p class="text-sm text-slate-400 mt-0.5">{{ current_user.email or 'No email recorded' }}</p>
                    </div>
                </div>

                <div class="flex items-center gap-2">
                    {% if all_users|length > 1 %}
                        <!-- Switch Account Dropdown Button -->
                        <div class="relative group">
                            <button class="px-3 py-1.5 text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg border border-slate-700 transition flex items-center gap-1.5">
                                <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4"></path></svg>
                                Switch Account ({{ all_users|length }})
                            </button>
                            <div class="absolute right-0 mt-2 w-56 bg-slate-900 border border-slate-800 rounded-xl shadow-xl py-2 hidden group-hover:block z-50">
                                <div class="px-3 py-1 text-[10px] font-semibold text-slate-400 uppercase tracking-wider">Switch Active Profile</div>
                                {% for u in all_users %}
                                    <a href="/switch/{{ u.user_id }}" class="px-3 py-2 text-xs flex items-center justify-between hover:bg-slate-800 text-slate-300 hover:text-white transition">
                                        <span class="truncate">{{ u.name or u.email }}</span>
                                        {% if u.user_id == current_user.user_id %}
                                            <span class="text-emerald-400">✓</span>
                                        {% endif %}
                                    </a>
                                {% endfor %}
                            </div>
                        </div>
                    {% endif %}
                    <a href="/logout" class="px-3 py-1.5 text-xs font-medium bg-red-500/10 hover:bg-red-500/20 text-red-400 rounded-lg border border-red-500/20 transition flex items-center gap-1.5">
                        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"></path></svg>
                        Sign Out
                    </a>
                </div>
            </div>

            <!-- Details Grid -->
            <div class="grid grid-cols-2 sm:grid-cols-3 gap-4">
                <div class="bg-slate-950/60 border border-slate-800/80 rounded-xl p-3">
                    <span class="text-[11px] font-medium text-slate-500 uppercase tracking-wider">User ID</span>
                    <p class="text-sm font-semibold text-slate-200 mt-1 font-mono">{{ current_user.user_id }}</p>
                </div>
                <div class="bg-slate-950/60 border border-slate-800/80 rounded-xl p-3">
                    <span class="text-[11px] font-medium text-slate-500 uppercase tracking-wider">Account ID</span>
                    <p class="text-sm font-semibold text-slate-200 mt-1 font-mono">{{ current_user.account_id or 'Auto' }}</p>
                </div>
                <div class="bg-slate-950/60 border border-slate-800/80 rounded-xl p-3 col-span-2 sm:col-span-1">
                    <span class="text-[11px] font-medium text-slate-500 uppercase tracking-wider">Storage Mode</span>
                    <p class="text-sm font-semibold text-emerald-400 mt-1 flex items-center gap-1.5">
                        <svg class="w-4 h-4 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path></svg>
                        AES-Encrypted
                    </p>
                </div>
            </div>

            <!-- Secret MCP API Key Card -->
            <div class="bg-slate-950 border border-slate-800 rounded-xl p-4 space-y-2">
                <div class="flex items-center justify-between">
                    <label class="text-xs font-semibold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                        <svg class="w-4 h-4 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 0121 9z"></path></svg>
                        Secret MCP API Key
                    </label>
                    <button onclick="toggleApiKey()" id="toggle-btn" class="text-xs text-slate-400 hover:text-slate-200 transition">Show Key</button>
                </div>
                <div class="flex items-center gap-2">
                    <input type="password" id="api-key-input" readonly value="{{ current_user.api_key }}" class="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-emerald-400 focus:outline-none focus:ring-1 focus:ring-emerald-500">
                    <button onclick="copyText('{{ current_user.api_key }}', 'Secret API Key copied!')" class="px-3 py-2 bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-semibold text-xs rounded-lg transition flex items-center gap-1 shrink-0">
                        <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path></svg>
                        Copy
                    </button>
                </div>
            </div>

            <!-- One-Click Configuration Snippets -->
            <div class="space-y-3 pt-2">
                <h4 class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Fast MCP Setup Snippets</h4>

                <!-- Tab Buttons -->
                <div class="flex gap-2 border-b border-slate-800 pb-2">
                    <button onclick="switchTab('claude-cli')" id="tab-claude-cli" class="tab-btn px-3 py-1 text-xs font-medium text-emerald-400 border-b-2 border-emerald-400">Claude CLI</button>
                    <button onclick="switchTab('claude-desktop')" id="tab-claude-desktop" class="tab-btn px-3 py-1 text-xs font-medium text-slate-400 hover:text-slate-200">Claude Desktop</button>
                    <button onclick="switchTab('docker-env')" id="tab-docker-env" class="tab-btn px-3 py-1 text-xs font-medium text-slate-400 hover:text-slate-200">Docker / Env</button>
                </div>

                <!-- Tab Contents -->
                <div id="content-claude-cli" class="tab-content relative">
                    <pre class="bg-slate-950 p-3 rounded-lg text-xs text-slate-300 overflow-x-auto border border-slate-800 font-mono">claude mcp add basecamp --transport sse "{{ mcp_server_url }}/sse?api_key={{ current_user.api_key }}"</pre>
                    <button onclick="copyText('claude mcp add basecamp --transport sse &quot;{{ mcp_server_url }}/sse?api_key={{ current_user.api_key }}&quot;', 'Claude CLI command copied!')" class="absolute top-2 right-2 px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-[10px] font-medium border border-slate-700">Copy</button>
                </div>

                <div id="content-claude-desktop" class="tab-content hidden relative">
                    <pre class="bg-slate-950 p-3 rounded-lg text-xs text-slate-300 overflow-x-auto border border-slate-800 font-mono">{
  "mcpServers": {
    "basecamp": {
      "url": "{{ mcp_server_url }}/sse?api_key={{ current_user.api_key }}"
    }
  }
}</pre>
                    <button onclick="copyText('{\n  &quot;mcpServers&quot;: {\n    &quot;basecamp&quot;: {\n      &quot;url&quot;: &quot;{{ mcp_server_url }}/sse?api_key={{ current_user.api_key }}&quot;\n    }\n  }\n}', 'Claude Desktop config copied!')" class="absolute top-2 right-2 px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-[10px] font-medium border border-slate-700">Copy</button>
                </div>

                <div id="content-docker-env" class="tab-content hidden relative">
                    <pre class="bg-slate-950 p-3 rounded-lg text-xs text-slate-300 overflow-x-auto border border-slate-800 font-mono">BASECAMP_API_KEY={{ current_user.api_key }}
BASECAMP_ACCOUNT_ID={{ current_user.account_id }}</pre>
                    <button onclick="copyText('BASECAMP_API_KEY={{ current_user.api_key }}\nBASECAMP_ACCOUNT_ID={{ current_user.account_id }}', 'Environment snippet copied!')" class="absolute top-2 right-2 px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-[10px] font-medium border border-slate-700">Copy</button>
                </div>
            </div>

            <!-- Footer Action -->
            <div class="pt-4 border-t border-slate-800/80 flex justify-between items-center text-xs text-slate-400">
                <span>Logged in as <strong class="text-slate-200">{{ current_user.name or current_user.user_id }}</strong></span>
                {% if auth_url %}
                    <a href="{{ auth_url }}" class="text-emerald-400 hover:underline flex items-center gap-1">
                        ➕ Connect Another Account
                    </a>
                {% endif %}
            </div>
        </div>

        {% else %}
        <!-- NOT LOGGED IN HERO CARD -->
        <div class="bg-slate-900/80 backdrop-blur-xl border border-slate-800 rounded-2xl shadow-2xl p-8 text-center space-y-6">
            <div class="max-w-md mx-auto space-y-3">
                <h3 class="text-xl font-bold text-white tracking-tight">Connect Your Basecamp 3 Account</h3>
                <p class="text-sm text-slate-400">Authenticate with Basecamp 3 to enable LLM assistants (Cursor, Claude Desktop, Claude CLI) to manage your projects, todos, and messages.</p>
            </div>

            <div class="py-4">
                {% if auth_url %}
                    <a href="{{ auth_url }}" class="inline-flex items-center gap-2 px-6 py-3.5 bg-gradient-to-r from-emerald-500 to-teal-500 hover:from-emerald-400 hover:to-teal-400 text-slate-950 font-bold text-base rounded-xl shadow-lg shadow-emerald-500/25 transition transform hover:-translate-y-0.5">
                        <svg class="w-5 h-5 text-slate-950" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M11 16l-4-4m0 0l4-4m-4 4h14m-5 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h7a3 3 0 013 3v1"></path></svg>
                        Connect Basecamp Account
                    </a>
                {% else %}
                    <p class="text-sm text-red-400 bg-red-500/10 p-3 rounded-lg border border-red-500/20">Missing OAuth credentials in <code>.env</code> file.</p>
                {% endif %}
            </div>

            <div class="grid grid-cols-3 gap-3 pt-6 border-t border-slate-800 text-left">
                <div class="p-3 bg-slate-950/40 rounded-xl border border-slate-800/60">
                    <p class="text-xs font-semibold text-slate-200">79 MCP Tools</p>
                    <p class="text-[11px] text-slate-400 mt-0.5">Full CRUD for Todos, Cards, Messages & Vault</p>
                </div>
                <div class="p-3 bg-slate-950/40 rounded-xl border border-slate-800/60">
                    <p class="text-xs font-semibold text-slate-200">AES Encrypted</p>
                    <p class="text-[11px] text-slate-400 mt-0.5">Tokens encrypted at rest via Fernet/Redis</p>
                </div>
                <div class="p-3 bg-slate-950/40 rounded-xl border border-slate-800/60">
                    <p class="text-xs font-semibold text-slate-200">Multi-User Ready</p>
                    <p class="text-[11px] text-slate-400 mt-0.5">Isolated sessions via secret API keys</p>
                </div>
            </div>
        </div>
        {% endif %}

        <div class="mt-8 text-center text-xs text-slate-500 font-mono">
            Basecamp 3 MCP Server v1.2 • Anthropic FastMCP Framework
        </div>
    </div>

    <!-- Interactive Scripts -->
    <script>
        function copyText(text, message) {
            navigator.clipboard.writeText(text).then(() => {
                showToast(message || 'Copied to clipboard!');
            }).catch(err => {
                console.error('Failed to copy: ', err);
            });
        }

        function showToast(message) {
            const toast = document.getElementById('toast');
            const toastMsg = document.getElementById('toast-message');
            toastMsg.innerText = message;
            toast.classList.remove('translate-y-20', 'opacity-0');
            toast.classList.add('translate-y-0', 'opacity-100');
            setTimeout(() => {
                toast.classList.remove('translate-y-0', 'opacity-100');
                toast.classList.add('translate-y-20', 'opacity-0');
            }, 2500);
        }

        function toggleApiKey() {
            const input = document.getElementById('api-key-input');
            const btn = document.getElementById('toggle-btn');
            if (input.type === 'password') {
                input.type = 'text';
                btn.innerText = 'Hide Key';
            } else {
                input.type = 'password';
                btn.innerText = 'Show Key';
            }
        }

        function switchTab(tabId) {
            document.querySelectorAll('.tab-content').forEach(el => el.classList.add('hidden'));
            document.querySelectorAll('.tab-btn').forEach(el => {
                el.classList.remove('text-emerald-400', 'border-b-2', 'border-emerald-400');
                el.classList.add('text-slate-400');
            });

            document.getElementById('content-' + tabId).classList.remove('hidden');
            const btn = document.getElementById('tab-' + tabId);
            btn.classList.remove('text-slate-400');
            btn.classList.add('text-emerald-400', 'border-b-2', 'border-emerald-400');
        }
    </script>
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
    """Shadcn UI Active Profile Dashboard with strict per-browser session isolation."""
    user_id_in_session = session.get('user_id')
    current_user = None
    if user_id_in_session:
        current_user = token_storage.get_user_token(user_id_in_session)

    all_users = token_storage.list_users() if current_user else []

    auth_url = None
    try:
        oauth_client = get_oauth_client()
        auth_url = oauth_client.get_authorization_url()
    except Exception as e:
        logger.error(f"Error generating auth url: {e}")

    mcp_server_url = (
        os.getenv('BASECAMP_MCP_SERVER_URL') or
        os.getenv('MCP_SERVER_URL') or
        'http://localhost:8001'
    ).rstrip('/')

    return render_template_string(
        SHADCN_DASHBOARD_TEMPLATE,
        current_user=current_user,
        all_users=all_users,
        auth_url=auth_url,
        mcp_server_url=mcp_server_url
    )


@app.route('/switch/<user_id>')
def switch_user(user_id):
    """Switch active user profile in session."""
    user_id = str(user_id)
    if token_storage.get_user_token(user_id):
        session['user_id'] = user_id
    return redirect(url_for('home'))


@app.route('/logout')
def logout():
    """Log out active browser session."""
    user_id = session.pop('user_id', None)
    if user_id:
        token_storage.remove_user_token(user_id)
    return redirect(url_for('home'))


@app.route('/logout/<user_id>')
def logout_user(user_id):
    """Remove specific user token."""
    user_id = str(user_id)
    if session.get('user_id') == user_id:
        session.pop('user_id', None)
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

        session['user_id'] = user_id
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
