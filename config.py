"""
OAuth Website Configuration
Environment-based configuration for standalone deployment

CLOUDFLARE COMPATIBLE HTTPS PORTS: 443, 2053, 2083, 2087, 2096, 8443
Default port is 8443 for Cloudflare reverse proxy compatibility

NOTE: This website uses MongoDB polling instead of webhooks.
The bot polls the oauth_users collection for new connections (logged: false).
"""

import os

CLIENT_ID = os.environ.get('DISCORD_CLIENT_ID', '1441348516835360870')
CLIENT_SECRET = os.environ.get('DISCORD_CLIENT_SECRET', 'P2SsQVPDlsR2lQ-yquXuoZegNRwFnGRp')
REDIRECT_URI = os.environ.get('OAUTH_REDIRECT_URI', 'https://oauth.yell.rest/callback')
MONGODB_URI = os.environ.get('MONGODB_URI', 'mongodb+srv://botuser:M6MMXbS9AjQfGZW7@primary.puygkcy.mongodb.net/')
PORT = int(os.environ.get('PORT', 8443))

DISCORD_API = "https://discord.com/api/v10"
DISCORD_OAUTH_URL = "https://discord.com/api/oauth2/authorize"
DISCORD_TOKEN_URL = "https://discord.com/api/oauth2/token"

TRUSTED_PROXIES = os.environ.get('TRUSTED_PROXIES', '*')
PROXY_HEADER_HOST = os.environ.get('PROXY_HEADER_HOST', 'X-Forwarded-Host')
PROXY_HEADER_PROTO = os.environ.get('PROXY_HEADER_PROTO', 'X-Forwarded-Proto')
