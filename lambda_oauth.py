"""
YELL OAuth Lambda - Single-file AWS Lambda handler for Discord OAuth2
Handles /callback and /error routes with full CRT/BIOS styling

For direct Discord OAuth flow:
1. Generate OAuth URL: https://discord.com/oauth2/authorize?client_id=YOUR_CLIENT_ID&redirect_uri=YOUR_LAMBDA_URL/callback&response_type=code&scope=identify
2. User clicks the URL, authorizes on Discord
3. Discord redirects to your Lambda /callback endpoint
4. Lambda exchanges code for token, saves user, shows success/error page
"""

import json
import time
import requests
from typing import Optional, Tuple, Any
from urllib.parse import urlencode, parse_qs
from pymongo import MongoClient

CLIENT_ID = '1441348516835360870'
CLIENT_SECRET = 'P2SsQVPDlsR2lQ-yquXuoZegNRwFnGRp'
REDIRECT_URI = 'https://oauth.yell.rest/callback'
MONGODB_URI = 'mongodb+srv://botuser:M6MMXbS9AjQfGZW7@primary.puygkcy.mongodb.net/'

DISCORD_API = 'https://discord.com/api/v10'
DISCORD_TOKEN_URL = 'https://discord.com/api/oauth2/token'
DISCORD_OAUTH_URL = 'https://discord.com/oauth2/authorize'

mongo_client = None
db = None

def get_db():
    global mongo_client, db
    if mongo_client is None:
        mongo_client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=5000)
        db = mongo_client['discord_bot']
    return db

def save_user_to_pool(user_id: int, username: str, discriminator: str, avatar: Optional[str] = None) -> bool:
    try:
        database = get_db()
        if database is None:
            print("MongoDB connection failed")
            return False
        connected_at = int(time.time())
        doc = {
            '_id': user_id,
            'username': username,
            'discriminator': discriminator,
            'avatar': avatar,
            'connected_at': connected_at,
            'logged': False,
            'pulled_guilds': []
        }
        database['oauth_users'].update_one(
            {'_id': user_id},
            {'$set': doc},
            upsert=True
        )
        return True
    except Exception as e:
        print(f"MongoDB error: {e}")
        return False

def exchange_code(code: str) -> Tuple[Optional[dict], Optional[str]]:
    data = {
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': REDIRECT_URI
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    
    try:
        resp = requests.post(DISCORD_TOKEN_URL, data=data, headers=headers, timeout=30)
        if resp.status_code != 200:
            try:
                error_data = resp.json()
                error_msg = error_data.get('error_description', error_data.get('error', 'Unknown error'))
            except:
                error_msg = resp.text[:200]
            return None, f"Token exchange failed ({resp.status_code}): {error_msg}"
        return resp.json(), None
    except requests.Timeout:
        return None, "Token exchange timed out"
    except requests.RequestException as e:
        return None, f"Network error: {str(e)}"

def get_user_info(access_token: str) -> Tuple[Optional[dict], Optional[str]]:
    headers = {'Authorization': f'Bearer {access_token}'}
    
    try:
        resp = requests.get(f"{DISCORD_API}/users/@me", headers=headers, timeout=15)
        if resp.status_code != 200:
            try:
                error_data = resp.json()
                error_msg = error_data.get('message', 'Unknown error')
            except:
                error_msg = resp.text
            return None, f"Failed to fetch user info ({resp.status_code}): {error_msg}"
        return resp.json(), None
    except requests.Timeout:
        return None, "User info request timed out"
    except requests.RequestException as e:
        return None, f"Network error: {str(e)}"

def get_oauth_url():
    params = {
        'client_id': CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'response_type': 'code',
        'scope': 'identify'
    }
    return f"{DISCORD_OAUTH_URL}?{urlencode(params)}"

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>YELL BIOS - Discord OAuth</title>
    <link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap" rel="stylesheet">
    <style>
        @font-face {{
            font-family: 'VT323';
            font-style: normal;
            font-weight: 400;
            font-display: swap;
            src: url('https://fonts.gstatic.com/s/vt323/v17/pxiKyp0ihIEF2isfFJU.woff2') format('woff2');
        }}
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        :root {{
            --primary: #FF3030;
            --primary-bright: #FF5050;
            --primary-dim: #8B0000;
            --primary-glow: rgba(255, 48, 48, 0.4);
            --primary-glow-light: rgba(255, 48, 48, 0.3);
            --primary-glow-subtle: rgba(255, 48, 48, 0.05);
            --primary-glow-faint: rgba(255, 48, 48, 0.02);
            --primary-glow-scan: rgba(255, 48, 48, 0.03);
            --bg: #0a0a0a;
            --bg-panel: rgba(40, 0, 0, 0.85);
            --bg-panel-dark: rgba(32, 0, 0, 0.8);
            --bg-panel-hover: rgba(64, 0, 0, 0.9);
            --success: #00FF00;
            --error: #FF0000;
        }}
        
        html {{
            overflow-x: hidden;
            background-color: var(--bg);
        }}
        
        body {{
            background-color: var(--bg);
            color: var(--primary);
            font-family: "VT323", monospace;
            font-size: 16px;
            line-height: 1.4;
            min-height: 100vh;
            overflow-x: hidden;
            overflow-y: auto;
            position: relative;
            width: 100%;
            max-width: 100vw;
        }}
        
        .crt {{
            position: relative;
            min-height: 100vh;
            overflow: hidden;
            width: 100%;
            max-width: 100vw;
        }}
        
        .crt::before {{
            content: "";
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: repeating-linear-gradient(
                0deg,
                rgba(0, 0, 0, 0.2),
                rgba(0, 0, 0, 0.2) 1px,
                transparent 1px,
                transparent 3px
            );
            pointer-events: none;
            z-index: 1000;
        }}
        
        .crt::after {{
            content: "";
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: 
                radial-gradient(ellipse at center, transparent 0%, transparent 60%, rgba(0,0,0,0.4) 100%),
                var(--primary-glow-faint);
            pointer-events: none;
            z-index: 999;
            animation: flicker 0.15s infinite;
        }}
        
        .screen-glow {{
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            box-shadow: inset 0 0 150px var(--primary-glow-subtle), inset 0 0 80px var(--primary-glow-scan);
            pointer-events: none;
            z-index: 998;
        }}
        
        @media screen and (max-width: 768px) {{
            .screen-glow {{
                box-shadow: none;
                background: radial-gradient(ellipse at center, var(--primary-glow-scan) 0%, transparent 50%);
            }}
        }}
        
        @keyframes flicker {{
            0% {{ opacity: 0.97; }}
            5% {{ opacity: 0.98; }}
            10% {{ opacity: 0.96; }}
            15% {{ opacity: 0.99; }}
            20% {{ opacity: 0.97; }}
            25% {{ opacity: 0.98; }}
            30% {{ opacity: 0.965; }}
            35% {{ opacity: 0.975; }}
            40% {{ opacity: 0.96; }}
            45% {{ opacity: 0.985; }}
            50% {{ opacity: 0.99; }}
            55% {{ opacity: 0.955; }}
            60% {{ opacity: 0.965; }}
            65% {{ opacity: 0.98; }}
            70% {{ opacity: 0.97; }}
            75% {{ opacity: 0.96; }}
            80% {{ opacity: 0.98; }}
            85% {{ opacity: 0.975; }}
            90% {{ opacity: 0.98; }}
            95% {{ opacity: 0.965; }}
            100% {{ opacity: 0.97; }}
        }}
        
        .terminal {{
            text-shadow: 
                0 0 2px var(--primary),
                0 0 5px var(--primary-glow), 
                0 0 10px var(--primary-glow),
                0 0 20px var(--primary-glow),
                0 0 40px var(--primary-glow-faint);
            word-wrap: break-word;
            overflow-wrap: break-word;
        }}
        
        main {{
            padding: 20px;
            padding-bottom: 80px;
            position: relative;
            z-index: 1;
            width: 100%;
            max-width: 100%;
            box-sizing: border-box;
        }}
        
        .bios-header {{
            display: flex;
            justify-content: space-between;
            padding: 10px 15px;
            margin-bottom: 15px;
            background: 
                repeating-linear-gradient(
                    90deg,
                    var(--primary-glow-scan) 0px,
                    var(--primary-glow-scan) 1px,
                    transparent 1px,
                    transparent 3px
                ),
                var(--bg-panel);
            backdrop-filter: blur(4px);
            -webkit-backdrop-filter: blur(4px);
            border: 1px solid var(--primary-dim);
            border-top: 1px solid var(--primary-glow);
            border-bottom: 1px solid var(--bg-panel-dark);
            border-radius: 2px;
            box-shadow: 
                0 2px 10px rgba(0, 0, 0, 0.5),
                inset 0 1px 0 var(--primary-glow-faint),
                inset 0 -1px 0 rgba(0, 0, 0, 0.3);
            color: var(--primary);
        }}
        
        .bios-header span {{
            color: var(--primary);
            text-shadow: 0 0 8px var(--primary-glow);
        }}
        
        .timestamp {{
            font-size: 14px;
            color: var(--primary-bright);
            text-shadow: 0 0 5px var(--primary-glow);
        }}
        
        .cursor {{
            display: inline-block;
            background: var(--primary);
            width: 8px;
            height: 14px;
            animation: blink 1s step-end infinite;
            vertical-align: text-bottom;
            margin-left: 2px;
        }}
        
        @keyframes blink {{
            0%, 50% {{ opacity: 1; }}
            51%, 100% {{ opacity: 0; }}
        }}
        
        .keyboard-hints {{
            position: fixed;
            bottom: 10px;
            left: 10px;
            right: 10px;
            background: 
                repeating-linear-gradient(
                    90deg,
                    var(--primary-glow-faint) 0px,
                    var(--primary-glow-faint) 1px,
                    transparent 1px,
                    transparent 3px
                ),
                var(--bg-panel);
            backdrop-filter: blur(4px);
            -webkit-backdrop-filter: blur(4px);
            border: 1px solid var(--primary-dim);
            border-top: 1px solid var(--primary-glow);
            border-bottom: 1px solid var(--bg-panel-dark);
            border-radius: 2px;
            box-shadow: 
                0 -2px 15px rgba(0, 0, 0, 0.4),
                inset 0 1px 0 var(--primary-glow-faint),
                inset 0 -1px 0 rgba(0, 0, 0, 0.3);
            color: var(--primary);
            padding: 12px 20px;
            display: flex;
            justify-content: center;
            gap: 20px;
            font-size: 14px;
            z-index: 100;
            flex-wrap: wrap;
        }}
        
        .keyboard-hints button {{
            background: var(--bg-panel-dark);
            border: 1px solid var(--primary-dim);
            border-top-color: var(--primary-glow-light);
            border-bottom-color: var(--bg-panel-dark);
            border-radius: 2px;
            color: var(--primary);
            font-family: "VT323", monospace;
            font-size: 14px;
            cursor: pointer;
            text-decoration: none;
            display: flex;
            align-items: center;
            padding: 6px 10px;
            transition: all 0.1s ease;
            box-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);
        }}
        
        .keyboard-hints button:hover {{
            background: var(--bg-panel-hover);
            border-color: var(--primary);
            box-shadow: 0 0 10px var(--primary-glow-light), 0 2px 4px rgba(0, 0, 0, 0.3);
        }}
        
        .key {{
            background: var(--bg-panel-hover);
            color: var(--primary-bright);
            padding: 2px 6px;
            margin-right: 5px;
            border-radius: 2px;
            border: 1px solid var(--primary-dim);
            text-shadow: 0 0 5px var(--primary-glow);
        }}
        
        .ok {{ color: #00FF00; }}
        .fail {{ color: #FF0000; }}
        .dim {{ color: #666666; }}
        .white {{ color: #FFFFFF; }}
        .cyan {{ color: #00FFFF; }}
        .yellow {{ color: var(--primary); }}
        .amber {{ color: var(--primary); }}
        .primary {{ color: var(--primary); }}
        .primary-bright {{ color: var(--primary-bright); }}
        
        @media screen and (max-width: 480px) {{
            body {{ font-size: 10px; }}
            main {{ padding: 8px; padding-bottom: 60px; }}
            .bios-header {{ flex-direction: row; gap: 5px; }}
            .bios-header span:first-child {{ font-size: 9px; }}
            .timestamp {{ font-size: 8px; }}
            .terminal {{ font-size: 11px; line-height: 1.2; }}
            .keyboard-hints {{ padding: 6px 3px; gap: 3px; font-size: 10px; }}
            .keyboard-hints button {{ padding: 6px 4px; font-size: 10px; }}
            .key {{ padding: 1px 3px; margin-right: 2px; font-size: 9px; }}
            .cursor {{ width: 5px; height: 8px; }}
        }}
    </style>
</head>
<body>
    <div class="crt">
        <div class="screen-glow"></div>
        <main>
            {content}
        </main>
        <div class="keyboard-hints">
            <button onclick="showHelp()"><span class="key">F1</span> Help</button>
            <button onclick="window.close()"><span class="key">F10</span> Exit</button>
        </div>
    </div>
    
    <script>
        function updateTimestamp() {{
            const now = new Date();
            const ts = document.getElementById('timestamp');
            if (ts) {{
                ts.textContent = now.toLocaleTimeString('en-US', {{ hour12: false }}) + ' ' + 
                                 now.toLocaleDateString('en-US', {{ year: 'numeric', month: '2-digit', day: '2-digit' }});
            }}
        }}
        setInterval(updateTimestamp, 1000);
        updateTimestamp();
        
        function showHelp() {{
            alert('YELL OAuth System\\n\\nYour Discord account has been processed.\\n\\nYou may close this window.');
        }}
    </script>
    
    {scripts}
</body>
</html>"""

SUCCESS_SEQUENCE = """<span class="amber">╔══════════════════════════════════════════════════════════════════════════════╗</span>
<span class="amber">║</span>                           <span class="white">YELL BIOS v2.0.93</span>                                  <span class="amber">║</span>
<span class="amber">║</span>                         <span class="dim">Copyright (C) 2093 Yell</span>                              <span class="amber">║</span>
<span class="amber">╚══════════════════════════════════════════════════════════════════════════════╝</span>

<span class="yellow">██    ██ ███████ ██      ██     </span>
<span class="yellow"> ██  ██  ██      ██      ██     </span>
<span class="yellow">  ████   █████   ██      ██     </span>
<span class="yellow">   ██    ██      ██      ██     </span>
<span class="yellow">   ██    ███████ ███████ ███████</span>

<span class="white">OAUTH AUTHENTICATION SYSTEM</span>

<span class="dim">Processing Authorization Code.....</span> [<span class="ok">████████████████████</span>] <span class="white">100%</span>
<span class="dim">Exchanging Token..................</span> [<span class="ok">████████████████████</span>] <span class="cyan">OK</span>
<span class="dim">Fetching User Data................</span> [<span class="ok">████████████████████</span>] <span class="cyan">OK</span>
<span class="dim">Saving to Global Pool.............</span> [<span class="ok">████████████████████</span>] <span class="cyan">OK</span>

<span class="ok">╔══════════════════════════════════════════════════════════════════════════════╗</span>
<span class="ok">║</span>                      <span class="ok">█ AUTHENTICATION SUCCESSFUL █</span>                         <span class="ok">║</span>
<span class="ok">╚══════════════════════════════════════════════════════════════════════════════╝</span>

  <span class="dim">Discord ID..........</span> <span class="cyan">{user_id}</span>
  <span class="dim">Username............</span> <span class="white">{username}</span>
  <span class="dim">Status..............</span> <span class="cyan">VERIFIED ■</span>
  <span class="dim">Pool Status.........</span> <span class="cyan">LINKED</span>

<span class="amber">╔══════════════════════════════════════════════════════════════════════════════╗</span>
<span class="amber">║</span>  <span class="white">Account successfully linked to global user pool.</span>                            <span class="amber">║</span>
<span class="amber">║</span>  <span class="dim">You may now close this window.</span>                                              <span class="amber">║</span>
<span class="amber">╚══════════════════════════════════════════════════════════════════════════════╝</span>

<span class="dim">C:\\YELL\\OAUTH></span><span class="cursor"></span>"""

ERROR_SEQUENCE = """<span class="amber">╔══════════════════════════════════════════════════════════════════════════════╗</span>
<span class="amber">║</span>                           <span class="white">YELL BIOS v2.0.93</span>                                  <span class="amber">║</span>
<span class="amber">║</span>                         <span class="dim">Copyright (C) 2093 Yell</span>                              <span class="amber">║</span>
<span class="amber">╚══════════════════════════════════════════════════════════════════════════════╝</span>

<span class="yellow">██    ██ ███████ ██      ██     </span>
<span class="yellow"> ██  ██  ██      ██      ██     </span>
<span class="yellow">  ████   █████   ██      ██     </span>
<span class="yellow">   ██    ██      ██      ██     </span>
<span class="yellow">   ██    ███████ ███████ ███████</span>

<span class="white">OAUTH AUTHENTICATION SYSTEM</span>

<span class="dim">Processing Authorization...........</span> [<span class="fail">████████</span><span class="dim">░░░░░░░░░░░░</span>] <span class="fail">FAILED</span>

<span class="fail">╔══════════════════════════════════════════════════════════════════════════════╗</span>
<span class="fail">║</span>                      <span class="fail">█ AUTHENTICATION FAILED █</span>                            <span class="fail">║</span>
<span class="fail">╚══════════════════════════════════════════════════════════════════════════════╝</span>

  <span class="dim">Error Code..........</span> <span class="fail">ERR 0x{error_hex}: {error_code}</span>
  <span class="dim">Description.........</span> <span class="cyan">{error_message}</span>
  <span class="dim">Timestamp...........</span> <span class="cyan">{timestamp}</span>

<span class="amber">╔══════════════════════════════════════════════════════════════════════════════╗</span>
<span class="amber">║</span>  <span class="cyan">Authorization failed. Please try again.</span>                                     <span class="amber">║</span>
<span class="amber">║</span>  <span class="dim">Press F1 for help or contact</span> <span class="cyan">speak@yell.rest</span>                                <span class="amber">║</span>
<span class="amber">╚══════════════════════════════════════════════════════════════════════════════╝</span>

<span class="dim">C:\\YELL\\OAUTH></span><span class="cursor"></span>"""

TYPEWRITER_SCRIPT = """
<script>
    const container = document.getElementById('terminal-text');
    const originalHTML = container.innerHTML;
    const lines = originalHTML.split('\\n');
    container.innerHTML = '';
    
    let lineIndex = 0;
    
    function renderNextLine() {
        if (lineIndex < lines.length) {
            container.innerHTML += lines[lineIndex] + '\\n';
            lineIndex++;
            setTimeout(renderNextLine, 45);
        }
    }
    
    renderNextLine();
</script>
"""

def render_success(user_id: int, username: str):
    success_text = SUCCESS_SEQUENCE.format(user_id=user_id, username=username)
    
    content = f"""
        <div class="bios-header">
            <span>YELL BIOS SETUP UTILITY</span>
            <span class="timestamp" id="timestamp"></span>
        </div>
        <div class="terminal">
            <pre id="terminal-text">{success_text}</pre>
        </div>
    """
    
    return HTML_TEMPLATE.format(content=content, scripts=TYPEWRITER_SCRIPT)

def render_error(error_code: str, error_message: str):
    error_hex = format(hash(error_code) % 0xFFFF, '04X')
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    
    error_text = ERROR_SEQUENCE.format(
        error_code=error_code,
        error_message=error_message,
        error_hex=error_hex,
        timestamp=timestamp
    )
    
    content = f"""
        <div class="bios-header">
            <span>YELL BIOS SETUP UTILITY</span>
            <span class="timestamp" id="timestamp"></span>
        </div>
        <div class="terminal">
            <pre id="terminal-text">{error_text}</pre>
        </div>
    """
    
    return HTML_TEMPLATE.format(content=content, scripts=TYPEWRITER_SCRIPT)

def html_response(body: str, status_code: int = 200):
    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'text/html; charset=utf-8',
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'SAMEORIGIN',
            'X-XSS-Protection': '1; mode=block'
        },
        'body': body
    }

def handle_callback(query_params: dict):
    code = query_params.get('code', [None])[0]
    error = query_params.get('error', [None])[0]
    
    if error:
        error_desc = query_params.get('error_description', ['Authorization was denied.'])[0]
        return html_response(render_error(error.upper(), error_desc))
    
    if not code:
        return html_response(render_error("NO_CODE", "No authorization code received."))
    
    token_data, err = exchange_code(code)
    if err or token_data is None:
        return html_response(render_error("TOKEN_ERROR", err or "Token exchange failed"))
    
    access_token = token_data.get('access_token')
    if not access_token:
        return html_response(render_error("NO_TOKEN", "No access token in response."))
    
    user_data, err = get_user_info(access_token)
    if err or user_data is None:
        return html_response(render_error("USER_ERROR", err or "Failed to fetch user data"))
    
    user_id = int(user_data['id'])
    username = user_data['username']
    discriminator = user_data.get('discriminator', '0')
    avatar = user_data.get('avatar')
    
    save_user_to_pool(user_id, username, discriminator, avatar)
    
    display_name = f"{username}#{discriminator}" if discriminator != '0' else username
    
    return html_response(render_success(user_id, display_name))

def handle_error(query_params: dict):
    error_code = query_params.get('code', ['AUTH_FAILED'])[0]
    error_message = query_params.get('message', ['Authorization was denied or expired.'])[0]
    return html_response(render_error(error_code, error_message))

def lambda_handler(event, context):
    """
    AWS Lambda handler for API Gateway events.
    Supports both REST API and HTTP API event formats.
    """
    path = event.get('path') or event.get('rawPath', '/')
    
    if event.get('queryStringParameters'):
        query_params = {k: [v] for k, v in event['queryStringParameters'].items()}
    elif event.get('rawQueryString'):
        query_params = parse_qs(event['rawQueryString'])
    else:
        query_params = {}
    
    if path == '/callback':
        return handle_callback(query_params)
    elif path == '/error':
        return handle_error(query_params)
    elif path == '/health':
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({
                'status': 'ok',
                'timestamp': int(time.time()),
                'service': 'oauth-lambda'
            })
        }
    elif path == '/oauth-url':
        return {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({
                'oauth_url': get_oauth_url()
            })
        }
    else:
        return {
            'statusCode': 404,
            'headers': {'Content-Type': 'application/json'},
            'body': json.dumps({'error': 'Not found', 'available_routes': ['/callback', '/error', '/health', '/oauth-url']})
        }
