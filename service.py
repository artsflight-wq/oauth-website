"""
YELL OAuth Website - Standalone Service (AWS Optimized)
Complete Discord OAuth2 implementation with BIOS/Terminal styling
Optimized for AWS ALB/ELB, ECS, and Lambda deployments

DEPLOYMENT:
1. Copy this file and config.py to your server
2. Set environment variables:
   - DISCORD_CLIENT_ID: Your Discord application client ID
   - DISCORD_CLIENT_SECRET: Your Discord application client secret
   - OAUTH_REDIRECT_URI: Full callback URL (e.g., https://oauth.yell.rest/callback)
   - MONGODB_URI: MongoDB connection string
   - PORT: Server port (default: 5000)
3. Run: python service.py

AWS OPTIMIZATIONS:
- uvloop for high-performance async event loop
- Gzip compression for reduced bandwidth
- Optimized MongoDB connection pooling with TLS
- HSTS and CSP security headers for HTTPS deployments
- Structured JSON logging for CloudWatch integration
- Graceful shutdown handling for ECS/container deployments
- AWS ALB/ELB health check support
"""

import asyncio
import aiohttp
from aiohttp import web
import time
import json
import logging
import signal
import sys
import os
import zlib
from urllib.parse import urlencode
import motor.motor_asyncio

try:
    import uvloop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    UVLOOP_ENABLED = True
except ImportError:
    UVLOOP_ENABLED = False

from config import (
    CLIENT_ID, CLIENT_SECRET, REDIRECT_URI, MONGODB_URI, PORT,
    DISCORD_API, DISCORD_OAUTH_URL, DISCORD_TOKEN_URL,
    TRUSTED_PROXIES, PROXY_HEADER_HOST, PROXY_HEADER_PROTO
)

class JSONFormatter(logging.Formatter):
    """JSON log formatter for CloudWatch/AWS integration."""
    def format(self, record):
        log_obj = {
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime()),
            'level': record.levelname,
            'message': record.getMessage(),
            'logger': record.name,
        }
        if hasattr(record, 'request_id'):
            log_obj['request_id'] = record.request_id
        if hasattr(record, 'client_ip'):
            log_obj['client_ip'] = record.client_ip
        if record.exc_info:
            log_obj['exception'] = self.formatException(record.exc_info)
        return json.dumps(log_obj)

logger = logging.getLogger('oauth_server')
logger.setLevel(logging.INFO)
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(JSONFormatter())
logger.addHandler(handler)

mongo_client = None
db = None
shutdown_event = asyncio.Event() if hasattr(asyncio, 'Event') else None

def get_real_ip(request):
    """
    Get real client IP from reverse proxy headers.
    Supports Cloudflare (CF-Connecting-IP) and standard proxies (X-Forwarded-For, X-Real-IP).
    """
    cf_ip = request.headers.get('CF-Connecting-IP')
    if cf_ip:
        return cf_ip
    
    x_real_ip = request.headers.get('X-Real-IP')
    if x_real_ip:
        return x_real_ip
    
    x_forwarded_for = request.headers.get('X-Forwarded-For')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    
    return request.remote or '0.0.0.0'

def get_scheme(request):
    """
    Get the real scheme (http/https) from reverse proxy headers.
    Supports Cloudflare and standard proxies.
    """
    cf_visitor = request.headers.get('CF-Visitor')
    if cf_visitor:
        try:
            import json as _json
            visitor = _json.loads(cf_visitor)
            return visitor.get('scheme', 'https')
        except:
            pass
    
    x_forwarded_proto = request.headers.get(PROXY_HEADER_PROTO)
    if x_forwarded_proto:
        return x_forwarded_proto.lower()
    
    return 'https' if request.secure else 'http'

def get_host(request):
    """
    Get the real host from reverse proxy headers.
    """
    x_forwarded_host = request.headers.get(PROXY_HEADER_HOST)
    if x_forwarded_host:
        return x_forwarded_host
    
    return request.host

@web.middleware
async def gzip_middleware(request, handler):
    """Gzip compression middleware for reduced bandwidth on AWS."""
    response = await handler(request)
    
    accept_encoding = request.headers.get('Accept-Encoding', '')
    if 'gzip' not in accept_encoding:
        return response
    
    if response.content_type and response.content_type.startswith(('text/', 'application/json', 'application/javascript')):
        if hasattr(response, 'body') and response.body and len(response.body) > 500:
            compressed = zlib.compress(response.body, level=6)
            if len(compressed) < len(response.body):
                response.body = compressed
                response.headers['Content-Encoding'] = 'gzip'
                response.headers['Content-Length'] = str(len(compressed))
    
    return response

@web.middleware
async def reverse_proxy_middleware(request, handler):
    """
    Middleware to handle reverse proxy headers for AWS ALB/ELB/Cloudflare compatibility.
    Sets request context with real client info and adds security headers.
    """
    request['real_ip'] = get_real_ip(request)
    request['real_scheme'] = get_scheme(request)
    request['real_host'] = get_host(request)
    request['request_id'] = request.headers.get('X-Amzn-Trace-Id', request.headers.get('X-Request-Id', str(time.time())))
    
    response = await handler(request)
    
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com https://discord.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; img-src 'self' https://cdn.discordapp.com data:;"
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    response.headers['X-Request-Id'] = request.get('request_id', '')
    
    return response

async def init_mongodb():
    """Initialize MongoDB with optimized connection pooling for AWS."""
    global mongo_client, db
    if not MONGODB_URI:
        logger.warning("MONGODB_URI not set - running without database")
        return
    try:
        mongo_client = motor.motor_asyncio.AsyncIOMotorClient(
            MONGODB_URI,
            maxPoolSize=50,
            minPoolSize=5,
            maxIdleTimeMS=30000,
            connectTimeoutMS=5000,
            serverSelectionTimeoutMS=5000,
            retryWrites=True,
            retryReads=True,
            compressors='snappy,zstd,zlib',
            tls=True if 'mongodb+srv' in MONGODB_URI else False,
            tlsAllowInvalidCertificates=False
        )
        db = mongo_client['discord_bot']
        await mongo_client.admin.command('ping')
        logger.info("MongoDB connected with optimized pooling")
    except Exception as e:
        logger.error(f"MongoDB connection failed: {e}")

async def save_user_to_pool(user_id: int, username: str, discriminator: str, avatar: str = None):
    """Save user to MongoDB. Bot polls for entries with logged: false."""
    if db is None:
        return False
    try:
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
        await db['oauth_users'].update_one(
            {'_id': user_id},
            {'$set': doc},
            upsert=True
        )
        print(f"\033[92m✓ OAuth: Saved user {username} ({user_id})\033[0m")
        return True
    except Exception as e:
        print(f"\033[91m✗ OAuth: Failed to save user {user_id} - {e}\033[0m")
        return False

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>YELL BIOS - Discord OAuth</title>
    <link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=VT323&display=swap" rel="stylesheet">
    <style>
        
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
        
        [data-theme="amber"] {{
            --primary: #FFB000;
            --primary-bright: #FFD050;
            --primary-dim: #8B6000;
            --primary-glow: rgba(255, 176, 0, 0.4);
            --primary-glow-light: rgba(255, 176, 0, 0.3);
            --primary-glow-subtle: rgba(255, 176, 0, 0.05);
            --primary-glow-faint: rgba(255, 176, 0, 0.02);
            --primary-glow-scan: rgba(255, 176, 0, 0.03);
            --bg-panel: rgba(40, 32, 0, 0.85);
            --bg-panel-dark: rgba(32, 24, 0, 0.8);
            --bg-panel-hover: rgba(64, 48, 0, 0.9);
        }}
        
        [data-theme="blue"] {{
            --primary: #00BFFF;
            --primary-bright: #50D0FF;
            --primary-dim: #006080;
            --primary-glow: rgba(0, 191, 255, 0.4);
            --primary-glow-light: rgba(0, 191, 255, 0.3);
            --primary-glow-subtle: rgba(0, 191, 255, 0.05);
            --primary-glow-faint: rgba(0, 191, 255, 0.02);
            --primary-glow-scan: rgba(0, 191, 255, 0.03);
            --bg-panel: rgba(0, 32, 48, 0.85);
            --bg-panel-dark: rgba(0, 24, 36, 0.8);
            --bg-panel-hover: rgba(0, 48, 72, 0.9);
        }}
        
        [data-theme="green"] {{
            --primary: #00FF00;
            --primary-bright: #50FF50;
            --primary-dim: #008000;
            --primary-glow: rgba(0, 255, 0, 0.4);
            --primary-glow-light: rgba(0, 255, 0, 0.3);
            --primary-glow-subtle: rgba(0, 255, 0, 0.05);
            --primary-glow-faint: rgba(0, 255, 0, 0.02);
            --primary-glow-scan: rgba(0, 255, 0, 0.03);
            --bg-panel: rgba(0, 40, 0, 0.85);
            --bg-panel-dark: rgba(0, 32, 0, 0.8);
            --bg-panel-hover: rgba(0, 64, 0, 0.9);
        }}
        
        [data-theme="white"] {{
            --primary: #E0E0E0;
            --primary-bright: #FFFFFF;
            --primary-dim: #808080;
            --primary-glow: rgba(224, 224, 224, 0.4);
            --primary-glow-light: rgba(224, 224, 224, 0.3);
            --primary-glow-subtle: rgba(224, 224, 224, 0.05);
            --primary-glow-faint: rgba(224, 224, 224, 0.02);
            --primary-glow-scan: rgba(224, 224, 224, 0.03);
            --bg-panel: rgba(40, 40, 40, 0.85);
            --bg-panel-dark: rgba(32, 32, 32, 0.8);
            --bg-panel-hover: rgba(64, 64, 64, 0.9);
        }}
        
        [data-theme="purple"] {{
            --primary: #BF00FF;
            --primary-bright: #DF50FF;
            --primary-dim: #600080;
            --primary-glow: rgba(191, 0, 255, 0.4);
            --primary-glow-light: rgba(191, 0, 255, 0.3);
            --primary-glow-subtle: rgba(191, 0, 255, 0.05);
            --primary-glow-faint: rgba(191, 0, 255, 0.02);
            --primary-glow-scan: rgba(191, 0, 255, 0.03);
            --bg-panel: rgba(40, 0, 48, 0.85);
            --bg-panel-dark: rgba(32, 0, 36, 0.8);
            --bg-panel-hover: rgba(64, 0, 72, 0.9);
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
        
        @keyframes btnPulse {{
            0% {{ box-shadow: 0 4px 8px rgba(0, 0, 0, 0.5), 0 0 20px var(--primary-glow-subtle), inset 0 1px 0 var(--primary-glow-faint), inset 0 -2px 0 rgba(0, 0, 0, 0.3); }}
            50% {{ box-shadow: 0 4px 8px rgba(0, 0, 0, 0.5), 0 0 35px var(--primary-glow-light), 0 0 60px var(--primary-glow-subtle), inset 0 1px 0 var(--primary-glow-faint), inset 0 -2px 0 rgba(0, 0, 0, 0.3); }}
            100% {{ box-shadow: 0 4px 8px rgba(0, 0, 0, 0.5), 0 0 20px var(--primary-glow-subtle), inset 0 1px 0 var(--primary-glow-faint), inset 0 -2px 0 rgba(0, 0, 0, 0.3); }}
        }}
        
        @keyframes scanlineSweep {{
            0% {{ background-position: 0 -100%; }}
            100% {{ background-position: 0 200%; }}
        }}
        
        @keyframes progressFill {{
            0% {{ width: 0%; }}
            100% {{ width: 100%; }}
        }}
        
        .progress-bar-enhanced {{
            display: inline-block;
            width: 200px;
            height: 14px;
            background: var(--bg-panel-dark);
            border: 1px solid var(--primary-dim);
            border-radius: 2px;
            overflow: hidden;
            position: relative;
        }}
        
        .progress-bar-enhanced .fill {{
            height: 100%;
            background: linear-gradient(90deg, var(--primary-dim) 0%, var(--primary) 50%, var(--primary-bright) 100%);
            box-shadow: 0 0 10px var(--primary-glow);
            animation: progressFill 1.5s ease-out forwards;
        }}
        
        .progress-bar-enhanced .glow {{
            position: absolute;
            top: 0;
            right: 0;
            width: 30px;
            height: 100%;
            background: linear-gradient(90deg, transparent, var(--primary-bright), transparent);
            animation: progressGlow 1.5s ease-out forwards;
            opacity: 0.7;
        }}
        
        @keyframes progressGlow {{
            0% {{ right: 100%; }}
            100% {{ right: 0%; }}
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
        
        .keyboard-hints a,
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
        
        .keyboard-hints a:hover,
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
        
        .connect-section {{
            margin-top: 30px;
            text-align: center;
        }}
        
        .connect-btn {{
            position: relative;
            background: 
                repeating-linear-gradient(
                    90deg,
                    var(--primary-glow-scan) 0px,
                    var(--primary-glow-scan) 1px,
                    transparent 1px,
                    transparent 4px
                ),
                linear-gradient(180deg, var(--bg-panel) 0%, var(--bg-panel-dark) 100%);
            color: var(--primary-bright);
            padding: 16px 45px;
            font-size: 18px;
            font-weight: bold;
            letter-spacing: 2px;
            border: 2px solid var(--primary);
            border-top-color: var(--primary-bright);
            border-bottom-color: var(--primary-dim);
            border-radius: 3px;
            cursor: pointer;
            font-family: "Share Tech Mono", monospace;
            transition: all 0.15s ease;
            text-decoration: none;
            display: inline-block;
            text-shadow: 0 0 10px var(--primary-glow), 0 0 20px var(--primary-glow-light);
            box-shadow: 
                0 4px 8px rgba(0, 0, 0, 0.5),
                0 0 25px var(--primary-glow-subtle),
                0 0 50px var(--primary-glow-faint),
                inset 0 1px 0 var(--primary-glow-light),
                inset 0 -2px 0 rgba(0, 0, 0, 0.4);
            animation: btnPulse 2.5s ease-in-out infinite;
            overflow: hidden;
        }}
        
        .connect-btn::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: radial-gradient(circle at var(--mouse-x, 50%) var(--mouse-y, 50%), var(--primary-glow-light) 0%, transparent 50%);
            opacity: 0;
            transition: opacity 0.3s ease;
            pointer-events: none;
        }}
        
        .connect-btn:hover::before {{
            opacity: 1;
        }}
        
        .connect-btn::after {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: linear-gradient(
                180deg,
                transparent 0%,
                var(--primary-glow-subtle) 45%,
                var(--primary-glow-light) 50%,
                var(--primary-glow-subtle) 55%,
                transparent 100%
            );
            background-size: 100% 300%;
            background-position: 0 -100%;
            opacity: 0;
            transition: opacity 0.2s ease;
            pointer-events: none;
        }}
        
        .connect-btn:hover::after {{
            opacity: 1;
            animation: scanlineSweep 0.8s ease-out;
        }}
        
        .connect-btn:hover {{
            background: 
                repeating-linear-gradient(
                    90deg,
                    var(--primary-glow-subtle) 0px,
                    var(--primary-glow-subtle) 1px,
                    transparent 1px,
                    transparent 4px
                ),
                linear-gradient(180deg, var(--bg-panel-hover) 0%, var(--bg-panel) 100%);
            border-color: var(--primary-bright);
            color: var(--primary-bright);
            text-shadow: 0 0 15px var(--primary-glow), 0 0 30px var(--primary-glow), 0 0 45px var(--primary-glow-light);
            box-shadow: 
                0 0 30px var(--primary-glow),
                0 0 60px var(--primary-glow-subtle),
                0 4px 8px rgba(0, 0, 0, 0.5),
                inset 0 1px 0 var(--primary-glow-light),
                inset 0 -2px 0 rgba(0, 0, 0, 0.3);
            animation: none;
            transform: translateY(-1px);
        }}
        
        .connect-btn:active {{
            transform: translateY(2px);
            box-shadow: 
                0 1px 3px rgba(0, 0, 0, 0.5),
                0 0 15px var(--primary-glow-subtle),
                inset 0 2px 4px rgba(0, 0, 0, 0.4);
            border-top-color: var(--primary-dim);
            border-bottom-color: var(--primary-bright);
        }}
        
        .boot-container {{
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: var(--bg);
            z-index: 2000;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: opacity 0.5s ease;
        }}
        
        .boot-container.fade-out {{
            opacity: 0;
            pointer-events: none;
        }}
        
        .splash-screen {{
            text-align: center;
            transition: opacity 0.4s ease;
        }}
        
        .splash-logo {{
            font-family: monospace;
            font-size: 24px;
            color: var(--primary);
            text-shadow: 
                0 0 10px var(--primary-glow),
                0 0 20px var(--primary-glow),
                0 0 40px var(--primary-glow);
            animation: logoPulse 1.5s ease-in-out infinite;
            white-space: pre;
            line-height: 1.2;
        }}
        
        @keyframes logoPulse {{
            0%, 100% {{ opacity: 0.8; text-shadow: 0 0 10px var(--primary-glow), 0 0 20px var(--primary-glow); }}
            50% {{ opacity: 1; text-shadow: 0 0 20px var(--primary-glow), 0 0 40px var(--primary-glow), 0 0 60px var(--primary-glow); }}
        }}
        
        .splash-tagline {{
            margin-top: 20px;
            font-size: 18px;
            letter-spacing: 8px;
            color: var(--primary-dim);
            text-shadow: 0 0 5px var(--primary-glow);
        }}
        
        .post-screen {{
            display: none;
            text-align: left;
            padding: 20px;
            max-width: 800px;
            width: 100%;
        }}
        
        .post-screen.visible {{
            display: block;
        }}
        
        .post-line {{
            margin: 2px 0;
            font-family: "VT323", monospace;
            font-size: 14px;
        }}
        
        .skip-hint {{
            position: fixed;
            bottom: 80px;
            left: 50%;
            transform: translateX(-50%);
            color: var(--primary-dim);
            font-size: 12px;
            z-index: 2001;
            animation: blinkHint 2s ease-in-out infinite;
        }}
        
        @keyframes blinkHint {{
            0%, 100% {{ opacity: 0.5; }}
            50% {{ opacity: 1; }}
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
        
        .glass-panel {{
            background: var(--bg-panel);
            border: 1px solid var(--primary-dim);
            border-radius: 4px;
            backdrop-filter: blur(4px);
        }}
        
        .divider {{
            height: 1px;
            background: linear-gradient(90deg, transparent, var(--primary-dim), transparent);
        }}
        
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
            .connect-btn {{ padding: 12px 25px; font-size: 16px; letter-spacing: 1px; }}
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
            <button onclick="doConnect()"><span class="key">Enter</span> Connect</button>
            <button onclick="history.back()"><span class="key">Esc</span> Back</button>
            <button onclick="cycleTheme()" id="theme-btn"><span class="key">T</span> <span id="theme-label">Red</span></button>
            <button onclick="window.location.href='/credits'"><span class="key">C</span> Credits</button>
        </div>
    </div>
    
    <script>
        let soundEnabled = false;
        
        function playBeep() {{
            if (!soundEnabled) return;
            try {{
                const ctx = new (window.AudioContext || window.webkitAudioContext)();
                const osc = ctx.createOscillator();
                const gain = ctx.createGain();
                osc.connect(gain);
                gain.connect(ctx.destination);
                osc.frequency.value = 800;
                osc.type = 'square';
                gain.gain.value = 0.1;
                osc.start();
                osc.stop(ctx.currentTime + 0.05);
            }} catch(e) {{}}
        }}
        
        function playClick() {{
            if (!soundEnabled) return;
            try {{
                const ctx = new (window.AudioContext || window.webkitAudioContext)();
                const osc = ctx.createOscillator();
                const gain = ctx.createGain();
                osc.connect(gain);
                gain.connect(ctx.destination);
                osc.frequency.value = 1000;
                osc.type = 'square';
                gain.gain.value = 0.05;
                osc.start();
                osc.stop(ctx.currentTime + 0.02);
            }} catch(e) {{}}
        }}
        
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
            alert('YELL OAuth System\\n\\nConnect your Discord account to the Yell network.\\n\\nTap [Connect] to authorize.');
        }}
        
        function doConnect() {{
            const btn = document.querySelector('.connect-btn');
            if (btn) btn.click();
            else alert('OAuth flow not available on this page.');
        }}
        
        const themes = ['red', 'amber', 'blue', 'green', 'white', 'purple'];
        let currentTheme = 0;
        
        function cycleTheme() {{
            currentTheme = (currentTheme + 1) % themes.length;
            const theme = themes[currentTheme];
            if (theme === 'red') document.documentElement.removeAttribute('data-theme');
            else document.documentElement.setAttribute('data-theme', theme);
            const label = document.getElementById('theme-label');
            if (label) label.textContent = theme.charAt(0).toUpperCase() + theme.slice(1);
            localStorage.setItem('yell-theme', theme);
        }}
        
        (function() {{
            const saved = localStorage.getItem('yell-theme');
            if (saved && themes.includes(saved)) {{
                currentTheme = themes.indexOf(saved);
                if (saved !== 'red') document.documentElement.setAttribute('data-theme', saved);
                const label = document.getElementById('theme-label');
                if (label) label.textContent = saved.charAt(0).toUpperCase() + saved.slice(1);
            }}
        }})();
        
        document.addEventListener('mousemove', function(e) {{
            const btn = document.querySelector('.connect-btn');
            if (btn) {{
                const rect = btn.getBoundingClientRect();
                const x = ((e.clientX - rect.left) / rect.width) * 100;
                const y = ((e.clientY - rect.top) / rect.height) * 100;
                btn.style.setProperty('--mouse-x', x + '%');
                btn.style.setProperty('--mouse-y', y + '%');
            }}
        }});
    </script>
    
    {scripts}
</body>
</html>"""

POST_SEQUENCE_DESKTOP = """<span class="amber">╔══════════════════════════════════════════════════════════════════════════════╗</span>
<span class="amber">║</span>                           <span class="white">YELL BIOS v2.0.93</span>                                  <span class="amber">║</span>
<span class="amber">║</span>                         <span class="dim">Copyright (C) 2093 Yell</span>                              <span class="amber">║</span>
<span class="amber">╚══════════════════════════════════════════════════════════════════════════════╝</span>

<span class="yellow">██    ██ ███████ ██      ██     </span>
<span class="yellow"> ██  ██  ██      ██      ██     </span>
<span class="yellow">  ████   █████   ██      ██     </span>
<span class="yellow">   ██    ██      ██      ██     </span>
<span class="yellow">   ██    ███████ ███████ ███████</span>

<span class="white">OAUTH AUTHENTICATION SYSTEM</span>
<span class="dim">Build:</span> <span class="cyan">32-Dec-2093</span> <span class="dim">|</span> <span class="dim">Rev:</span> <span class="cyan">84-01011001-ZETRO</span>

<span class="amber">╔══════════════════════════════════════════════════════════════════════════════╗</span>
<span class="amber">║</span>  <span class="white">POWER-ON SELF TEST</span>                                                          <span class="amber">║</span>
<span class="amber">╚══════════════════════════════════════════════════════════════════════════════╝</span>

<span class="dim">Processor.............</span> <span class="cyan">Discord Gateway v10</span>           [  <span class="ok">OK</span>  ]
<span class="dim">Memory Test...........</span> <span class="cyan">2048 MB</span>                       [  <span class="ok">OK</span>  ]
<span class="dim">OAuth Module..........</span> <span class="cyan">Version 2.0</span>                   [  <span class="ok">OK</span>  ]
<span class="dim">Discord API...........</span> <span class="cyan">v10.0</span>                         [  <span class="ok">OK</span>  ]
<span class="dim">Token Handler.........</span> <span class="cyan">CONNECTED</span>                     [  <span class="ok">OK</span>  ]
<span class="dim">MongoDB Pool..........</span> <span class="cyan">CONNECTED</span>                     [  <span class="ok">OK</span>  ]
<span class="dim">VME Firmware..........</span> <span class="cyan">Version 5000</span>                  [  <span class="ok">OK</span>  ]

<span class="amber">╔══════════════════════════════════════════════════════════════════════════════╗</span>
<span class="amber">║</span>  <span class="white">SYSTEM CONFIGURATION</span>                                                        <span class="amber">║</span>
<span class="amber">╚══════════════════════════════════════════════════════════════════════════════╝</span>

<span class="dim">Service Provider......</span> <span class="cyan">yell™</span>
<span class="dim">Contact...............</span> <span class="cyan">speak@yell.rest</span>
<span class="dim">Platform..............</span> <span class="cyan">Python 3.11 Async</span>
<span class="dim">Connection Status.....</span> <span class="cyan">STANDBY</span>

<span class="dim">Loading OAuth Handler.............</span> [<span class="ok">████████████████████</span>] <span class="white">100%</span>
<span class="dim">Loading Discord Credentials.......</span> [<span class="ok">████████████████████</span>] <span class="white">100%</span>
<span class="dim">Preparing Authorization Flow......</span> [<span class="ok">████████████████████</span>] <span class="white">100%</span>

<span class="amber">╔══════════════════════════════════════════════════════════════════════════════╗</span>
<span class="amber">║</span>  <span class="white">READY FOR AUTHENTICATION</span>                                                    <span class="amber">║</span>
<span class="amber">╚══════════════════════════════════════════════════════════════════════════════╝</span>

Press <span class="white">CONNECT</span> to authorize your Discord account.

<span class="dim">C:\\YELL\\OAUTH></span><span class="cursor"></span>"""

POST_SEQUENCE_MOBILE = """<span class="amber">╔═════════════════════════════════════╗</span>
<span class="amber">║</span>      <span class="white">YELL BIOS v2.0.93</span>            <span class="amber">║</span>
<span class="amber">║</span>    <span class="dim">Copyright (C) 2093 Yell</span>        <span class="amber">║</span>
<span class="amber">╚═════════════════════════════════════╝</span>

<span class="yellow">██  ██ ███ ██  ██  </span>
<span class="yellow"> ████  █   ██  ██  </span>
<span class="yellow">  ██   ██  ██  ██  </span>
<span class="yellow">  ██   ███ ███ ███ </span>

<span class="white">OAUTH AUTHENTICATION SYSTEM</span>
<span class="dim">Build:</span> <span class="cyan">32-Dec-2093</span>

<span class="amber">╔═════════════════════════════════════╗</span>
<span class="amber">║</span>  <span class="white">POWER-ON SELF TEST</span>              <span class="amber">║</span>
<span class="amber">╚═════════════════════════════════════╝</span>

<span class="dim">Processor....</span> <span class="cyan">Discord v10</span>  [<span class="ok">OK</span>]
<span class="dim">Memory.......</span> <span class="cyan">2048 MB</span>      [<span class="ok">OK</span>]
<span class="dim">OAuth........</span> <span class="cyan">v2.0</span>         [<span class="ok">OK</span>]
<span class="dim">Discord API..</span> <span class="cyan">v10.0</span>        [<span class="ok">OK</span>]
<span class="dim">Token........</span> <span class="cyan">CONNECTED</span>    [<span class="ok">OK</span>]
<span class="dim">MongoDB......</span> <span class="cyan">CONNECTED</span>    [<span class="ok">OK</span>]
<span class="dim">VME..........</span> <span class="cyan">v5000</span>        [<span class="ok">OK</span>]

<span class="amber">╔═════════════════════════════════════╗</span>
<span class="amber">║</span>  <span class="white">SYSTEM CONFIGURATION</span>            <span class="amber">║</span>
<span class="amber">╚═════════════════════════════════════╝</span>

<span class="dim">Provider..</span> <span class="cyan">yell™</span>
<span class="dim">Contact...</span> <span class="cyan">speak@yell.rest</span>
<span class="dim">Platform..</span> <span class="cyan">Python 3.11</span>
<span class="dim">Status....</span> <span class="cyan">STANDBY</span>

<span class="dim">Loading OAuth....</span> [<span class="ok">████████</span>] <span class="white">100%</span>
<span class="dim">Loading Creds....</span> [<span class="ok">████████</span>] <span class="white">100%</span>
<span class="dim">Preparing........</span> [<span class="ok">████████</span>] <span class="white">100%</span>

<span class="amber">╔═════════════════════════════════════╗</span>
<span class="amber">║</span>  <span class="white">READY FOR AUTHENTICATION</span>        <span class="amber">║</span>
<span class="amber">╚═════════════════════════════════════╝</span>

Press <span class="white">CONNECT</span> to authorize.

<span class="dim">C:\\YELL\\OAUTH></span><span class="cursor"></span>"""

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
            if (Math.random() > 0.7) playClick();
            setTimeout(renderNextLine, 45);
        }
    }
    
    renderNextLine();
</script>
"""

BOOT_SEQUENCE_SCRIPT = """
<script>
    let bootComplete = false;
    let bootSkipped = false;
    
    document.addEventListener('click', function() {
        if (!bootComplete && !bootSkipped) {
            bootSkipped = true;
            skipToMain();
        }
    });
    
    document.addEventListener('keydown', function() {
        if (!bootComplete && !bootSkipped) {
            bootSkipped = true;
            skipToMain();
        }
    });
    
    function skipToMain() {
        const bootContainer = document.getElementById('boot-container');
        const mainContent = document.getElementById('main-content');
        const skipHint = document.getElementById('skip-hint');
        const connectSection = document.getElementById('connect-section');
        
        if (bootContainer) {
            bootContainer.classList.add('fade-out');
            setTimeout(() => bootContainer.style.display = 'none', 500);
        }
        if (skipHint) skipHint.style.display = 'none';
        if (mainContent) mainContent.style.display = 'block';
        if (connectSection) {
            connectSection.style.display = 'block';
            connectSection.style.opacity = '1';
        }
        bootComplete = true;
    }
    
    async function runBootSequence() {
        const splashScreen = document.getElementById('splash-screen');
        const postScreen = document.getElementById('post-screen');
        const bootContainer = document.getElementById('boot-container');
        const mainContent = document.getElementById('main-content');
        const skipHint = document.getElementById('skip-hint');
        const connectSection = document.getElementById('connect-section');
        const container = document.getElementById('terminal-text');
        
        if (!splashScreen || !postScreen) {
            if (mainContent) mainContent.style.display = 'block';
            if (connectSection) {
                connectSection.style.display = 'block';
                connectSection.style.opacity = '1';
            }
            bootComplete = true;
            return;
        }
        
        if (mainContent) mainContent.style.display = 'none';
        if (connectSection) connectSection.style.display = 'none';
        
        await sleep(2500);
        if (bootSkipped) return;
        
        splashScreen.style.opacity = '0';
        await sleep(400);
        if (bootSkipped) return;
        
        splashScreen.style.display = 'none';
        postScreen.classList.add('visible');
        
        const postLines = [
            { text: 'YELL BIOS v2.0.93', class: 'white', delay: 100 },
            { text: 'Copyright (C) 2093 Yell Corporation', class: 'dim', delay: 50 },
            { text: '', delay: 100 },
            { text: 'Detecting Hardware...', class: 'primary', delay: 300 },
            { text: '', delay: 50 },
            { text: 'CPU: Discord Gateway v10              [OK]', class: 'primary', okClass: 'ok', delay: 80 },
            { text: 'Memory: ', class: 'primary', isMemory: true, delay: 20 },
            { text: 'OAuth Module v2.0                     [OK]', class: 'primary', okClass: 'ok', delay: 80 },
            { text: 'Discord API v10.0                     [OK]', class: 'primary', okClass: 'ok', delay: 80 },
            { text: 'Token Handler                         [OK]', class: 'primary', okClass: 'ok', delay: 80 },
            { text: 'MongoDB Pool                          [OK]', class: 'primary', okClass: 'ok', delay: 80 },
            { text: 'VME Firmware v5000                    [OK]', class: 'primary', okClass: 'ok', delay: 80 },
            { text: '', delay: 100 },
            { text: 'Initializing OAuth Handler...', class: 'cyan', delay: 200, isProgress: true },
            { text: 'Loading Discord Credentials...', class: 'cyan', delay: 200, isProgress: true },
            { text: 'Preparing Authorization...', class: 'cyan', delay: 200, isProgress: true },
            { text: '', delay: 100 },
            { text: 'System Ready', class: 'ok', delay: 300 },
        ];
        
        const postContent = document.getElementById('post-content');
        
        for (const line of postLines) {
            if (bootSkipped) return;
            
            const lineEl = document.createElement('div');
            lineEl.className = 'post-line';
            
            if (line.isMemory) {
                lineEl.innerHTML = '<span class="' + (line.class || '') + '">Memory: </span><span class="memory-counter" id="mem-counter">0</span><span class="' + (line.class || '') + '"> KB</span>';
                postContent.appendChild(lineEl);
                await animateMemory();
            } else if (line.isProgress) {
                lineEl.innerHTML = '<span class="' + (line.class || '') + '">' + line.text + '</span> <div class="progress-bar-enhanced"><div class="fill"></div><div class="glow"></div></div>';
                postContent.appendChild(lineEl);
                await sleep(800);
            } else if (line.okClass) {
                const parts = line.text.split('[OK]');
                lineEl.innerHTML = '<span class="' + (line.class || '') + '">' + parts[0] + '</span><span class="' + line.okClass + '">[OK]</span>';
                postContent.appendChild(lineEl);
            } else {
                lineEl.innerHTML = '<span class="' + (line.class || '') + '">' + line.text + '</span>';
                postContent.appendChild(lineEl);
            }
            
            if (!line.isMemory && !line.isProgress) await sleep(line.delay || 50);
        }
        
        if (bootSkipped) return;
        
        await sleep(800);
        if (bootSkipped) return;
        
        bootContainer.classList.add('fade-out');
        if (skipHint) skipHint.style.display = 'none';
        
        await sleep(500);
        bootContainer.style.display = 'none';
        
        if (mainContent) mainContent.style.display = 'block';
        
        if (container) {
            const originalHTML = container.innerHTML;
            const lines = originalHTML.split('\\n');
            container.innerHTML = '';
            
            for (let i = 0; i < lines.length; i++) {
                if (bootSkipped) {
                    container.innerHTML = originalHTML;
                    break;
                }
                container.innerHTML += lines[i] + '\\n';
                if (Math.random() > 0.7) playClick();
                await sleep(35);
            }
        }
        
        if (connectSection) {
            connectSection.style.display = 'block';
            connectSection.style.opacity = '0';
            connectSection.style.transition = 'opacity 0.5s';
            setTimeout(() => connectSection.style.opacity = '1', 100);
            playBeep();
        }
        
        bootComplete = true;
    }
    
    async function animateMemory() {
        const counter = document.getElementById('mem-counter');
        if (!counter) return;
        
        const targetMem = 2097152;
        const steps = 30;
        
        for (let i = 0; i <= steps; i++) {
            if (bootSkipped) {
                counter.textContent = targetMem.toLocaleString();
                return;
            }
            const current = Math.floor((targetMem / steps) * i);
            counter.textContent = current.toLocaleString();
            await sleep(25);
        }
        
        counter.parentElement.innerHTML = '<span class="primary">Memory: 2097152 KB </span><span class="ok">[OK]</span>';
    }
    
    function sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
    
    runBootSequence();
</script>
"""

def get_oauth_url():
    params = {
        'client_id': CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'response_type': 'code',
        'scope': 'identify'
    }
    return f"{DISCORD_OAUTH_URL}?{urlencode(params)}"

async def exchange_code(code: str):
    data = {
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': REDIRECT_URI
    }
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(DISCORD_TOKEN_URL, data=data, headers=headers, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                if resp.status != 200:
                    try:
                        error_data = await resp.json()
                        error_msg = error_data.get('error_description', error_data.get('error', 'Unknown error'))
                    except:
                        error_text = await resp.text()
                        error_msg = error_text[:200] if len(error_text) > 200 else error_text
                    return None, f"Token exchange failed ({resp.status}): {error_msg}"
                
                try:
                    return await resp.json(), None
                except Exception as e:
                    return None, f"Invalid JSON response from Discord: {str(e)}"
    except asyncio.TimeoutError:
        return None, "Token exchange timed out - Discord API slow"
    except aiohttp.ClientError as e:
        return None, f"Network error during token exchange: {str(e)}"
    except Exception as e:
        return None, f"Unexpected error during token exchange: {str(e)}"

async def get_user_info(access_token: str):
    headers = {'Authorization': f'Bearer {access_token}'}
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{DISCORD_API}/users/@me", headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                if resp.status != 200:
                    try:
                        error_data = await resp.json()
                        error_msg = error_data.get('message', 'Unknown error')
                    except:
                        error_msg = await resp.text()
                    return None, f"Failed to fetch user info ({resp.status}): {error_msg}"
                
                try:
                    return await resp.json(), None
                except Exception as e:
                    return None, f"Invalid JSON from Discord user API: {str(e)}"
    except asyncio.TimeoutError:
        return None, "User info request timed out"
    except aiohttp.ClientError as e:
        return None, f"Network error fetching user info: {str(e)}"
    except Exception as e:
        return None, f"Unexpected error fetching user info: {str(e)}"

def is_mobile(request):
    user_agent = request.headers.get('User-Agent', '').lower()
    mobile_keywords = ['mobile', 'android', 'iphone', 'ipad', 'ipod', 'webos', 'blackberry', 'opera mini', 'opera mobi']
    return any(keyword in user_agent for keyword in mobile_keywords)

async def handle_home(request):
    oauth_url = get_oauth_url()
    post_content = POST_SEQUENCE_MOBILE if is_mobile(request) else POST_SEQUENCE_DESKTOP
    
    yell_ascii = """██  ██ ███ ██  ██  
 ████  █   ██  ██  
  ██   ██  ██  ██  
  ██   ███ ███ ███"""
    
    content = f"""
        <div id="boot-container" class="boot-container">
            <div id="splash-screen" class="splash-screen">
                <pre class="splash-logo">{yell_ascii}</pre>
                <div class="splash-tagline">INDUSTRIES</div>
            </div>
            <div id="post-screen" class="post-screen">
                <div id="post-content" class="terminal"></div>
            </div>
        </div>
        
        <div id="skip-hint" class="skip-hint">Click anywhere or press any key to skip</div>
        
        <div id="main-content" style="display: none;">
            <div class="bios-header">
                <span>YELL BIOS SETUP UTILITY</span>
                <span class="timestamp" id="timestamp"></span>
            </div>
            <div class="terminal">
                <pre id="terminal-text">{post_content}</pre>
            </div>
            <div id="connect-section" class="connect-section" style="display: none;">
                <a href="{oauth_url}" class="connect-btn" onclick="playBeep()">[ CONNECT WITH DISCORD ]</a>
            </div>
        </div>
    """
    
    html = HTML_TEMPLATE.format(content=content, scripts=BOOT_SEQUENCE_SCRIPT)
    return web.Response(text=html, content_type='text/html')

async def handle_authorize(request):
    return web.HTTPFound(get_oauth_url())

async def handle_callback(request):
    code = request.query.get('code')
    error = request.query.get('error')
    
    if error:
        error_desc = request.query.get('error_description', 'Authorization was denied.')
        return await render_error(error.upper(), error_desc)
    
    if not code:
        return await render_error("NO_CODE", "No authorization code received.")
    
    token_data, error = await exchange_code(code)
    if error:
        return await render_error("TOKEN_ERROR", error)
    
    access_token = token_data.get('access_token')
    if not access_token:
        return await render_error("NO_TOKEN", "No access token in response.")
    
    user_data, error = await get_user_info(access_token)
    if error:
        return await render_error("USER_ERROR", error)
    
    user_id = int(user_data['id'])
    username = user_data['username']
    discriminator = user_data.get('discriminator', '0')
    avatar = user_data.get('avatar')
    
    await save_user_to_pool(user_id, username, discriminator, avatar)
    
    display_name = f"{username}#{discriminator}" if discriminator != '0' else username
    
    success_text = SUCCESS_SEQUENCE.format(user_id=user_id, username=display_name)
    
    content = f"""
        <div class="bios-header">
            <span>YELL BIOS SETUP UTILITY</span>
            <span class="timestamp" id="timestamp"></span>
        </div>
        <div class="terminal">
            <pre id="terminal-text">{success_text}</pre>
        </div>
    """
    
    html = HTML_TEMPLATE.format(content=content, scripts=TYPEWRITER_SCRIPT)
    return web.Response(text=html, content_type='text/html')

async def render_error(error_code: str, error_message: str):
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
    
    html = HTML_TEMPLATE.format(content=content, scripts=TYPEWRITER_SCRIPT)
    return web.Response(text=html, content_type='text/html')

async def handle_error(request):
    error_code = request.query.get('code', 'AUTH_FAILED')
    error_message = request.query.get('message', 'Authorization was denied or expired.')
    return await render_error(error_code, error_message)

async def handle_health(request):
    """AWS ALB/ELB compatible health check endpoint."""
    is_healthy = db is not None
    status_code = 200 if is_healthy else 503
    
    return web.json_response({
        'status': 'healthy' if is_healthy else 'degraded',
        'timestamp': int(time.time()),
        'service': 'yell-oauth-server',
        'version': '2.1.0',
        'mongodb': 'connected' if db is not None else 'disconnected',
        'uvloop': UVLOOP_ENABLED,
        'port': PORT,
        'aws_optimized': True,
        'features': ['gzip', 'hsts', 'csp', 'graceful-shutdown'],
        'proxy_headers': ['X-Forwarded-For', 'X-Forwarded-Proto', 'X-Forwarded-Host', 'X-Amzn-Trace-Id'],
        'client_ip': request.get('real_ip', request.remote),
        'scheme': request.get('real_scheme', 'http'),
        'request_id': request.get('request_id', '')
    }, status=status_code)

async def handle_credits(request):
    credits_ascii_desktop = """
 ██████ ██████  ███████ ██████  ██ ████████ ███████ 
██      ██   ██ ██      ██   ██ ██    ██    ██      
██      ██████  █████   ██   ██ ██    ██    ███████ 
██      ██   ██ ██      ██   ██ ██    ██         ██ 
 ██████ ██   ██ ███████ ██████  ██    ██    ███████"""
    
    credits_ascii_mobile = """
█▀▀ █▀█ █▀▀ █▀▄ █ ▀█▀ █▀
█▄▄ █▀▄ ██▄ █▄▀ █  █  ▄█"""
    
    credits_ascii = credits_ascii_mobile if is_mobile(request) else credits_ascii_desktop
    font_size = "16px" if is_mobile(request) else "14px"
    
    content = f"""
        <div class="bios-header">
            <span>YELL BIOS SETUP UTILITY</span>
            <span class="timestamp" id="timestamp"></span>
        </div>
        <div class="terminal" style="text-align: center;">
            <pre class="splash-logo" style="font-size: {font_size}; margin-bottom: 30px;">{credits_ascii}</pre>
            
            <div class="glass-panel" style="max-width: 500px; margin: 0 auto; padding: 30px;">
                <div style="margin-bottom: 25px;">
                    <span class="primary" style="font-size: 16px; letter-spacing: 2px;">SYSTEM DEVELOPED BY</span>
                </div>
                
                <div style="margin-bottom: 30px;">
                    <span class="primary-bright" style="font-size: 28px; font-weight: bold; letter-spacing: 4px; text-shadow: 0 0 15px var(--primary-glow), 0 0 30px var(--primary-glow);">ZETRO</span>
                </div>
                
                <div class="divider" style="margin: 20px 0;"></div>
                
                <div style="margin-top: 25px;">
                    <span class="dim" style="font-size: 12px;">YELL INDUSTRIES OAUTH SYSTEM</span><br>
                    <span class="dim" style="font-size: 12px;">VERSION 2.0.93</span>
                </div>
                
                <div style="margin-top: 30px;">
                    <a href="/" class="connect-btn" style="padding: 10px 30px; font-size: 14px;" onclick="playBeep()">[ RETURN HOME ]</a>
                </div>
            </div>
        </div>
    """
    
    html = HTML_TEMPLATE.format(content=content, scripts="")
    return web.Response(text=html, content_type='text/html')

async def on_startup(app):
    """Initialize services on startup."""
    logger.info("Starting OAuth server initialization...")
    await init_mongodb()
    logger.info("OAuth server ready to accept connections")

async def on_cleanup(app):
    """Cleanup resources on shutdown."""
    global mongo_client
    logger.info("Initiating graceful shutdown...")
    if mongo_client:
        mongo_client.close()
        logger.info("MongoDB connection closed")
    logger.info("Cleanup complete")

def create_app():
    """Create and configure the aiohttp application with AWS optimizations."""
    app = web.Application(
        middlewares=[gzip_middleware, reverse_proxy_middleware],
        client_max_size=1024 * 1024 * 2
    )
    app.on_startup.append(on_startup)
    app.on_cleanup.append(on_cleanup)
    app.router.add_get('/', handle_home)
    app.router.add_get('/authorize', handle_authorize)
    app.router.add_get('/callback', handle_callback)
    app.router.add_get('/error', handle_error)
    app.router.add_get('/health', handle_health)
    app.router.add_get('/credits', handle_credits)
    return app

def handle_sigterm(signum, frame):
    """Handle SIGTERM for graceful shutdown."""
    logger.info(f"Received signal {signum}, initiating graceful shutdown...")
    sys.exit(0)

def run_with_failsafe(max_retries=5, retry_delay=10):
    """Run the server with automatic restart on crash."""
    import subprocess
    retry_count = 0
    
    while retry_count < max_retries:
        try:
            logger.info("YELL OAuth Website starting (Ubuntu + Cloudflare)...")
            logger.info(f"Port: {PORT}")
            logger.info(f"Redirect URI: {REDIRECT_URI}")
            logger.info(f"uvloop: {'enabled' if UVLOOP_ENABLED else 'disabled'}")
            logger.info(f"Attempt: {retry_count + 1}/{max_retries}")
            
            app = create_app()
            web.run_app(
                app,
                host='0.0.0.0',
                port=PORT,
                access_log=None,
                handle_signals=True,
                shutdown_timeout=30.0
            )
            break
            
        except OSError as e:
            if 'Address already in use' in str(e):
                logger.error(f"Port {PORT} in use, attempting to free...")
                subprocess.run(f"fuser -k {PORT}/tcp", shell=True, capture_output=True)
                time.sleep(3)
                retry_count += 1
            else:
                raise
                
        except KeyboardInterrupt:
            logger.info("Shutdown requested by user")
            break
            
        except Exception as e:
            retry_count += 1
            logger.error(f"Server crashed: {e}")
            if retry_count < max_retries:
                logger.info(f"Restarting in {retry_delay} seconds... (attempt {retry_count}/{max_retries})")
                time.sleep(retry_delay)
            else:
                logger.error("Max retries reached, giving up")
                sys.exit(1)

if __name__ == '__main__':
    signal.signal(signal.SIGTERM, handle_sigterm)
    signal.signal(signal.SIGINT, handle_sigterm)
    
    if not CLIENT_ID or not CLIENT_SECRET:
        logger.error("Missing DISCORD_CLIENT_ID or DISCORD_CLIENT_SECRET")
        logger.error("Run: sudo bash setup.sh to configure the server")
        sys.exit(1)
    
    run_with_failsafe(max_retries=5, retry_delay=10)
