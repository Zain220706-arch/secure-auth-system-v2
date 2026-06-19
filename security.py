"""
security.py - Security Utilities
Modul keamanan: JWT, hashing, CSRF, brute force protection
"""
import os
import jwt
import bcrypt
import secrets
import hashlib
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import request, jsonify, 
from dotenv import load_dotenv

load_dotenv()

JWT_SECRET = os.getenv('JWT_SECRET_KEY', 'fallback-secret-change-me')
JWT_ACCESS_EXPIRES = int(os.getenv('JWT_ACCESS_TOKEN_EXPIRES', 3600))
JWT_REFRESH_EXPIRES = int(os.getenv('JWT_REFRESH_TOKEN_EXPIRES', 86400))
MAX_ATTEMPTS = int(os.getenv('MAX_LOGIN_ATTEMPTS', 5))
LOCKOUT_DURATION = int(os.getenv('LOCKOUT_DURATION', 900))


# ============================================================
# PASSWORD HASHING
# ============================================================
def hash_password(password: str) -> str:
    """Hash password menggunakan bcrypt dengan salt rounds=12"""
    if len(password) < 8:
        raise ValueError("Password minimal 8 karakter")
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')


def verify_password(password: str, hashed: str) -> bool:
    """Verifikasi password vs hash (timing-safe)"""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    except Exception:
        return False


def validate_password_strength(password: str) -> tuple[bool, str]:
    """Validasi kekuatan password"""
    if len(password) < 8:
        return False, "Password minimal 8 karakter"
    if not any(c.isupper() for c in password):
        return False, "Password harus mengandung huruf kapital"
    if not any(c.islower() for c in password):
        return False, "Password harus mengandung huruf kecil"
    if not any(c.isdigit() for c in password):
        return False, "Password harus mengandung angka"
    if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
        return False, "Password harus mengandung karakter spesial"
    return True, "Password kuat"


# ============================================================
# JWT TOKEN MANAGEMENT
# ============================================================
def generate_jti() -> str:
    """Generate unique JWT ID"""
    return str(uuid.uuid4())


def create_access_token(user_id: int, username: str, role: str, permissions: list) -> tuple[str, str]:
    """Buat JWT access token dengan claims lengkap"""
    jti = generate_jti()
    now = datetime.now(timezone.utc)
    payload = {
        'iss': 'secure-auth-system',
        'sub': str(user_id),
        'iat': now,
        'exp': now + timedelta(seconds=JWT_ACCESS_EXPIRES),
        'jti': jti,
        'type': 'access',
        'username': username,
        'role': role,
        'permissions': permissions,
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
    return token, jti


def create_refresh_token(user_id: int) -> tuple[str, str]:
    """Buat JWT refresh token"""
    jti = generate_jti()
    now = datetime.now(timezone.utc)
    payload = {
        'iss': 'secure-auth-system',
        'sub': str(user_id),
        'iat': now,
        'exp': now + timedelta(seconds=JWT_REFRESH_EXPIRES),
        'jti': jti,
        'type': 'refresh',
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
    return token, jti


def decode_token(token: str) -> dict | None:
    """Decode dan validasi JWT token"""
    try:
        payload = jwt.decode(
            token, JWT_SECRET,
            algorithms=['HS256'],
            options={"verify_exp": True}
        )
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


# ============================================================
# CSRF PROTECTION
# ============================================================
def generate_csrf_token() -> str:
    """Generate CSRF token yang kuat"""
    return secrets.token_hex(32)


def verify_csrf_token(session_csrf: str, request_csrf: str) -> bool:
    """Verifikasi CSRF token (timing-safe comparison)"""
    if not session_csrf or not request_csrf:
        return False
    return secrets.compare_digest(session_csrf, request_csrf)


# ============================================================
# SESSION TOKEN
# ============================================================
def generate_session_token() -> str:
    """Generate session token yang aman (128 karakter hex)"""
    return secrets.token_hex(64)


def hash_session_token(token: str) -> str:
    """Hash session token untuk penyimpanan di DB"""
    return hashlib.sha256(token.encode()).hexdigest()


# ============================================================
# IP & USER AGENT HELPERS
# ============================================================
def get_client_ip() -> str:
    """Ambil IP klien (support proxy)"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr or '0.0.0.0'


def get_user_agent() -> str:
    """Ambil User-Agent dengan panjang terbatas"""
    return (request.user_agent.string or '')[:500]


# ============================================================
# RBAC DECORATORS
# ============================================================
def token_required(f):
    """Decorator: wajib login dengan JWT valid"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]

        if not token:
            return jsonify({'error': 'Token tidak ditemukan', 'code': 'MISSING_TOKEN'}), 401

        payload = decode_token(token)
        if not payload:
            return jsonify({'error': 'Token tidak valid atau sudah kadaluarsa', 'code': 'INVALID_TOKEN'}), 401

        if payload.get('type') != 'access':
            return jsonify({'error': 'Tipe token tidak valid', 'code': 'WRONG_TOKEN_TYPE'}), 401

        # Simpan info user di g (Flask global context)
        g.current_user = {
            'id': int(payload['sub']),
            'username': payload['username'],
            'role': payload['role'],
            'permissions': payload.get('permissions', []),
            'jti': payload['jti']
        }
        return f(*args, **kwargs)
    return decorated


def require_permission(*required_permissions):
    """Decorator: wajib memiliki permission tertentu (RBAC least privilege)"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not hasattr(g, 'current_user'):
                return jsonify({'error': 'Autentikasi diperlukan', 'code': 'UNAUTHORIZED'}), 401

            user_permissions = g.current_user.get('permissions', [])
            for perm in required_permissions:
                if perm not in user_permissions:
                    return jsonify({
                        'error': f'Akses ditolak. Permission "{perm}" diperlukan.',
                        'code': 'FORBIDDEN'
                    }), 403
            return f(*args, **kwargs)
        return decorated
    return decorator


def require_roles(*roles):
    """Decorator: wajib memiliki role tertentu"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not hasattr(g, 'current_user'):
                return jsonify({'error': 'Autentikasi diperlukan', 'code': 'UNAUTHORIZED'}), 401

            user_role = g.current_user.get('role')
            if user_role not in roles:
                return jsonify({
                    'error': f'Akses ditolak. Role {list(roles)} diperlukan.',
                    'code': 'FORBIDDEN'
                }), 403
            return f(*args, **kwargs)
        return decorated
    return decorator
