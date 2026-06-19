"""
app.py - Main Flask Application
Sistem Autentikasi Aman dengan JWT, RBAC, CSRF Protection
"""
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, request, jsonify, render_template, send_from_directory
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv

from security import (
    verify_password, token_required, require_permission, require_roles,
    create_access_token, create_refresh_token, decode_token,
    verify_csrf_token, get_client_ip, get_user_agent,
    validate_password_strength, JWT_ACCESS_EXPIRES, JWT_REFRESH_EXPIRES
)
from models import (
    get_user_by_username, get_user_by_id, get_all_users, create_user,
    update_user, update_password, delete_user,
    record_failed_login, reset_failed_login, is_account_locked,
    store_token, revoke_token, is_token_revoked, revoke_all_user_tokens,
    create_session, get_session, invalidate_session, update_session_activity,
    log_action, get_audit_logs, get_all_roles
)

load_dotenv()

app = Flask(
    __name__,
    template_folder='../frontend/templates',
    static_folder='../frontend/static'
)

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'fallback-secret')
app.config['JSON_SORT_KEYS'] = False

# ============================================================
# RATE LIMITER (Anti Brute Force)
# ============================================================
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

MAX_ATTEMPTS = int(os.getenv('MAX_LOGIN_ATTEMPTS', 5))
LOCKOUT_DURATION = int(os.getenv('LOCKOUT_DURATION', 900))


# ============================================================
# SECURITY HEADERS MIDDLEWARE
# ============================================================
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:;"
    )
    return response


# ============================================================
# FRONTEND ROUTES
# ============================================================
@app.route('/')
def index():
    return render_template('index.html')


@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')


# ============================================================
# AUTH API - LOGIN
# ============================================================
@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    ip = get_client_ip()
    ua = get_user_agent()
    data = request.get_json(silent=True) or {}

    username = str(data.get('username', '')).strip()
    password = str(data.get('password', ''))

    # Validasi input dasar
    if not username or not password:
        return jsonify({'error': 'Username dan password wajib diisi', 'code': 'MISSING_CREDENTIALS'}), 400

    # Sanitasi: batasi panjang untuk mencegah abuse
    if len(username) > 50 or len(password) > 128:
        return jsonify({'error': 'Input tidak valid', 'code': 'INVALID_INPUT'}), 400

    user = get_user_by_username(username)

    # Generic error untuk mencegah user enumeration
    auth_failed_msg = {'error': 'Username atau password salah', 'code': 'INVALID_CREDENTIALS'}

    if not user:
        log_action(None, 'LOGIN_ATTEMPT', 'auth', ip, ua, 'failed', {'username': username, 'reason': 'user_not_found'})
        return jsonify(auth_failed_msg), 401

    # Cek apakah akun aktif
    if not user['is_active']:
        log_action(user['id'], 'LOGIN_ATTEMPT', 'auth', ip, ua, 'blocked', {'reason': 'account_disabled'})
        return jsonify({'error': 'Akun dinonaktifkan. Hubungi administrator.', 'code': 'ACCOUNT_DISABLED'}), 403

    # Cek apakah akun dikunci (brute force protection)
    if is_account_locked(user):
        log_action(user['id'], 'LOGIN_ATTEMPT', 'auth', ip, ua, 'blocked', {'reason': 'account_locked'})
        return jsonify({'error': f'Akun dikunci sementara karena terlalu banyak percobaan login. Coba lagi dalam {LOCKOUT_DURATION // 60} menit.', 'code': 'ACCOUNT_LOCKED'}), 429

    # Verifikasi password (timing-safe via bcrypt)
    if not verify_password(password, user['password_hash']):
        record_failed_login(username, MAX_ATTEMPTS, LOCKOUT_DURATION)
        remaining = MAX_ATTEMPTS - (user['failed_login_attempts'] + 1)
        log_action(user['id'], 'LOGIN_ATTEMPT', 'auth', ip, ua, 'failed', {'reason': 'wrong_password'})
        if remaining <= 0:
            return jsonify({'error': f'Akun dikunci karena terlalu banyak percobaan gagal.', 'code': 'ACCOUNT_LOCKED'}), 429
        return jsonify({**auth_failed_msg, 'attempts_remaining': max(0, remaining)}), 401

    # Login berhasil
    permissions = user.get('role_permissions', [])
    if isinstance(permissions, str):
        import json
        permissions = json.loads(permissions)

    access_token, access_jti = create_access_token(
        user['id'], user['username'], user['role_name'], permissions
    )
    refresh_token, refresh_jti = create_refresh_token(user['id'])

    # Simpan token ke DB
    store_token(user['id'], access_jti, 'access', JWT_ACCESS_EXPIRES)
    store_token(user['id'], refresh_jti, 'refresh', JWT_REFRESH_EXPIRES)

    # Update login info & reset failed attempts
    reset_failed_login(user['id'], ip)

    # Buat session
    session_token, csrf_token = create_session(user['id'], ip, ua)

    log_action(user['id'], 'LOGIN', 'auth', ip, ua, 'success')

    response = jsonify({
        'message': 'Login berhasil',
        'access_token': access_token,
        'refresh_token': refresh_token,
        'csrf_token': csrf_token,
        'session_token': session_token,
        'expires_in': JWT_ACCESS_EXPIRES,
        'user': {
            'id': user['id'],
            'username': user['username'],
            'email': user['email'],
            'role': user['role_name'],
            'permissions': permissions
        }
    })
    # Set session cookie HttpOnly, Secure, SameSite
    response.set_cookie(
        'session_token', session_token,
        httponly=True, secure=False,  # Set secure=True di production (HTTPS)
        samesite='Strict', max_age=86400,
        path='/'
    )
    return response, 200


# ============================================================
# AUTH API - LOGOUT
# ============================================================
@app.route('/api/auth/logout', methods=['POST'])
@token_required
def logout():
    ip = get_client_ip()
    ua = get_user_agent()

    from flask import g
    current = g.current_user

    # Cabut access token
    revoke_token(current['jti'])

    # Cabut session cookie
    session_token = request.cookies.get('session_token')
    if session_token:
        invalidate_session(session_token)

    log_action(current['id'], 'LOGOUT', 'auth', ip, ua, 'success')

    response = jsonify({'message': 'Logout berhasil'})
    response.delete_cookie('session_token', path='/')
    return response, 200


# ============================================================
# AUTH API - REFRESH TOKEN
# ============================================================
@app.route('/api/auth/refresh', methods=['POST'])
def refresh():
    data = request.get_json(silent=True) or {}
    refresh_token = data.get('refresh_token')
    if not refresh_token:
        return jsonify({'error': 'Refresh token diperlukan'}), 400

    payload = decode_token(refresh_token)
    if not payload or payload.get('type') != 'refresh':
        return jsonify({'error': 'Refresh token tidak valid'}), 401

    if is_token_revoked(payload['jti']):
        return jsonify({'error': 'Refresh token sudah dicabut'}), 401

    user = get_user_by_id(int(payload['sub']))
    if not user or not user['is_active']:
        return jsonify({'error': 'User tidak aktif'}), 401

    import json as _json
    permissions = user.get('role_permissions', [])
    if isinstance(permissions, str):
        permissions = _json.loads(permissions)

    access_token, access_jti = create_access_token(
        user['id'], user['username'], user['role_name'], permissions
    )
    store_token(user['id'], access_jti, 'access', JWT_ACCESS_EXPIRES)

    # Cabut refresh token lama
    revoke_token(payload['jti'])
    new_refresh, new_refresh_jti = create_refresh_token(user['id'])
    store_token(user['id'], new_refresh_jti, 'refresh', JWT_REFRESH_EXPIRES)

    return jsonify({
        'access_token': access_token,
        'refresh_token': new_refresh,
        'expires_in': JWT_ACCESS_EXPIRES
    }), 200


# ============================================================
# USER MANAGEMENT API
# ============================================================
@app.route('/api/users', methods=['GET'])
@token_required
@require_permission('user:read')
def list_users():
    users = get_all_users()
    # Serialisasi datetime
    result = []
    for u in users:
        row = dict(u)
        for k, v in row.items():
            if hasattr(v, 'isoformat'):
                row[k] = v.isoformat()
        result.append(row)
    return jsonify({'users': result, 'total': len(result)}), 200


@app.route('/api/users/<int:user_id>', methods=['GET'])
@token_required
@require_permission('user:read')
def get_user(user_id):
    from flask import g
    current = g.current_user
    # User biasa hanya bisa lihat profil sendiri
    if current['role'] == 'user' and current['id'] != user_id:
        return jsonify({'error': 'Akses ditolak', 'code': 'FORBIDDEN'}), 403

    user = get_user_by_id(user_id)
    if not user:
        return jsonify({'error': 'User tidak ditemukan'}), 404

    row = dict(user)
    for k, v in row.items():
        if hasattr(v, 'isoformat'):
            row[k] = v.isoformat()
    row.pop('password_hash', None)
    return jsonify(row), 200


@app.route('/api/users', methods=['POST'])
@token_required
@require_permission('user:write')
def add_user():
    ip = get_client_ip()
    ua = get_user_agent()
    from flask import g
    current = g.current_user

    data = request.get_json(silent=True) or {}
    username = str(data.get('username', '')).strip()
    email = str(data.get('email', '')).strip()
    password = str(data.get('password', ''))
    role_id = int(data.get('role_id', 3))

    if not all([username, email, password]):
        return jsonify({'error': 'Username, email, dan password wajib diisi'}), 400

    # Superadmin saja yang boleh assign role superadmin (id=1)
    if role_id == 1 and current['role'] != 'superadmin':
        return jsonify({'error': 'Hanya superadmin yang dapat memberikan role superadmin'}), 403

    valid, msg = validate_password_strength(password)
    if not valid:
        return jsonify({'error': msg}), 400

    try:
        user_id = create_user(username, email, password, role_id)
        log_action(current['id'], 'CREATE_USER', 'user_management', ip, ua, 'success', {'new_user_id': user_id})
        return jsonify({'message': 'User berhasil dibuat', 'user_id': user_id}), 201
    except ValueError as e:
        return jsonify({'error': str(e)}), 409


@app.route('/api/users/<int:user_id>', methods=['PUT'])
@token_required
@require_permission('user:write')
def edit_user(user_id):
    ip = get_client_ip()
    ua = get_user_agent()
    from flask import g
    current = g.current_user

    data = request.get_json(silent=True) or {}
    allowed = {}
    if 'email' in data:
        allowed['email'] = str(data['email']).strip()
    if 'role_id' in data:
        role_id = int(data['role_id'])
        if role_id == 1 and current['role'] != 'superadmin':
            return jsonify({'error': 'Hanya superadmin yang dapat memberikan role superadmin'}), 403
        allowed['role_id'] = role_id
    if 'is_active' in data:
        allowed['is_active'] = bool(data['is_active'])

    if not allowed:
        return jsonify({'error': 'Tidak ada field yang valid untuk diupdate'}), 400

    success = update_user(user_id, allowed)
    if not success:
        return jsonify({'error': 'User tidak ditemukan'}), 404

    if not allowed.get('is_active', True):
        revoke_all_user_tokens(user_id)

    log_action(current['id'], 'UPDATE_USER', 'user_management', ip, ua, 'success', {'target_user': user_id, 'fields': list(allowed.keys())})
    return jsonify({'message': 'User berhasil diupdate'}), 200


@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@token_required
@require_permission('user:delete')
def remove_user(user_id):
    ip = get_client_ip()
    ua = get_user_agent()
    from flask import g
    current = g.current_user

    if current['id'] == user_id:
        return jsonify({'error': 'Tidak dapat menghapus akun sendiri'}), 400

    revoke_all_user_tokens(user_id)
    success = delete_user(user_id)
    if not success:
        return jsonify({'error': 'User tidak ditemukan'}), 404

    log_action(current['id'], 'DELETE_USER', 'user_management', ip, ua, 'success', {'deleted_user_id': user_id})
    return jsonify({'message': 'User berhasil dihapus'}), 200


@app.route('/api/users/<int:user_id>/change-password', methods=['POST'])
@token_required
def change_password(user_id):
    ip = get_client_ip()
    ua = get_user_agent()
    from flask import g
    current = g.current_user

    # Hanya bisa ubah password diri sendiri, atau admin/superadmin
    if current['id'] != user_id and current['role'] not in ('admin', 'superadmin'):
        return jsonify({'error': 'Akses ditolak'}), 403

    data = request.get_json(silent=True) or {}
    new_password = str(data.get('new_password', ''))

    valid, msg = validate_password_strength(new_password)
    if not valid:
        return jsonify({'error': msg}), 400

    update_password(user_id, new_password)
    revoke_all_user_tokens(user_id)
    log_action(current['id'], 'CHANGE_PASSWORD', 'user_management', ip, ua, 'success', {'target_user': user_id})
    return jsonify({'message': 'Password berhasil diubah. Silakan login ulang.'}), 200


# ============================================================
# PROFILE API
# ============================================================
@app.route('/api/profile', methods=['GET'])
@token_required
def get_profile():
    from flask import g
    current = g.current_user
    user = get_user_by_id(current['id'])
    if not user:
        return jsonify({'error': 'User tidak ditemukan'}), 404
    row = dict(user)
    for k, v in row.items():
        if hasattr(v, 'isoformat'):
            row[k] = v.isoformat()
    row.pop('password_hash', None)
    return jsonify(row), 200


# ============================================================
# ROLES API
# ============================================================
@app.route('/api/roles', methods=['GET'])
@token_required
@require_permission('role:read')
def list_roles():
    roles = get_all_roles()
    return jsonify({'roles': roles}), 200


# ============================================================
# AUDIT LOGS API
# ============================================================
@app.route('/api/audit-logs', methods=['GET'])
@token_required
@require_permission('log:read')
def audit_logs():
    limit = min(int(request.args.get('limit', 100)), 500)
    logs = get_audit_logs(limit)
    result = []
    for log in logs:
        row = dict(log)
        for k, v in row.items():
            if hasattr(v, 'isoformat'):
                row[k] = v.isoformat()
        result.append(row)
    return jsonify({'logs': result, 'total': len(result)}), 200


# ============================================================
# OAUTH2 INFO ENDPOINT (Edukasi Least Privilege)
# ============================================================
@app.route('/api/oauth2/info', methods=['GET'])
@token_required
def oauth2_info():
    return jsonify({
        'concept': 'OAuth 2.0 dengan Prinsip Least Privilege',
        'description': 'OAuth2 memungkinkan delegasi akses terbatas tanpa berbagi password.',
        'grant_types': [
            {'type': 'authorization_code', 'use_case': 'Aplikasi web server-side (paling aman)'},
            {'type': 'client_credentials', 'use_case': 'Komunikasi antar service (M2M)'},
            {'type': 'implicit', 'use_case': 'Deprecated - jangan digunakan'},
            {'type': 'device_code', 'use_case': 'Perangkat tanpa browser'}
        ],
        'scopes_example': {
            'read:profile': 'Hanya baca profil',
            'write:profile': 'Edit profil',
            'read:data': 'Baca data',
            'admin:all': 'Akses penuh (hindari jika bisa)'
        },
        'least_privilege': 'Selalu minta scope minimal yang diperlukan aplikasi.'
    }), 200


# ============================================================
# ERROR HANDLERS
# ============================================================
@app.errorhandler(429)
def rate_limit_exceeded(e):
    return jsonify({'error': 'Terlalu banyak permintaan. Coba lagi nanti.', 'code': 'RATE_LIMIT_EXCEEDED'}), 429


@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Endpoint tidak ditemukan', 'code': 'NOT_FOUND'}), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({'error': 'Terjadi kesalahan server', 'code': 'SERVER_ERROR'}), 500


if __name__ == '__main__':
    print("=" * 60)
    print(" Secure Auth System - Flask Backend")
    print(" http://127.0.0.1:5000")
    print("=" * 60)
    app.run(debug=True, host='127.0.0.1', port=5000)
