"""
models.py - Database Models & Query Layer
Menggunakan PyMySQL langsung (tanpa ORM) untuk kontrol penuh
"""
import os
import json
import pymysql
import pymysql.cursors
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
from security import (
    hash_password, verify_password, generate_session_token,
    generate_csrf_token, hash_session_token
)

load_dotenv()


def get_db():
    """Buat koneksi database baru"""
    return pymysql.connect(
        host=os.getenv('DB_HOST', 'localhost'),
        port=int(os.getenv('DB_PORT', 3306)),
        user=os.getenv('DB_USER', 'root'),
        password=os.getenv('DB_PASSWORD', ''),
        database=os.getenv('DB_NAME', 'secure_auth_db'),
        charset='utf8mb4',
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=False,
        connect_timeout=10
    )


# ============================================================
# USER QUERIES
# ============================================================
def get_user_by_username(username: str) -> dict | None:
    """Ambil user by username (gunakan parameterized query)"""
    conn = get_db()
    try:
        with conn.cursor() as cur:
            # Parameterized query - mencegah SQL Injection
            cur.execute("""
                SELECT u.*, r.name as role_name, r.permissions as role_permissions
                FROM users u
                JOIN roles r ON u.role_id = r.id
                WHERE u.username = %s
            """, (username,))
            user = cur.fetchone()
            if user and user.get('role_permissions'):
                if isinstance(user['role_permissions'], str):
                    user['role_permissions'] = json.loads(user['role_permissions'])
            return user
    finally:
        conn.close()


def get_user_by_id(user_id: int) -> dict | None:
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT u.id, u.username, u.email, u.is_active, u.is_verified,
                       u.last_login, u.last_login_ip, u.created_at, u.updated_at,
                       r.name as role_name, r.permissions as role_permissions
                FROM users u
                JOIN roles r ON u.role_id = r.id
                WHERE u.id = %s
            """, (user_id,))
            user = cur.fetchone()
            if user and user.get('role_permissions'):
                if isinstance(user['role_permissions'], str):
                    user['role_permissions'] = json.loads(user['role_permissions'])
            return user
    finally:
        conn.close()


def get_all_users() -> list:
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT u.id, u.username, u.email, u.is_active, u.is_verified,
                       u.failed_login_attempts, u.locked_until,
                       u.last_login, u.last_login_ip, u.created_at,
                       r.name as role_name
                FROM users u
                JOIN roles r ON u.role_id = r.id
                ORDER BY u.created_at DESC
            """)
            return cur.fetchall()
    finally:
        conn.close()


def create_user(username: str, email: str, password: str, role_id: int = 3) -> int:
    """Buat user baru dengan password di-hash"""
    pw_hash = hash_password(password)
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO users (username, email, password_hash, role_id, is_verified)
                VALUES (%s, %s, %s, %s, TRUE)
            """, (username, email, pw_hash, role_id))
            conn.commit()
            return cur.lastrowid
    except pymysql.IntegrityError as e:
        conn.rollback()
        raise ValueError(f"Username atau email sudah terdaftar: {e}")
    finally:
        conn.close()


def update_user(user_id: int, data: dict) -> bool:
    """Update data user (field yang diizinkan saja)"""
    allowed = {'email', 'role_id', 'is_active', 'is_verified'}
    fields = {k: v for k, v in data.items() if k in allowed}
    if not fields:
        return False

    set_clause = ', '.join(f"{k} = %s" for k in fields)
    values = list(fields.values()) + [user_id]

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute(f"UPDATE users SET {set_clause} WHERE id = %s", values)
            conn.commit()
            return cur.rowcount > 0
    finally:
        conn.close()


def update_password(user_id: int, new_password: str) -> bool:
    pw_hash = hash_password(new_password)
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE users SET password_hash = %s WHERE id = %s", (pw_hash, user_id))
            conn.commit()
            return cur.rowcount > 0
    finally:
        conn.close()


def delete_user(user_id: int) -> bool:
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
            conn.commit()
            return cur.rowcount > 0
    finally:
        conn.close()


# ============================================================
# BRUTE FORCE PROTECTION
# ============================================================
def record_failed_login(username: str, max_attempts: int, lockout_seconds: int):
    """Catat percobaan login gagal, kunci akun jika melebihi batas"""
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE users
                SET failed_login_attempts = failed_login_attempts + 1,
                    locked_until = CASE
                        WHEN failed_login_attempts + 1 >= %s
                        THEN DATE_ADD(NOW(), INTERVAL %s SECOND)
                        ELSE locked_until
                    END
                WHERE username = %s
            """, (max_attempts, lockout_seconds, username))
            conn.commit()
    finally:
        conn.close()


def reset_failed_login(user_id: int, ip_address: str):
    """Reset counter login gagal setelah berhasil login"""
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE users
                SET failed_login_attempts = 0, locked_until = NULL,
                    last_login = NOW(), last_login_ip = %s
                WHERE id = %s
            """, (ip_address, user_id))
            conn.commit()
    finally:
        conn.close()


def is_account_locked(user: dict) -> bool:
    """Cek apakah akun sedang dikunci"""
    if not user.get('locked_until'):
        return False
    locked_until = user['locked_until']
    if isinstance(locked_until, datetime):
        return locked_until > datetime.now()
    return False


# ============================================================
# TOKEN MANAGEMENT (JWT Blacklist)
# ============================================================
def store_token(user_id: int, jti: str, token_type: str, expires_seconds: int):
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO tokens (user_id, jti, token_type, expires_at)
                VALUES (%s, %s, %s, DATE_ADD(NOW(), INTERVAL %s SECOND))
            """, (user_id, jti, token_type, expires_seconds))
            conn.commit()
    finally:
        conn.close()


def revoke_token(jti: str):
    """Masukkan token ke blacklist (logout)"""
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE tokens SET is_revoked = TRUE WHERE jti = %s", (jti,))
            conn.commit()
    finally:
        conn.close()


def is_token_revoked(jti: str) -> bool:
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT is_revoked FROM tokens WHERE jti = %s", (jti,))
            row = cur.fetchone()
            if not row:
                return True  # Token tidak dikenal = revoked
            return bool(row['is_revoked'])
    finally:
        conn.close()


def revoke_all_user_tokens(user_id: int):
    """Cabut semua token user (force logout semua sesi)"""
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE tokens SET is_revoked = TRUE WHERE user_id = %s", (user_id,))
            conn.commit()
    finally:
        conn.close()


# ============================================================
# SESSION MANAGEMENT
# ============================================================
def create_session(user_id: int, ip_address: str, user_agent: str) -> tuple[str, str]:
    """Buat sesi baru, kembalikan (session_token, csrf_token)"""
    raw_token = generate_session_token()
    hashed_token = hash_session_token(raw_token)
    csrf_token = generate_csrf_token()

    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO sessions (user_id, session_token, csrf_token, ip_address, user_agent, expires_at)
                VALUES (%s, %s, %s, %s, %s, DATE_ADD(NOW(), INTERVAL 24 HOUR))
            """, (user_id, hashed_token, csrf_token, ip_address[:45], user_agent[:500]))
            conn.commit()
    finally:
        conn.close()

    return raw_token, csrf_token


def get_session(raw_token: str) -> dict | None:
    """Validasi sesi (cek IP untuk deteksi session hijacking)"""
    hashed = hash_session_token(raw_token)
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT * FROM sessions
                WHERE session_token = %s AND is_active = TRUE AND expires_at > NOW()
            """, (hashed,))
            return cur.fetchone()
    finally:
        conn.close()


def invalidate_session(raw_token: str):
    hashed = hash_session_token(raw_token)
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE sessions SET is_active = FALSE WHERE session_token = %s", (hashed,))
            conn.commit()
    finally:
        conn.close()


def update_session_activity(raw_token: str):
    hashed = hash_session_token(raw_token)
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE sessions SET last_activity = NOW() WHERE session_token = %s", (hashed,))
            conn.commit()
    finally:
        conn.close()


# ============================================================
# AUDIT LOG
# ============================================================
def log_action(user_id: int | None, action: str, resource: str,
               ip_address: str, user_agent: str, status: str, details: dict = None):
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO audit_logs (user_id, action, resource, ip_address, user_agent, status, details)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (user_id, action, resource, ip_address, user_agent[:500], status,
                  json.dumps(details) if details else None))
            conn.commit()
    finally:
        conn.close()


def get_audit_logs(limit: int = 100) -> list:
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT al.*, u.username
                FROM audit_logs al
                LEFT JOIN users u ON al.user_id = u.id
                ORDER BY al.created_at DESC
                LIMIT %s
            """, (limit,))
            return cur.fetchall()
    finally:
        conn.close()


# ============================================================
# ROLES
# ============================================================
def get_all_roles() -> list:
    conn = get_db()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM roles ORDER BY id")
            roles = cur.fetchall()
            for r in roles:
                if isinstance(r.get('permissions'), str):
                    r['permissions'] = json.loads(r['permissions'])
            return roles
    finally:
        conn.close()
