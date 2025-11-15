"""MySQL users table + salted hashing (no chat storage).""" 

#!/usr/bin/env python3
import os
import secrets
import hashlib
import hmac
from typing import Optional, Dict

import pymysql
from pymysql.err import IntegrityError, OperationalError
from dotenv import load_dotenv

load_dotenv()  # reads .env in project root

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
DB_NAME = os.getenv("DB_NAME", "securechat")


def _get_conn(connect_db: bool = True):
    """
    Return a new pymysql connection.
    If connect_db is False, do not specify `db` so you can create the DB.
    """
    params = dict(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True,
    )
    if connect_db:
        params["db"] = DB_NAME
    return pymysql.connect(**params)


def init_db():
    """
    Create database and users table if they do not exist.
    Run this once during setup (or at server start).
    """
    create_db_sql = f"CREATE DATABASE IF NOT EXISTS `{DB_NAME}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
    create_table_sql = """
    CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      email VARCHAR(255) NOT NULL,
      username VARCHAR(255) NOT NULL UNIQUE,
      salt VARBINARY(16) NOT NULL,
      pwd_hash CHAR(64) NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """

    # create database
    conn = _get_conn(connect_db=False)
    try:
        with conn.cursor() as cur:
            cur.execute(create_db_sql)
    finally:
        conn.close()

    # create table
    conn = _get_conn(connect_db=True)
    try:
        with conn.cursor() as cur:
            cur.execute(create_table_sql)
    finally:
        conn.close()


def _hash_pwd(salt: bytes, password: str) -> str:
    """
    Return hex(SHA256(salt || password)).
    salt: raw bytes (16 bytes)
    password: string (UTF-8)
    result: 64-char hex string
    """
    if isinstance(password, str):
        password_bytes = password.encode("utf-8")
    else:
        password_bytes = password
    digest = hashlib.sha256(salt + password_bytes).hexdigest()
    return digest


def register_user(email: str, username: str, password: str) -> bool:
    """
    Register a new user.
    - Generates a 16-byte random salt (server-side).
    - Computes pwd_hash = hex(SHA256(salt || password))
    - Stores (email, username, salt, pwd_hash)
    Returns True on success, False if username/email already exists.
    Raises on other DB errors.
    """
    if not (email and username and password):
        raise ValueError("email, username and password are required")

    salt = secrets.token_bytes(16)
    pwd_hash = _hash_pwd(salt, password)

    sql = "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s);"

    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            try:
                cur.execute(sql, (email, username, salt, pwd_hash))
                return True
            except IntegrityError as e:
                # IntegrityError for unique constraint violation (username)
                # Could also check for duplicate email by querying first if you prefer.
                return False
    finally:
        conn.close()


def get_user_by_username_or_email(identifier: str) -> Optional[Dict]:
    """
    Lookup user by username or email. Returns dict with keys:
    id, email, username, salt (bytes), pwd_hash (hex str), created_at
    """
    sql = "SELECT id, email, username, salt, pwd_hash, created_at FROM users WHERE username=%s OR email=%s LIMIT 1;"
    conn = _get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(sql, (identifier, identifier))
            row = cur.fetchone()
            return row
    finally:
        conn.close()


def verify_user(identifier: str, password: str) -> bool:
    """
    Verify login credentials.
    - Fetch salt and stored hash
    - Compute hex(SHA256(salt || password))
    - Constant-time compare with stored pwd_hash using hmac.compare_digest
    Returns True if match, else False.
    """
    user = get_user_by_username_or_email(identifier)
    if not user:
        # Do a fake hash to mitigate timing attacks for non-existent users
        fake_salt = b"\x00" * 16
        _ = _hash_pwd(fake_salt, password)
        return False

    salt = user["salt"]
    stored = user["pwd_hash"]
    computed = _hash_pwd(salt, password)
    # constant-time compare
    return hmac.compare_digest(stored, computed)
