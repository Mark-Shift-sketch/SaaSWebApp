import os
from dotenv import load_dotenv
import mysql.connector

load_dotenv()

Email = (
    os.environ.get("SMTP_EMAIL")
    or os.environ.get("email")
)
password = (
    os.environ.get("SMTP_PASSWORD")
    or os.environ.get("pass")
)


def _get_env(name, fallback_name=None, default=None):
    value = os.environ.get(name)
    if (value is None or str(value).strip() == "") and fallback_name:
        value = os.environ.get(fallback_name)
    if value is None:
        return default
    return str(value).strip()

def get_connection():
    return mysql.connector.connect(
        host=_get_env("DB_HOST", default="localhost"),
        user=_get_env("DB_USER", default="root"),
        password=_get_env("DB_PASSWORD", "DB_PASS", default=""),
        database=_get_env("DB_NAME", default="sysdb"),
    )
