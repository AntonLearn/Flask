import os
import environ
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
env = environ.Env()
env.read_env(os.path.join(BASE_DIR, '.env'))

POSTGRES_USER = os.getenv("POSTGRES_USER", default="adv_web")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", default="adv_web")
POSTGRES_DB = os.getenv("POSTGRES_DB", default="adv_web")
POSTGRES_HOST = os.getenv("POSTGRES_HOST", default="127.0.0.1")
POSTGRES_PORT = os.getenv("POSTGRES_PORT", default="5432")
HOST_LOCATION = os.getenv("HOST_LOCATION", default="127.0.0.1")
PORT_LOCATION = int(os.getenv("PORT_LOCATION", default="5000"))
DEBUG = os.getenv("DEBUG", default=True)

PG_DSN = (f'postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}@'
          f'{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}')

URL_USER = f'http://{HOST_LOCATION}:{PORT_LOCATION}/user'
URL_ADV = f'http://{HOST_LOCATION}:{PORT_LOCATION}/adv'

