import logging
import logging.handlers

from app.config import settings

LOG_FILE_PATH = settings.LOG_FILE_PATH
MAX_LOG_FILE_SIZE = 20 * 1024 * 1024  # 20 MB
MAX_LOG_FILES = 10

oidc_logger = logging.getLogger(
    f"sv_oidc-{settings.SERVER_INSTANCE_NAME}-{settings.ENV_NAME}-{settings.ENV_VERSION}-logger"
)
oidc_logger.setLevel(logging.INFO)

oidc_formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

file_handler = logging.handlers.RotatingFileHandler(
    filename=LOG_FILE_PATH,
    maxBytes=MAX_LOG_FILE_SIZE,
    backupCount=MAX_LOG_FILES,
)
file_handler.setLevel(logging.INFO)
file_handler.setFormatter(oidc_formatter)
oidc_logger.addHandler(file_handler)

ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
ch.setFormatter(oidc_formatter)
oidc_logger.addHandler(ch)
