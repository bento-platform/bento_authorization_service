import logging

from .config import get_config

__all__ = [
    "logger",
]

log_config_to_log_level = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
}

logging.basicConfig(level=logging.DEBUG)

# TODO: convert to injectable thing for FastAPI

logger = logging.getLogger(__name__)
logger.setLevel(log_config_to_log_level[get_config().log_level])
