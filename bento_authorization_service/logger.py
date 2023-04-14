import logging

from .config import config

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

logger = logging.getLogger(__name__)
logger.setLevel(log_config_to_log_level[config.log_level])
