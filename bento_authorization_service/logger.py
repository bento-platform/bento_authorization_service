import logging

from bento_lib.logging import log_level_from_str
from .config import get_config

__all__ = [
    "logger",
]

logging.basicConfig(level=logging.DEBUG)

# TODO: convert to injectable thing for FastAPI

logger = logging.getLogger(__name__)
logger.setLevel(log_level_from_str(get_config().log_level))
