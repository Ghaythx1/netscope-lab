"""
NetScope Lab — Application configuration.
"""

from __future__ import annotations

import os
from pathlib import Path


class Config:
    """Base configuration."""
    SECRET_KEY = os.environ.get("NETSCOPE_SECRET_KEY", "netscope-lab-dev-key-change-in-production")
    MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50 MB upload limit
    UPLOAD_FOLDER = str(Path(__file__).parent / "uploads")
    SAMPLE_DATA_DIR = str(Path(__file__).parent / "sample_data")
    DATABASE_PATH = str(Path(__file__).parent.parent / "instance" / "netscope_scans.sqlite3")
    ALLOWED_EXTENSIONS = {"xml", "json"}
    DEBUG = False
    TESTING = False
    LOG_LEVEL = os.environ.get("NETSCOPE_LOG_LEVEL", "INFO")


class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True
    LOG_LEVEL = "DEBUG"


class TestingConfig(Config):
    """Testing configuration."""
    TESTING = True
    LOG_LEVEL = "WARNING"


config_map = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": Config,
    "default": DevelopmentConfig,
}
