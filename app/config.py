from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    checkpoint_mgmt: str = "https://127.0.0.1"
    checkpoint_user: str = ""
    checkpoint_password: str = ""
    checkpoint_domain: str = ""
    checkpoint_verify_ssl: bool = False
    checkpoint_timeout: float = 90.0
    checkpoint_min_request_interval: float = 0.55
    checkpoint_rate_limit_retries: int = 4
    checkpoint_rate_limit_base_delay: float = 2.0
    checkpoint_cache_ttl: int = 300

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", case_sensitive=False)

settings = Settings()
