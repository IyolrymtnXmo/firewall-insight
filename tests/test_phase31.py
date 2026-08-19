from app.checkpoint import CheckPointRateLimitError, CheckPointAPIError

def test_rate_limit_error_is_api_error():
    assert issubclass(CheckPointRateLimitError, CheckPointAPIError)
