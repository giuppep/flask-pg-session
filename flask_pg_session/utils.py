import logging
import time
from functools import wraps
from typing import Any, Callable

logger = logging.getLogger(__name__)


def retry_query(
    *, max_attempts: int = 3, delay: float = 0.3, backoff: int = 2
) -> Callable[..., Any]:
    """Decorator to retry a query when an OperationalError is raised.

    Args:
        max_attempts: Maximum number of attempts. Defaults to 3.
        delay: Delay between attempts in seconds. Defaults to 0.3.
        backoff: Backoff factor. Defaults to 2.
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                # TODO: use proper exception type
                except Exception as e:
                    if attempt == max_attempts - 1:
                        raise e

                    sleep_time = delay * backoff**attempt
                    logger.warning(
                        f"Exception when querying database ({e})."
                        f"Retrying ({attempt + 1}/{max_attempts}) in {sleep_time:.2f}s."
                    )
                    time.sleep(sleep_time)

        return wrapper

    return decorator
