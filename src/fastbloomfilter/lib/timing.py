import sys
from collections.abc import Callable
from functools import wraps
from time import time


def timing(f: Callable[..., object]) -> Callable[..., object]:
    @wraps(f)
    def wrap(*args: object, **kw: object) -> object:
        ts = time()
        result = f(*args, **kw)
        te = time()
        sys.stderr.write(
            f"func:{f.__name__!r} args:{args!r}, {kw!r} took: {te - ts:2.4f} sec\n"
        )
        return result

    return wrap
