# -*- coding: utf-8 -*-

from datetime import datetime

from config import LOG_TIMESTAMP_FORMAT


def log(message=""):
    text = str(message)
    prefix = datetime.now().strftime(LOG_TIMESTAMP_FORMAT)
    if text.startswith("\n"):
        print("\n" + prefix + " " + text[1:], flush=True)
    else:
        print(prefix + " " + text, flush=True)
