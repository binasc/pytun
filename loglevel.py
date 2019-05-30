import sys
import logging

formatter = logging.Formatter(fmt='%(asctime)-15s %(levelname)-5s %(name)s %(message)s')
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(formatter)

DEFAULT_LEVEL = logging.INFO
DEBUG = logging.DEBUG
INFO = logging.INFO
logging.basicConfig(format=formatter)


def get_logger(name, level=DEFAULT_LEVEL):
    logger = logging.getLogger(name)
    logger.level = level
    if not logger.handlers:
        logger.addHandler(handler)
    logger.propagate = False
    return logger
