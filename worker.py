import time
import logging
from abc import ABC, abstractmethod
from threading import Thread

logger = logging.getLogger(__name__)


class Worker(Thread, ABC):
    def __init__(self, config, stop_event, queue):
        super().__init__()
        self._config = config
        self._stop_event = stop_event
        self._queue = queue

    def run(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._do()
            except Exception as e:
                logger.error(e)
                time.sleep(1)

    @abstractmethod
    def _do(self):
        pass
