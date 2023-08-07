from worker import Worker
from state import State


class MijaMeasurementConsumer(Worker):
    def __init__(self,  config, stop_event, queue, state):
        super(MijaMeasurementConsumer, self).__init__(config, stop_event, queue)
        self._state = state

    def _do(self):
        frame = self._queue.get()
        self._state.update(frame)
