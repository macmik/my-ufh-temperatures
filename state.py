from threading import Lock


class State:
    def __init__(self, config):
        self._config = config
        self._lock = Lock()
        self._state = {}

    def get(self):
        with self._lock:
            return self._state

    def update(self, frame):
        ts, mac, measurement = frame
        with self._lock:
            self._state[mac] = {
                'last_updated': ts.strftime('%Y%m%d-%H%M%S.%f'),
                'measurement': {
                    'temperature': measurement.temperature,
                    'humidity': measurement.humidity,
                    'battery': measurement.battery,
                }
            }
