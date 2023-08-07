import sys
import json
import logging
from os import environ
from queue import Queue
from threading import Event
from pathlib import Path

from flask import Flask, jsonify

from sensor.mija.measurement_collector import MeasurementCollector
from consumer.mija_measurement_consumer import MijaMeasurementConsumer
from state import State


def setup_logging():
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    log_level = environ.get("LOG_LVL", "dump")
    if log_level == "dump":
        level = logging.DEBUG
    elif log_level == "info":
        level = logging.INFO
    elif log_level == "error":
        level = logging.ERROR
    elif log_level == "warning":
        level = logging.WARNING
    else:
        logging.error('"%s" is not correct log level', log_level)
        sys.exit(1)
    if getattr(setup_logging, "_already_set_up", False):
        logging.warning("Logging already set up")
    else:
        logging.basicConfig(format="[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s", level=level)
        setup_logging._already_set_up = True


def create_app():
    app = Flask(__name__, static_folder='templates')

    setup_logging()
    config = json.loads(Path('config.json').read_text())

    queue = Queue()
    event = Event()
    state = State(config)

    mija_worker = MeasurementCollector(config, event, queue)
    mija_consumer = MijaMeasurementConsumer(config, event, queue, state)

    mija_worker.start()
    mija_consumer.start()

    app.state = state
    return app


app = create_app()


@app.route('/state')
def state():
    return jsonify(app.state.get())


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=8001)
