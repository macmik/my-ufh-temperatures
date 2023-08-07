import logging
from datetime import datetime as DT
from sensor.mija.bluetooth_utils import (
    toggle_device, parse_le_advertising_events, enable_le_scan, raw_packet_to_str, decode_data_atc
)
from temperature_measurement import Measurement
from worker import Worker

import bluetooth._bluetooth as bluez


logger = logging.getLogger(__name__)


class MeasurementCollector(Worker):
    def _do(self):
        device_id = self._config['device_id']
        try:
            toggle_device(device_id, enable=True)
            sock = bluez.hci_open_dev(device_id)
            enable_le_scan(sock, filter_duplicates=False)
            logger.debug("Starting bluetooth scanner.")
            parse_le_advertising_events(
                sock=sock,
                handler=self._le_advertise_packet_handler,
                debug=False,
                stop_event=self._stop_event,
            )
        except Exception as e:
            logger.error(e)
            toggle_device(device_id, enable=False)

    def _le_advertise_packet_handler(self, mac, adv_type, data, rssi):
        data_str = raw_packet_to_str(data)
        measurement = Measurement(0, 0, 0, 0, 0, 0, 0, 0)
        measurement = decode_data_atc(mac, adv_type, data_str, rssi, measurement)

        logger.debug(f'Detected {measurement} for {mac}.')
        if not measurement:
            return
        if measurement.temperature == 0:
            return
        self._queue.put((DT.now(), mac, measurement))



