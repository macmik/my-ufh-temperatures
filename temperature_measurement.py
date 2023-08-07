from dataclasses import dataclass


@dataclass
class Measurement:
    temperature: float
    humidity: int
    voltage: float
    calibratedHumidity: int = 0
    battery: int = 0
    timestamp: int = 0
    sensorname: str = ""
    rssi: int = 0
