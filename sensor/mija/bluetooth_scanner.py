def le_advertise_packet_handler(mac, adv_type, data, rssi):
    data_str = raw_packet_to_str(data)
    measurement = Measurement(0, 0, 0, 0, 0, 0, 0, 0)
    measurement = decode_data_atc(mac, adv_type, data_str, rssi, measurement)
    if measurement:
        with open('results.csv', 'a') as fo:
            fo.write(','.join([mac, str(DT.utcnow()), str(measurement.temperature), str(measurement.humidity), str(measurement.battery), str(measurement.sensorname), "\n"]))
        print(mac, measurement)
    else:
        print('skipping')