rsync -avr --exclude "*venv*" --exclude ".git*" --exclude ".idea" --exclude "config.json" ../ pi@192.168.68.102:/home/pi/my-ufh-temperatures
rsync -avr --exclude "*venv*" --exclude ".git*" --exclude ".idea" --exclude "config.json" ../ pi@192.168.68.108:/home/pi/my-ufh-temperatures
