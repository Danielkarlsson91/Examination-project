<<<<<<< HEAD

=======
>>>>>>> 3-implement-the-client-gui-and-the-server
SPEED = 115200
PORT = /dev/ttyUSB0

clean:
<<<<<<< HEAD
	@rm -rf server/.pio server/.vscode client/__pycache__

client:
	@python3 client/main.py $(PORT):$(SPEED)
=======
	@rm -rf server /.pio server/.vscode client/__pycache

client:
	@python3 client/client.py $(PORT):$(SPEED)
>>>>>>> 3-implement-the-client-gui-and-the-server

server:
	@cd server: \
	export PLATFORMIO_BUILD_FLAGS="-DSPEED=$(SPEED)";\
	pio run -t upload

.PHONY: clean client server