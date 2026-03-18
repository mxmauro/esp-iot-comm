# Provisioning example

To compile and run the example, open an ESP-IDF v5.5 or later terminal and run the following commands:

```bash
idf.py set-target esp32c3    # replace esp32c3 with your device type
idf.py build
idf.py -p COM3 flash monitor    # replace COM3 with the port your device is connected
```
