#!/bin/bash

ssh root@192.168.32.177 mkdir -p /storage/.kodi/addons/service.presence.detector/lib/
scp presence_detector.py root@192.168.32.177:/storage/.kodi/addons/service.presence.detector/service.py
scp -r lib root@192.168.32.177:/storage/.kodi/addons/service.presence.detector/
scp -r kodi/* root@192.168.32.177:/storage/.kodi/addons/service.presence.detector/
