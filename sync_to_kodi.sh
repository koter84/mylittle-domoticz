#!/bin/bash

kodi="root@192.168.32.191"

ssh ${kodi} mkdir -p /storage/.kodi/addons/service.presence.detector/lib/
scp presence_detector.py ${kodi}:/storage/.kodi/addons/service.presence.detector/service.py
scp -r lib ${kodi}:/storage/.kodi/addons/service.presence.detector/
scp -r kodi/* ${kodi}:/storage/.kodi/addons/service.presence.detector/
