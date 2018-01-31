import paho.mqtt.client as mqtt

mqttc = mqtt.Client("presence_detector")

mqttc.connect('192.168.32.91')

# pinkie home/away
mqttc.publish('test/domoticz/in', '{"command": "setuservariable", "idx": 1, "value": "HOME" }')
#mqttc.publish('test/domoticz/in', '{"command": "setuservariable", "idx": 1, "value": "AWAY" }')

# greenie home/away
mqttc.publish('test/domoticz/in', '{"command": "setuservariable", "idx": 2, "value": "HOME" }')
#mqttc.publish('test/domoticz/in', '{"command": "setuservariable", "idx": 2, "value": "AWAY" }')
