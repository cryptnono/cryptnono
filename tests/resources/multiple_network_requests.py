#!/usr/bin/env python
import requests

# example/flowkiller_config.py sets unique_destinations_threshold=10
# so this script should be killed since we're making requests to more
# than 10 ports

# In practice example.org resolves to multiple IPs and since we're
# requesting an invalid port requests.get seems to automatically try
# multiple IPs for the same port so this may be killed before we
# reach 10 ports
for i in range(60000, 60012):
    try:
        # Needs to be a public IP that allows the "Connection established"
        # event to occur even if it's not actually listening
        requests.get(f"http://example.org:{i}", timeout=0.2)
    except Exception as e:
        print(e)

print("Not killed!")
