#!/usr/bin/env python3

## ProxyTool v3.1
## Basically v3.0 but ported to falconpy SDK instead of reinventing the wheel
## It now requires falconpy (https://github.com/CrowdStrike/falconpy) instead of requests


import json
import os
import time
import datetime

def log(s):
    print(datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S") + '  ' + str(s))


try:    
    from falconpy import Hosts
    from falconpy import OAuth2
    from falconpy import RealTimeResponse
except ImportError as err:
    log(err)
    log('Python falconpy library is required. Install with: python3 -m pip install crowdstrike-falconpy')
    exit()

try:
    import creds
except ImportError as err:
    log(err)
    log('The file config.py cannot be found.')
    exit()


if (creds.api_client_id == "" or creds.api_client_secret == ""):
    log("Please configure the API credentials first")
    exit()
else:
    log("Using API client " + creds.api_client_id)

#####################################


log("Starting execution of ProxyTool v3")

log("Authenticating to API")
auth = OAuth2(client_id=creds.api_client_id, client_secret=creds.api_client_secret)



## Fetch list of hosts

log("Getting all hosts")

offset = ""
hosts_all = []

falcon = Hosts(auth_object=auth)

while True:
    batch_size = 5000 ## 5000 is max supported by API
    
    response = falcon.query_devices_by_filter_scroll(offset=offset, limit=batch_size, filter="platform_name:'Windows'")
    offset = response['body']['meta']['pagination']['offset']

    for host_id in response['body']['resources']:
        hosts_all.append(host_id)

    log("-- Fetched " + str(len(response['body']['resources'])) + ' hosts, ' + str(len(hosts_all)) + '/' + str(response['body']['meta']['pagination']['total']))

    if len(hosts_all) >= int(response['body']['meta']['pagination']['total']):
        break

log("-- Retrieved a total of " + str(len(hosts_all)) + " hosts")


## Now that we have the host IDs, we create a batch RTR list of commands to execute it in all hosts

falcon = RealTimeResponse(auth_object=auth)

## Get batch id

response = falcon.batch_init_sessions(host_ids=hosts_all, queue_offline=True)
batch_id = response['body']['batch_id']

if batch_id:
    log("Initiated RTR batch with id " + batch_id)
else:
    exit()


## Commands to change proxy config
## Delete DisableProxy, PAC, PN, PP in both locations. Change CsProxyHostname and CsProxyport with new values


registry_stores = ["HKLM:\SYSTEM\Crowdstrike\{9b03c1d9-3138-44ed-9fae-d9f4c034b88d}\{16e0423f-7058-48c9-a204-725362b67639}\Default", 
                    "HKLM:\SYSTEM\CurrentControlSet\Services\CSAgent\Sim"]

registry_keys_to_delete = ["DisableProxy", "PAC", "PN", "PP"]

response = falcon.batch_active_responder_command(batch_id=batch_id, base_command="reg delete", command_string="reg delete HKLM:\SYSTEM\CurrentControlSet Test")

for store in registry_stores:
    for key in registry_keys_to_delete:
        response = falcon.batch_active_responder_command(batch_id=batch_id, base_command="reg delete", command_string="reg delete " + store + " " + key)
        if response["status_code"] == 201:
            log("-- Issuing registry deletion for " + key + " in " + store)
        else:
            log("Error, Response: " + response["status_code"] + " - " + response.text)
            exit()           
    
    code = falcon.batch_active_responder_command(batch_id=batch_id, base_command="reg set", command_string="reg set " + store + " CsProxyHostname -ValueType=REG_SZ -Value=" + creds.proxy_hostname)
    if response["status_code"] == 201:
        log("-- Issuing registry setting of CsProxyHostname to " + creds.proxy_hostname + " in " + store)
    else:
        log("Error, Response: " + response["status_code"] + " - " + response.text)
        exit()   

    code = falcon.batch_active_responder_command(batch_id=batch_id, base_command="reg set", command_string="reg set " + store + " CsProxyport -ValueType=REG_DWORD -Value=" + creds.proxy_port)
    if response["status_code"] == 201:
        log("-- Issuing registry setting of CsProxyport to " + creds.proxy_hostname + " in " + store)
    else:
        log("Error, Response: " + response["status_code"] + " - " + response.text)
        exit()   

log("-- Finished launching RTR commands, please check progress in the RTR audit logs")


log("End")