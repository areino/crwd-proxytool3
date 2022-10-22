#!/usr/bin/env python3

## ProxyTool v3

import json
import os
import time
import datetime

def log(s):
    print(datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S") + '  ' + str(s))

log("Starting execution of ProxyTool v3")


try:
    import requests
except ImportError as err:
    log(err)
    log('Python requests library is required.')
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



## Logic to cache API access token or request a new one if expired or not there

needsToken = False
if os.path.exists(creds.token_filename):
    mod_time = os.path.getmtime(creds.token_filename)
    now_time = int(time.time())
    delta = int(now_time - mod_time)
    log("-- Cached token found (" + str(delta) + " seconds old, max is " + str(creds.max_duration) + ")")    

    if delta < creds.max_duration:
        # Get cached token from file
        log("-- Reusing cached token")    
        f = open(creds.token_filename, 'r')
        access_token = f.read()
        f.close()
    else:
        needsToken = True  
else:
    needsToken = True

if needsToken:
    log("-- Fetching new token from API")    

    url = creds.cloud_domain + "/oauth2/token"
    payload = "client_id=" + creds.api_client_id + "&client_secret=" + creds.api_client_secret
    headers = { 'Content-Type': 'application/x-www-form-urlencoded' }
    
    response = requests.request("POST", url, headers=headers, data=payload)
    response = response.json()
    access_token = response['access_token']
    log("Got access token for " + str(response['expires_in']) + " seconds")

    f = open(creds.token_filename, "w")
    f.write(access_token)
    f.close()
    log("-- New token cached")    


## Fetch list of hosts (FQL filter to find host IDs)
## https://falcon.crowdstrike.com/documentation/84/host-and-host-group-management-apis
## Use /devices/queries/devices-scroll/v1 instead, with continuous pagination
## -- filter (optional) - include CID in filter, to avoid FCTL issues (but CID does not seem to work as filter)


log("Getting all hosts")

offset = ""
hosts_all = []

while True:
    batch_size = 5000 ## 5000 is max supported by API
    url = creds.cloud_domain + "/devices/queries/devices-scroll/v1?limit=" + str(batch_size)
    
    if offset != "":
        url = url + "&offset=" + offset

    url = url + "&filter=platform_name:'Windows'"

    headers = { 'Authorization': 'Bearer ' + access_token, 'Accept': 'application/json' }
    response = requests.request("GET", url, headers=headers)
    response = response.json()

    offset = response['meta']['pagination']['offset']

    for host_id in response['resources']:
        hosts_all.append(host_id)

    log("-- Fetched " + str(len(response['resources'])) + ' hosts, ' + str(len(hosts_all)) + '/' + str(response['meta']['pagination']['total']))

    if len(hosts_all) >= int(response['meta']['pagination']['total']):
        break

log("-- Retrieved a total of " + str(len(hosts_all)) + " hosts")

## Now that we have the host IDs, we create a batch RTR list of commands to execute it in all hosts
##



def rtr_batch_init():
    url = creds.cloud_domain + "/real-time-response/combined/batch-init-session/v1" 
    
    payload = json.dumps({
        "host_ids": hosts_all,
        "queue_offline": True
    })

    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + access_token
    }

    response = requests.request("POST", url, headers=headers, data=payload)
    response = response.json()
    try:
        batch_id = response['batch_id']
    except:
        log("-- RTR batch could not be created")
        log(response)
        return()

    return(batch_id)


def rtr_batch_add_command(batch_id, base_command, command_string):
    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + access_token
    }
    
    payload = {
        "batch_id": batch_id,
        "base_command": base_command,
        "command_string": command_string
    }

    url = creds.cloud_domain + "/real-time-response/combined/batch-active-responder-command/v1"

    response = requests.request("POST", url, headers=headers, data=json.dumps(payload))

    return(response)








## Get batch id
batch_id = rtr_batch_init()
if batch_id:
    log("Initiated RTR batch with id " + batch_id)
else:
    exit()

## Commands to change proxy config
## Delete DisableProxy, PAC, PN, PP in both locations. Change CsProxyHostname and CsProxyport with new values

registry_stores = ["HKLM:\SYSTEM\Crowdstrike\{9b03c1d9-3138-44ed-9fae-d9f4c034b88d}\{16e0423f-7058-48c9-a204-725362b67639}\Default", 
                    "HKLM:\SYSTEM\CurrentControlSet\Services\CSAgent\Sim"]

registry_keys_to_delete = ["DisableProxy", "PAC", "PN", "PP"]

for store in registry_stores:
    for key in registry_keys_to_delete:
        code = rtr_batch_add_command(batch_id, "reg delete", "reg delete " + store + " " + key)
        if code.status_code == 201:
            log("-- Issuing registry deletion for " + key + " in " + store)
        else:
            log("Error, Response: " + code.status_code + " - " + response.text)
            exit()           
    
    code = rtr_batch_add_command(batch_id, "reg set", "reg set " + store + " CsProxyHostname -ValueType=REG_SZ -Value=" + creds.proxy_hostname)
    if code.status_code == 201:
        log("-- Issuing registry setting of CsProxyHostname to " + creds.proxy_hostname + " in " + store)
    else:
        log("Error, Response: " + code.status_code + " - " + response.text)
        exit()   

    code = rtr_batch_add_command(batch_id, "reg set", "reg set " + store + " CsProxyport -ValueType=REG_DWORD -Value=" + creds.proxy_port)
    if code.status_code == 201:
        log("-- Issuing registry setting of CsProxyport to " + creds.proxy_hostname + " in " + store)
    else:
        log("Error, Response: " + code.status_code + " - " + response.text)
        exit()   

log("-- Finished launching RTR commands, please check progress in the RTR audit logs")


log("End")
