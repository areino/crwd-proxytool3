
## Config and API credentials
##
## API client must have Hosts (Read), Real time response (admin) rights

## Configure desired proxy config

proxy_hostname = "proxyhost.domain.com"
proxy_port = "8080"


## Select your cloud

cloud_domain = "https://api.crowdstrike.com"             # US1 cloud
# cloud_domain = "https://api.us-2.crowdstrike.com"         # US2 cloud
# cloud_domain = "https://api.eu-1.crowdstrike.com"         # EU Cloud
# cloud_domain = "https://api.laggar.gcw.crowdstrike.com"   # Gov Cloud

## Enter CID

cid = "A0C63F1116634DC6A3658027D05D9718"

## Enter your API credentials

api_client_id           = "ENTER YOUR API CLIENT DETAILS HERE"
api_client_secret       = "ENTER YOUR API CLIENT DETAILS HERE"


## Access bearer token caching

max_duration = 1799 ## seconds
token_filename = "token.txt"
