# Prisma SD-WAN Clone (Preview)
The purpose of this script is to export and import Custom Apps 

#### Features
 - ./sdwan_clone_apps.py can be used to export Custom Apps (with Global Prefixes) and also import them (moving to a new tenant)
 

#### License
MIT

#### Requirements
* Active CloudGenix Account - Please generate your API token and add it to cloudgenix_settings.py
* Python >=3.6

#### Installation:
 Scripts directory. 
 - **Github:** Download files to a local directory, manually run the scripts. 
 - pip install -r requirements.txt

### Examples of usage:
 Please generate your API token and add it to cloudgenix_settings.py
 
 - Use the ./sdwan_clone_apps.py and enter get to retrive all Custom Apps and Global Prefixies
 1. ./sdwan_clone_apps.py
      - Do you want to get or deploy custom Apps (get or deploy)?

 - Use the ./sdwan_clone_apps.py and enter deploy. Will take the data exported in your /apps-data directory from step 1 and deploy it (if you want to do this to a new tenant change your auth token)
 1. ./sdwan_clone_apps.py
      - Do you want to get or deploy custom Apps (get or deploy)?
 
### Caveats and known issues:
 - This is a PREVIEW release, hiccups to be expected. Please file issues on Github for any problems.

#### Version
| Version | Build | Changes |
| ------- | ----- | ------- |
| **1.0.0** | **b1** | Initial Release. |


#### For more info
 * Get help and additional Prisma SD-WAN Documentation at <https://docs.paloaltonetworks.com/prisma/cloudgenix-sd-wan.html>
