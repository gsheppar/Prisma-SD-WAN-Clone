#!/usr/bin/env python3
import cloudgenix
import argparse
from cloudgenix import jd, jd_detailed
import cloudgenix_settings
import sys
import logging
import os
import datetime
import collections
import csv
from csv import DictReader
import time
import collections
import ipaddress
import json
from datetime import datetime, timedelta
jdout = cloudgenix.jdout


# Global Vars
TIME_BETWEEN_API_UPDATES = 60       # seconds
REFRESH_LOGIN_TOKEN_INTERVAL = 7    # hours
SDK_VERSION = cloudgenix.version
SCRIPT_NAME = 'CloudGenix: Example script: Get Paths'
SCRIPT_VERSION = "v1"
directory = 'path_data'

# Set NON-SYSLOG logging to use function name
logger = logging.getLogger(__name__)


####################################################################
# Read cloudgenix_settings file for auth token or username/password
####################################################################

sys.path.append(os.getcwd())
try:
    from cloudgenix_settings import CLOUDGENIX_AUTH_TOKEN

except ImportError:
    # Get AUTH_TOKEN/X_AUTH_TOKEN from env variable, if it exists. X_AUTH_TOKEN takes network.
    if "X_AUTH_TOKEN" in os.environ:
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('X_AUTH_TOKEN')
    elif "AUTH_TOKEN" in os.environ:
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('AUTH_TOKEN')
    else:
        # not set
        CLOUDGENIX_AUTH_TOKEN = None

try:
    from cloudgenix_settings import CLOUDGENIX_USER, CLOUDGENIX_PASSWORD

except ImportError:
    # will get caught below
    CLOUDGENIX_USER = None
    CLOUDGENIX_PASSWORD = None

def get_service_lable(cgx, label_name):
    label_id = None
    for label in cgx.get.servicelabels().cgx_content["items"]:
        if label['name'] == label_name:
            label_id = label['id']
    if not label_id:
        data = {"name":label_name,"description":None,"tags":None,"type":"cg-transit"}
        resp = cgx.post.servicelabels(data=data)
        if not resp:
            print("Failed creating Service Label " + label_name)
            print(str(jdout(resp)))
        else:
            print("Creating Service Label " + label_name)
            for label in cgx.get.servicelabels().cgx_content["items"]:
                if label['name'] == label_name:
                    label_id = label['id']    
    return label_id
         

def get(cgx):
    prefix_id2n = {}
    path_globalprefixes_list = []        
    for prefix in cgx.get.networkpolicyglobalprefixes().cgx_content["items"]:
        prefix_id2n[prefix['id']] = prefix['name']
        prefix.pop('id')
        prefix.pop('_etag')
        prefix.pop('_schema')
        prefix.pop('_created_on_utc')
        prefix.pop('_updated_on_utc')
        prefix.pop('_debug')
        prefix.pop('_info')
        prefix.pop('_warning')
        prefix.pop('_error')
        path_globalprefixes_list.append(json.dumps(prefix))
    
    path_localprefixes_list = []
    path_localprefixes_site_list = []
    for prefix in cgx.get.tenant_networkpolicylocalprefixes().cgx_content["items"]:
        prefix_id2n[prefix['id']] = prefix['name']
        prefix.pop('id')
        prefix.pop('_etag')
        prefix.pop('_schema')
        prefix.pop('_created_on_utc')
        prefix.pop('_updated_on_utc')
        prefix.pop('_debug')
        prefix.pop('_info')
        prefix.pop('_warning')
        prefix.pop('_error')
        path_localprefixes_list.append(json.dumps(prefix))
    for site in cgx.get.sites().cgx_content["items"]:
        for site_prefix in cgx.get.site_networkpolicylocalprefixes(site_id=site['id']).cgx_content["items"]:
            site_prefix.pop('id')
            site_prefix.pop('_etag')
            site_prefix.pop('_schema')
            site_prefix.pop('_created_on_utc')
            site_prefix.pop('_updated_on_utc')
            site_prefix.pop('_debug')
            site_prefix.pop('_info')
            site_prefix.pop('_warning')
            site_prefix.pop('_error')
            site_prefix['prefix_id'] = prefix_id2n[site_prefix['prefix_id']]
            site_prefix['site_name'] = site['name']
            path_localprefixes_site_list.append(json.dumps(site_prefix))     
    
    dc_group_id2n = {}
    for label in cgx.get.servicelabels().cgx_content["items"]:
        dc_group_id2n[label['id']] = label['name']
    
    network_context_id2n = {}
    for endpoint in cgx.get.networkcontexts().cgx_content["items"]:
        network_context_id2n[endpoint['id']] = endpoint['name']    
    
    app_id2n = {}
    for apps in cgx.get.appdefs().cgx_content["items"]:
        app_id2n[apps['id']] = apps['display_name']
    
    stack_id2n = {}
    for network_stack in cgx.get.networkpolicysetstacks().cgx_content["items"]:
        stack_id2n[network_stack['id']] = network_stack['name']
    
    network_policy_list = []
    network_policy_id2n = {}
    network_policy_rule_list = []

    for network_policy in cgx.get.networkpolicysets().cgx_content["items"]:
        policy_id = network_policy['id']
        network_policy_id2n[network_policy['id']] = network_policy['name']
        network_policy.pop('id')
        network_policy.pop('_etag')
        network_policy.pop('_schema')
        network_policy.pop('_created_on_utc')
        network_policy.pop('_updated_on_utc')
        network_policy.pop('_debug')
        network_policy.pop('_info')
        network_policy.pop('_warning')
        network_policy.pop('_error')
        network_policy.pop('clone_from')
        network_policy_list.append(network_policy)
        for rule in cgx.get.networkpolicyrules(networkpolicyset_id=policy_id).cgx_content["items"]:
            rule.pop('id')
            rule.pop('_etag')
            rule.pop('_schema')
            rule.pop('_created_on_utc')
            rule.pop('_updated_on_utc')
            rule.pop('_debug')
            rule.pop('_info')
            rule.pop('_warning')
            rule.pop('_error')
            rule['networkpolicyset_id'] = network_policy['name']
            if rule['network_context_id']:
                rule['network_context_id'] = network_context_id2n[rule['network_context_id']] 
            if rule['app_def_ids']:
                app_list = []
                for item in rule['app_def_ids']:
                    app_list.append(app_id2n[item])
                rule['app_def_ids'] = app_list 
            if rule['source_prefixes_id']:
                rule['source_prefixes_id'] = prefix_id2n[rule['source_prefixes_id']]
            if rule['destination_prefixes_id']:
                rule['destination_prefixes_id'] = prefix_id2n[rule['destination_prefixes_id']]
            if rule['service_context']:  
                if rule['service_context']['active_service_label_id']:
                    rule['service_context']['active_service_label_id'] = dc_group_id2n[rule['service_context']['active_service_label_id']]
                if rule['service_context']['backup_service_label_id']:
                    rule['service_context']['backup_service_label_id'] = dc_group_id2n[rule['service_context']['backup_service_label_id']]
            network_policy_rule_list.append(rule)
    
    if network_policy_list:
        csv_columns = []
        for key in network_policy_list[0]:
            csv_columns.append(key)
        csv_file = directory + '/'  + "path_policy_list.csv"
        try:
            with open(csv_file, 'w', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
                writer.writeheader()
                for data in network_policy_list:
                    try:
                        writer.writerow(data)
                    except:
                        print("Failed to write data for row")
                print("Saved path_policy_list.csv file")
        except IOError:
            print("CSV Write Failed")
    
    if network_policy_rule_list:
        csv_columns = []
        for key in network_policy_rule_list[0]:
            csv_columns.append(key)
        csv_file = directory + '/'  + "path_policy_rule_list.csv"
        try:
            with open(csv_file, 'w', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
                writer.writeheader()
                for data in network_policy_rule_list:
                    try:
                        writer.writerow(data)
                    except:
                        print("Failed to write data for row")
                print("Saved path_policy_rule_list.csv file")
        except IOError:
            print("CSV Write Failed")
    
    network_labels_list = []
    for network_labels in cgx.get.waninterfacelabels().cgx_content["items"]:
        network_labels.pop('id')
        network_labels.pop('_etag')
        network_labels.pop('_schema')
        network_labels.pop('_created_on_utc')
        network_labels.pop('_updated_on_utc')
        network_labels.pop('_debug')
        network_labels.pop('_info')
        network_labels.pop('_warning')
        network_labels.pop('_error')
        network_labels_list.append(json.dumps(network_labels))
    
    network_policy_stack_list = []
    for network_stack in cgx.get.networkpolicysetstacks().cgx_content["items"]:
        network_stack.pop('id')
        network_stack.pop('_etag')
        network_stack.pop('_schema')
        network_stack.pop('_created_on_utc')
        network_stack.pop('_updated_on_utc')
        network_stack.pop('_debug')
        network_stack.pop('_info')
        network_stack.pop('_warning')
        network_stack.pop('_error')
        if network_stack['policyset_ids']:
            id_list = []
            for item in network_stack['policyset_ids']:
                id_list.append(network_policy_id2n[item])
            network_stack['policyset_ids'] = id_list
        if network_stack['defaultrule_policyset_id']:
            network_stack['defaultrule_policyset_id'] = network_policy_id2n[network_stack['defaultrule_policyset_id']]
        network_policy_stack_list.append(network_stack)
    
    if network_policy_stack_list:
        csv_columns = []
        for key in network_policy_stack_list[0]:
            csv_columns.append(key)
        csv_file = directory + '/'  + "path_policy_stack_list.csv"
        try:
            with open(csv_file, 'w', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=csv_columns)
                writer.writeheader()
                for data in network_policy_stack_list:
                    try:
                        writer.writerow(data)
                    except:
                        print("Failed to write data for row")
                print("Saved path_policy_stack_list.csv file")
        except IOError:
            print("CSV Write Failed")
        
    
    return
    
                                      
def go():
    ############################################################################
    # Begin Script, parse arguments.
    ############################################################################

    # Parse arguments
    parser = argparse.ArgumentParser(description="{0}.".format(SCRIPT_NAME))

    # Allow Controller modification and debug level sets.
    controller_group = parser.add_argument_group('API', 'These options change how this program connects to the API.')
    controller_group.add_argument("--controller", "-C",
                                  help="Controller URI, ex. "
                                       "Alpha: https://api-alpha.elcapitan.cloudgenix.com"
                                       "C-Prod: https://api.elcapitan.cloudgenix.com",
                                  default=None)
    controller_group.add_argument("--insecure", "-I", help="Disable SSL certificate and hostname verification",
                                  dest='verify', action='store_false', default=True)
    login_group = parser.add_argument_group('Login', 'These options allow skipping of interactive login')
    login_group.add_argument("--email", "-E", help="Use this email as User Name instead of prompting",
                             default=None)
    login_group.add_argument("--pass", "-PW", help="Use this Password instead of prompting",
                             default=None)
    debug_group = parser.add_argument_group('Debug', 'These options enable debugging output')
    debug_group.add_argument("--debug", "-D", help="Verbose Debug info, levels 0-2", type=int,
                             default=0)
    
    args = vars(parser.parse_args())
                             
    ############################################################################
    # Instantiate API
    ############################################################################
    cgx_session = cloudgenix.API(controller=args["controller"], ssl_verify=args["verify"])

    # set debug
    cgx_session.set_debug(args["debug"])

    ##
    # ##########################################################################
    # Draw Interactive login banner, run interactive login including args above.
    ############################################################################
    print("{0} v{1} ({2})\n".format(SCRIPT_NAME, SCRIPT_VERSION, cgx_session.controller))

    # login logic. Use cmdline if set, use AUTH_TOKEN next, finally user/pass from config file, then prompt.
    # figure out user
    if args["email"]:
        user_email = args["email"]
    elif CLOUDGENIX_USER:
        user_email = CLOUDGENIX_USER
    else:
        user_email = None

    # figure out password
    if args["pass"]:
        user_password = args["pass"]
    elif CLOUDGENIX_PASSWORD:
        user_password = CLOUDGENIX_PASSWORD
    else:
        user_password = None

    # check for token
    if CLOUDGENIX_AUTH_TOKEN and not args["email"] and not args["pass"]:
        cgx_session.interactive.use_token(CLOUDGENIX_AUTH_TOKEN)
        if cgx_session.tenant_id is None:
            print("AUTH_TOKEN login failure, please check token.")
            sys.exit()

    else:
        while cgx_session.tenant_id is None:
            cgx_session.interactive.login(user_email, user_password)
            # clear after one failed login, force relogin.
            if not cgx_session.tenant_id:
                user_email = None
                user_password = None

    ############################################################################
    # End Login handling, begin script..
    ############################################################################

    # get time now.
    curtime_str = datetime.utcnow().strftime('%Y-%m-%d-%H-%M-%S')

    # create file-system friendly tenant str.
    tenant_str = "".join(x for x in cgx_session.tenant_name if x.isalnum()).lower()
    cgx = cgx_session
    
    if not os.path.exists(directory):
        os.makedirs(directory)
       
    get(cgx)

    # end of script, run logout to clear session.
    cgx_session.get.logout()

if __name__ == "__main__":
    go()