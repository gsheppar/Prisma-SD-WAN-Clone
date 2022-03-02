#!/usr/bin/env python3

# 20201020 - Add a function to add a single prefix to a local prefixlist - Dan
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
SCRIPT_NAME = 'CloudGenix: Example script: Get Apps'
SCRIPT_VERSION = "v1"
directory = 'apps_data'

# Set NON-SYSLOG logging to use function name
logger = logging.getLogger(__name__)


####################################################################
# Read cloudgenix_settings file for auth token or username/password
####################################################################

sys.path.append(os.getcwd())
try:
    from cloudgenix_settings import CLOUDGENIX_AUTH_TOKEN

except ImportError:
    # Get AUTH_TOKEN/X_AUTH_TOKEN from env variable, if it exists. X_AUTH_TOKEN takes priority.
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

def deploy(cgx, app_globalprefixes_file, app_file):
    try:
        file_open = open(app_globalprefixes_file, 'r')
        lines = file_open.readlines()
        app_globalprefixes_list = []
        for line in lines:
            app_globalprefixes_list.append(json.loads(line))
        file_present = True
    except:
        print("\nError importing file " + qos_globalprefixes_file)
        print("Skipping qos_globalprefixes_file import")
        file_present = False
    
    if file_present:
        site_n2id = {}
        for site in cgx.get.sites().cgx_content["items"]:
            site_n2id[site['name']] = site['id']
    
        for prefix in app_globalprefixes_list:
            does_exsist = False
            for prefix_current in cgx.get.globalprefixfilters().cgx_content["items"]:
                if prefix_current['name'] == prefix['name']:
                    does_exsist = True
                    is_the_same = True
                    for key in prefix:
                        if prefix_current[key] != prefix[key]:
                            is_the_same = False
                            prefix_current[key] = prefix[key]
                    if is_the_same:      
                        print("Global prefix " + prefix['name'] + " already exsists")
                    else:
                        data = prefix_current
                        resp = cgx.put.globalprefixfilters(globalprefixfilter_id=prefix_current['id'], data=data)
                        if not resp:
                            print("Failed updating global prefix " + prefix_current["name"])
                            print(str(jdout(resp)))
                        else:
                            print("Update global prefix " + prefix_current["name"])
            if not does_exsist:
                resp = cgx.post.globalprefixfilters(data=prefix)
                if not resp:
                    print("Failed creating global prefix " + prefix["name"])
                    print(str(jdout(resp)))
                else:
                    print("Created global prefix " + prefix["name"])          
                

    try:
        file_open = open(app_file, 'r')
        lines = file_open.readlines()
        lists_from_csv = []
        for line in lines:
            lists_from_csv.append(json.loads(line))
        file_present = True
    except:
        print("Error importing file " + app_file)
        print("Skipping app import")
        file_present = False
    
    if file_present:
        for site in cgx.get.sites().cgx_content["items"]:
            site_n2id[site['name']] = site['id']
        
        prefix_id2n = {}
        prefix_n2id = {}
        for prefix in cgx.get.globalprefixfilters().cgx_content["items"]:
            prefix_id2n[prefix['id']] = prefix['name']
            prefix_n2id[prefix['name']] = prefix['id']    
        
        
        for app in lists_from_csv:
            updated_tcp = []
            if  app['tcp_rules']:
                tcp_list = []
                new_rule = list(app['tcp_rules'].split("&"))
                for rule in new_rule:
                    rule_dict = {}
                    rule = json.loads(rule)
                    if rule['server_filters']:
                        tcp_rule_list = []
                        for prefix_rule in rule['server_filters']:
                            tcp_rule_list.append(prefix_n2id[prefix_rule])
                        rule_dict['server_filters'] = tcp_rule_list
                    else:
                        rule_dict['server_filters'] = None
        
                    if rule['client_filters']:
                        tcp_rule_list = []
                        for prefix_rule in rule['client_filters']:
                            tcp_rule_list.append(prefix_n2id[prefix_rule])
                        rule_dict['client_filters'] = tcp_rule_list
                    else:
                        rule_dict['client_filters'] = None
            
                    rule_dict['server_port'] = rule['server_port']
                    rule_dict['client_port'] = rule['client_port']
                    if rule['dscp']:
                        rule_dict['dscp'] = rule['dscp']
                    else:
                        rule_dict['dscp'] = None
                    if rule['server_prefixes']:
                        rule_dict['server_prefixes'] = rule['server_prefixes']
                    else:
                        rule_dict['server_prefixes'] = None
                    tcp_list.append(rule_dict)
                updated_tcp = tcp_list
                app['tcp_rules'] = tcp_list
            else:
                updated_tcp = None
                app['tcp_rules'] = None
            
            updated_udp = []
            if  app['udp_rules']:
                udp_list = []
                new_rule = list(app['udp_rules'].split("&"))
                for rule in new_rule:
                    rule_dict = {}
                    rule = json.loads(rule)
                    if rule['udp_filters']:
                        udp_rule_list = []
                        for prefix_rule in rule['udp_filters']:
                            udp_rule_list.append(prefix_n2id[prefix_rule])
                        rule_dict['udp_filters'] = udp_rule_list
                    else:
                        rule_dict['udp_filters'] = None
                    rule_dict['udp_port'] = rule['udp_port']
                    if rule['dscp']:
                        rule_dict['dscp'] = rule['dscp']
                    else:
                        rule_dict['dscp'] = None
                    if rule['dest_prefixes']:
                        rule_dict['dest_prefixes'] = rule['dest_prefixes']
                    else:
                        rule_dict['dest_prefixes'] = None
                        
                    udp_list.append(rule_dict)
                updated_udp = udp_list
                app['udp_rules'] = updated_udp
            else:
                updated_udp = None
                app['udp_rules'] = None

            updated_ip = []
            if  app['ip_rules']:
                ip_list = []
                new_rule = list(app['ip_rules'].split("&"))
                for rule in new_rule:
                    rule_dict = {}
                    rule = json.loads(rule)
                    rule_dict['protocol'] = rule['protocol']
                    if rule['dest_filters']:
                        ip_rule_list = []
                        for prefix_rule in rule['dest_filters']:
                            ip_rule_list.append(prefix_n2id[prefix_rule])
                        rule_dict['dest_filters'] = ip_rule_list
                    else:
                        rule_dict['dest_filters'] = None
        
                    if rule['src_filters']:
                        ip_rule_list = []
                        for prefix_rule in rule['src_filters']:
                            ip_rule_list.append(prefix_n2id[prefix_rule])
                        rule_dict['src_filters'] = ip_rule_list
                    else:
                        rule_dict['src_filters'] = None
        
                    rule_dict['dscp'] = rule['dscp']
                    rule_dict['dest_prefixes'] = rule['dest_prefixes']
                    ip_list.append(rule_dict)
                updated_ip = ip_list
                app['ip_rules'] = updated_ip
            else:
                updated_ip = None
                app['ip_rules'] = None    
             
            does_exsist = False
            for apps in cgx.get.appdefs().cgx_content["items"]:
                if app['display_name'] == apps['display_name']:
                    does_exsist = True
                    is_the_same = True
                    for key in app:
                        if apps[key] != app[key]:
                            is_the_same = False
                            apps[key] = app[key]
                    
                    if is_the_same:      
                        print(apps['display_name'] + " already exsists") 
                    else:
                        data = apps
                        resp = cgx.put.appdefs(appdef_id=apps['id'], data=data)
                        if not resp:
                            print("Failed updating app " + app['display_name'])
                            print(str(jdout(resp)))
                        else:
                            print("Updating app " + app['display_name'])   
            if not does_exsist:
                data = app
                resp = cgx.post.appdefs(data=data)
                if not resp:
                    print("Failed creating app " + app['display_name'])
                    print(str(jdout(resp)))
                else:
                    print("Creating app " + app['display_name'])
        

required_prefix = []
def get(cgx):
    prefix_id2n = {}
    app_globalprefixes_list = []
    for prefix in cgx.get.globalprefixfilters().cgx_content["items"]:
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
        app_globalprefixes_list.append(json.dumps(prefix))            
    
    if app_globalprefixes_list:
        f = open(directory + '/' + "app_globalprefixes_list.json", "w")
        for item in app_globalprefixes_list:
            f.write(item + "\n")
        print("Saved file app_globalprefixes_list.json")
        f.close()
    
    
    app_list = []
    for apps in cgx.get.appdefs().cgx_content["items"]:
        if apps['app_type'] == "custom":    
            apps.pop('id')
            apps.pop('_etag')
            apps.pop('_schema')
            apps.pop('_created_on_utc')
            apps.pop('_updated_on_utc')
            apps.pop('_debug')
            apps.pop('_info')
            apps.pop('_warning')
            apps.pop('_error')
            
            if  apps['tcp_rules']:
                tcp_list = []
                for rule in apps['tcp_rules']:
                    rule_dict = {}
                    if rule['server_filters']:
                        tcp_rule_list = []
                        for prefix_rule in rule['server_filters']:
                            tcp_rule_list.append(prefix_id2n[prefix_rule])
                            required_prefix.append(prefix_rule)
                        rule_dict['server_filters'] = tcp_rule_list
                    else:
                        rule_dict['server_filters'] = None
            
                    if rule['client_filters']:
                        tcp_rule_list = []
                        for prefix_rule in rule['client_filters']:
                            tcp_rule_list.append(prefix_id2n[prefix_rule])
                            required_prefix.append(prefix_rule)
                        rule_dict['client_filters'] = tcp_rule_list
                    else:
                        rule_dict['client_filters'] = None
                
                    rule_dict['server_port'] = rule['server_port']
                    rule_dict['client_port'] = rule['client_port']
                    if rule['dscp']:
                        rule_dict['dscp'] = rule['dscp']
                    else:
                        rule_dict['dscp'] = None
                    if rule['server_prefixes']:
                        rule_dict['server_prefixes'] = rule['server_prefixes']
                    else:
                        rule_dict['server_prefixes'] = None
                    tcp_list.append(json.dumps(rule_dict))
                apps['tcp_rules'] = '&'.join([str(elem) for elem in tcp_list])
        
            else:
                apps['tcp_rules'] = None
    
            if  apps['udp_rules']:
                udp_list = []
                for rule in apps['udp_rules']:
                    rule_dict = {}
                    if rule['udp_filters']:
                        udp_rule_list = []
                        for prefix_rule in rule['udp_filters']:
                            udp_rule_list.append(prefix_id2n[prefix_rule])
                            required_prefix.append(prefix_rule)
                        rule_dict['udp_filters'] = udp_rule_list
                    else:
                        rule_dict['udp_filters'] = None
                    rule_dict['udp_port'] = rule['udp_port']
                    rule_dict['dscp'] = rule['dscp']
                    rule_dict['dest_prefixes'] = rule['dest_prefixes']
                    udp_list.append(json.dumps(rule_dict))
                apps['udp_rules'] = '&'.join([str(elem) for elem in udp_list])
        
            else:
                apps['udp_rules'] = None
        
    
            if  apps['ip_rules']:
                ip_list = []
                for rule in apps['ip_rules']:
                    rule_dict = {}
                    rule_dict['protocol'] = rule['protocol']
                    if rule['dest_filters']:
                        ip_rule_list = []
                        for prefix_rule in rule['dest_filters']:
                            ip_rule_list.append(prefix_id2n[prefix_rule])
                            required_prefix.append(prefix_rule)
                        rule_dict['dest_filters'] = ip_rule_list
                    else:
                        rule_dict['dest_filters'] = None
            
                    if rule['src_filters']:
                        ip_rule_list = []
                        for prefix_rule in rule['src_filters']:
                            ip_rule_list.append(prefix_id2n[prefix_rule])
                            required_prefix.append(prefix_rule)
                        rule_dict['src_filters'] = ip_rule_list
                    else:
                        rule_dict['src_filters'] = None
            
                    rule_dict['dscp'] = rule['dscp']
                    rule_dict['dest_prefixes'] = rule['dest_prefixes']
                    ip_list.append(json.dumps(rule_dict))
                apps['ip_rules'] = '&'.join([str(elem) for elem in ip_list])
        
            else:
                apps['ip_rules'] = None  
            
            app_list.append(json.dumps(apps))
    
    if app_list:
        f = open(directory + '/'  + "app_list.json", "w")
        for item in app_list:
            f.write(item + "\n")
        print("Saved app_list.json file")
        f.close()    
    
                                      
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

    action = input ("Do you want to get or deploy custom Apps (get or deploy)?")
    if action == "get":
        get(cgx)
    elif action == "deploy":
        app_file = directory + '/app_list.json'
        app_globalprefixes_file = directory + '/app_globalprefixes_list.json'
        deploy(cgx, app_globalprefixes_file, app_file)
    else:
        print("Please type 'get' or 'deploy'")
    # end of script, run logout to clear session.
    cgx_session.get.logout()

if __name__ == "__main__":
    go()