import subprocess
import netifaces
import re

from swsscommon.swsscommon import SonicV2Connector, ConfigDBConnector

#DB Numbers

APPL_DB   = 0
CONFIG_DB = 4
STATE_DB  = 6

#DB Table Separators

APPL_DB_TABLE_SEPARATOR = ":"
CONFIG_DB_TABLE_SEPARATOR = "|"
STATE_DB_TABLE_SEPARATOR = "|"
KEY_ALL = "*"

#DB Connectors

appl_db = SonicV2Connector()
appl_db.connect(appl_db.APPL_DB)

config_db = ConfigDBConnector()
config_db.connect()

state_db = SonicV2Connector()
state_db.connect(state_db.STATE_DB)

###HTTPS TABLE CONSTANTS###

WEB_TABLE = "WEB_TABLE"
WEB_TABLE_KEY = "INFO"
HTTPS_PORT = "https_port"
HTTPS_MODE = "https_mode"
WEB_SESSION_IDLE_TIMEOUT = "web_session_idle_timeout"
WEB_REFRESH_TIMER = "web_refresh_timer"
HTTPS_DATA = "https_data"
CONFIG_DB = "config_db"
HTTPS_ENABLE = "enable"
HTTPS_DISABLE = "disable"
HTTPS_PORT_NO = "port_no"
STATUS_CMD ="systemctl status lighttpd.service"
FORCE_RELOAD_CMD = "sudo systemctl force-reload lighttpd.service"
RESTART_CMD = "sudo systemctl restart lighttpd.service"
START_CMD = "sudo systemctl start lighttpd.service"
STOP_CMD = "sudo systemctl stop lighttpd.service"
IPADDR_SEPARATOR = ":"
PORT_NO_PATTERN = "[0-9]*"
 
###ETH0 CONSTANTS###
ETH0 = "eth0"
ETH0_IP_PATTERN = "192.[0-9]*.[0-9]*.[0-9]*"
LIGHTTPD_CONF_FILE = "/etc/lighttpd/lighttpd.conf"
LIGHTTPD_PROCESS = "lighttpd"

SUCCESS_STATUS = 0
HTTPS_PORT_ALREADY_IN_USE = 1
HTTPS_PORT_FREE = 2
WRITE_FAILURE_STATUS = 3
CMD_ERROR_VALUE = 256

HTTPS_PORT_DEFAULT_VALUE = 443
HTTPS_MODE_DEFAULT_VALUE = "enable"
WEB_SESSION_IDLE_TIMEOUT_VALUE = 30 #minutes
WEB_REFRESH_TIMER_VALUE = 60 #seconds
PROCESS_NOT_RUNNING = 0
PROCESS_RUNNING = 1



##############################################################################
#Function Name    : get_management_information
#Purpose          : To get management informations from netifaces
#Created By       : INDIA_SONIC
#Paramters        : NA
#Output           : It returns mgmt_info
##############################################################################
def get_management_information():
    addr_family = netifaces.ifaddresses(ETH0)

    eth0_ipv4_addr_family = addr_family[2]
    eth0_ipv4_addr = eth0_ipv4_addr_family[0]['addr']
    eth0_ipv4_netmask = eth0_ipv4_addr_family[0]['netmask']
    prefix = sum([bin(int(x)).count('1') for x in eth0_ipv4_netmask.split('.')])
    eth0_ipv4_prefix = eth0_ipv4_addr + "/" + str(prefix)
    eth0_ipv4_broadcast = eth0_ipv4_addr_family[0]['broadcast']

    cmd = "sudo ip address | grep " + eth0_ipv4_addr
    eth0_ipv4_mode_output = run_command(cmd)
    if "dynamic" in eth0_ipv4_mode_output:
        if "global" in eth0_ipv4_mode_output:
            eth0_ipv4_mode = "Global DHCP"
        else:
            eth0_ipv4_mode = "Static DHCP"
    else:
        eth0_ipv4_mode = "Static"
    
    eth0_ipv6_addr_family = addr_family[10]
    eth0_ipv6_addr = eth0_ipv6_addr_family[0]['addr']
    eth0_ipv6_netmask = eth0_ipv6_addr_family[0]['netmask']
    eth0_mac = addr_family[17][0]['addr']

    cmd = "sudo ip address | grep " + eth0_ipv6_addr
    eth0_ipv6_mode_output = run_command(cmd)
    if "dynamic" in eth0_ipv6_mode_output:
        if "global" in eth0_ipv6_mode_output:
            eth0_ipv6_mode = "Global DHCP"
        else:
            eth0_ipv6_mode = "Static DHCP"
    else:
        eth0_ipv6_mode = "Static"

    mgmt_info = dict(eth0_mac = eth0_mac,
            eth0_ipv4_addr = eth0_ipv4_addr,
            eth0_ipv4_netmask = eth0_ipv4_netmask,
            eth0_ipv4_prefix = eth0_ipv4_prefix,
            eth0_ipv4_broadcast = eth0_ipv4_broadcast,
            eth0_ipv4_mode = eth0_ipv4_mode,
            eth0_ipv6_addr = eth0_ipv6_addr,
            eth0_ipv6_netmask = eth0_ipv6_netmask,
            eth0_ipv6_mode = eth0_ipv6_mode)
    return mgmt_info

##############################################################################
#Funtion Name    : check_process_running
#Purpose         : To check whether process is running or not
#Created By      : INDIA_SONIC
#Parameters      : process name
#Output          : It return the process mode(Running or Not)
##############################################################################
def check_process_running(process_name):
    process_status = 0
    cmd = "ps -ef | grep " + process_name + " | wc -l"
    output = run_command(cmd)
    if (int(output) > 2):
        process_status = PROCESS_RUNNING
    else:
        process_status = PROCESS_NOT_RUNNING

    return process_status

##############################################################################
#Function Name : configure_lighttpd_mode
#Purpose       : To configure the lighthtpd.service
#Created By    : INDIA_SONIC
#Parameters    : status cmd,  stop_cmd
#output        : It configure the lighttpd.service
##############################################################################
def configure_lighttpd_mode(mode):
    process_status = SUCCESS_STATUS
    if mode == HTTPS_ENABLE:
        run_command(RESTART_CMD)
        process_status = check_process_running(LIGHTTPD_PROCESS)
    else:
        run_command(STOP_CMD)
    return process_status

#############################################################################
#Function Name : modify_lighttpd_conf_file
#Purpose       : To replace port number in lighttpd conf file
#Created By    : INDIA_SONIC
#Parameter     : port_number
#Output        : None
#############################################################################
def modify_lighttpd_conf_file(port_number):
    modify_status = SUCCESS_STATUS
    mgmt_info = get_management_information()
    eth0_ip_addr = mgmt_info[MGMT_IP_ADDRESS_FIELD]
    
    try:
        f = open(LIGHTTPD_CONF_FILE , "rt")
        lighttpd_data = f.read()
    
        lighttpd_data = re.sub(ETH0_IP_PATTERN + 
            IPADDR_SEPARATOR + PORT_NO_PATTERN,
            str(eth0_ip_addr) + IPADDR_SEPARATOR + str(port_number), 
            lighttpd_data)
        
        f.close()
    except OSError:
        print("Could not read file {}".format(LIGHTTPD_CONF_FILE))
        modify_status = WRITE_FAILURE_STATUS

    try:
        f = open(LIGHTTPD_CONF_FILE,"wt")
        f.write(lighttpd_data)
        f.close()
    except OSError:
        print("Could not write file {}".format(LIGHTTPD_CONF_FILE))
        modify_status = WRITE_FAILURE_STATUS

   
    return modify_status

#############################################################################
#Function Name: get_https_port
#Purpose: This function is used to get https port
#Created By: INDIA_SONIC
#Parameters: None
#Output: https port - int
#############################################################################
def get_https_port():
    https_port = get_db_field(CONFIG_DB, WEB_TABLE, WEB_TABLE_KEY, HTTPS_PORT)
    if (https_port == None):
        https_port = get_https_port_lighttpd_conf_file()
        if (https_port != None):
            set_db_field(CONFIG_DB, WEB_TABLE, WEB_TABLE_KEY,{HTTPS_PORT : https_port})

    return https_port

#############################################################################
#Function Name: get_https_port_lighttpd_conf_file
#Purpose: This function is used to get https port from lightttpd conf file
#Created By: INDIA_SONIC
#Parameters: None
#Output: https port - int
#############################################################################
def get_https_port_lighttpd_conf_file():
    port_num = None
    try:
        f = open(LIGHTTPD_CONF_FILE , "rt")
        lighttpd_data = f.read()
    
        lighttpd_data = re.search(":[0-9]+\w+",lighttpd_data)
        port_num = lighttpd_data.group()
        port_num = port_num.replace(":","")
        f.close()
    except OSError:
        print("Could not read file {}".format(LIGHTTPD_CONF_FILE))

    #print("Port number: {0}".format(port_num))
    return port_num

#############################################################################
#Function Name: get_web_session_idle_timeout
#Purpose: This function is used to get web session idle timeout
#Created By: INDIA_SONIC
#Parameters: None
#Output: https port - int
#############################################################################
def get_web_session_idle_timeout():
    web_session_idle_timeout = get_db_field(CONFIG_DB,WEB_TABLE,WEB_TABLE_KEY, WEB_SESSION_IDLE_TIMEOUT)
    #print("Web session idle timeout: {0}".format(web_session_idle_timeout))
    return web_session_idle_timeout

#############################################################################
#Function Name: get_https_mode
#Purpose: This function is used to get https mode
#Created By: INDIA_SONIC
#Parameters: None
#Output: https port - enable or disable
#############################################################################
def get_https_mode():
    https_mode = get_db_field(CONFIG_DB, WEB_TABLE, WEB_TABLE_KEY, HTTPS_MODE)
    if (https_mode == None):
        output = run_command(STATUS_CMD)
        if 'active (running)' in output:
            https_mode = HTTPS_ENABLE
        else:
            https_mode = HTTPS_DISABLE
        if (https_mode != None):
            set_db_field(CONFIG_DB, WEB_TABLE, WEB_TABLE_KEY, {HTTPS_MODE : https_mode})
    return https_mode

#############################################################################
#Function Name   : chech_lighttpd_status
#Purpose         : To check the port is already in use by other process
#Created By      : INDIA_SONIC
#Parameters      : https_port
#Output          : It returns the lighttpd status
#############################################################################
def check_lighttpd_status(https_port):
    port_status = SUCCESS_STATUS
    mgmt_info = get_management_information()
    ip_address = mgmt_info[MGMT_IP_ADDRESS_FIELD]
    cmd = "sudo netstat -tulpn | grep " + ip_address + ":" + str(https_port)
    port_exists = run_command(cmd)
    port_len = len(port_exists)
    if (port_len > 0):
        port_status = HTTPS_PORT_ALREADY_IN_USE
    else:
        port_status = HTTPS_PORT_FREE
    return port_status

############################
#Function Name: get_db_field
#Purpose      : To GET field from any Table, DB and return output
#Created By   : INDIA_SONIC
#Parameters   : dbnum - DB number
#               table - Table name
#               key   - Key of Table
#               field - Required Field name
#Output       : get_output - Value of the requested field
###########################
def get_db_field(dbnum, table, key, field):
    get_output = None
    
    if dbnum == APPL_DB:
        full_table_id = table + APPL_DB_TABLE_SEPARATOR + key
        get_output = appl_db.get(appl_db.APPL_DB, full_table_id, field)
    elif dbnum == CONFIG_DB:
        full_table_id = table + CONFIG_DB_TABLE_SEPARATOR + key
        get_output = config_db.get(config_db.CONFIG_DB, full_table_id, field)
    elif dbnum == STATE_DB:
        full_table_id = table + STATE_DB_TABLE_SEPARATOR + key
        get_output = state_db.get(state_db.STATE_DB, full_table_id, field)
    return get_output

############################
#Function Name: set_db_field
#Purpose      : To SET field from any Table, DB and return True or False
#Created By   : INDIA_SONIC
#Parameters   : dbnum      - DB number
#               table      - Table name
#               key        - Key of Table
#               field_dict - Required Fields with value in dictionary format
#Output       : True  - Success
#                     or 
#               False - Failure
###########################

def set_db_field(dbnum, table, key, field_dict):
    if dbnum == CONFIG_DB:
        config_db.mod_entry(table, key, field_dict)
        return True

#############################################################################
#Function Name   : run_command
#Purpose         : To run linux commands and return output
#Created By      : INDIA_SONIC
#Parameters      : command
#Output          : Returns the command output
#############################################################################
def run_command(command):
    cmd_output = subprocess.Popen(command, shell=True, text=True, 
            stdout=subprocess.PIPE)
    stdout = cmd_output.communicate()
    return stdout[0]
