#!/usr/bin/python

import os
import sys
import logging
import logging.handlers
import threading
import tempfile
import logging_module

import json
from time import sleep
from dateutil import parser as dateParser
from datetime import datetime
import base64
import ast
#sys.path.insert(0,'/Users/yk032359/PycharmProjects/HP-CEM/Cred.py')
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class instanses():

    def __init__(self,cred):
        self.password = cred['password']
        self.host = cred['host']
        self.local_user = cred['local_user']
        self.username = cred['username']
        self.logging_level = cred['logging_level']
        self.numAlertsProcessedAtStart = int(cred['numAlertsProcessedAtStart'])
        self.authLoginDomain = cred['authLoginDomain']
        self.log = logging_module.logs()

    def get_ovgd_token(self):
        print(self.host)
        self.req_url = "https://{}/rest/login-sessions".format(self.host)
        self.headers = {'Content-Type': 'application/json', 'X-Api-Version': '2'}
        self.body = {'authLoginDomain': self.authLoginDomain, 'userName': self.username,
                'password': self.ovgd_config["password"]}

        # print(json.dumps(body, indent=4))
        # print(req_url)
        self.resp = requests.post(self.req_url, headers=self.headers, data=json.dumps(self.body), verify=False)

        if (self.resp.status_code != 200):
            logging.error(
                "Failed to retrive TOKEN..! Status code = {}. Error Message = {}.".format(self.resp.status_code, self.resp.text))
            exit(1)

        self.resp_dict = self.resp.json()
        self.auth_token = self.resp_dict["token"]
        return self.resp_dict["token"]

    def init_ovgd_extr(self):

        self.create_globals()

        # Creating the directory only if it does not exists.
        if not os.path.isdir(self.gOvgdDir):
            self.retStatus = os.makedirs(self.gOvgdDir)

            if self.retStatus != None:
                logging.error("ERROR: Failed to create OVGD directory - {}".format(self.gOvgdDir))
                sys.exit(1)

    def create_globals(self):

        tempDir = tempfile.gettempdir()
        print(tempDir)

        self.gLastAlertTimestampFile = tempDir + os.sep + "ovgd_extr" + os.sep + self.host + os.sep + "timestatmp"
        self.gMissedAlertsInfoFile = tempDir + os.sep + "ovgd_extr" + os.sep + self.host + os.sep + "missed_alerts"
        self.gServersURItoHostnamesMap = tempDir + os.sep + "ovgd_extr" + os.sep + self.host + os.sep + "server_map"
        self.gOvgdDir = tempDir + os.sep + "ovgd_extr" + os.sep + self.host
        print(self.gServersURItoHostnamesMap)
        print(self.gOvgdDir)

    def get_ovgd_config(self):

        self.ovgd_config = {}

        # Ensure that all the config variables are exported to env.
        # If a particular variable is not present, it will return a NULL string and that will be assigned to that config variable
        self.ovgd_config["ovgd_host"] = self.host
        self.ovgd_config["username"] = self.username
        self.tempPwd = self.password
        self.tempPwd = base64.b64decode(self.tempPwd)
        self.tempPwd = self.tempPwd.decode('utf-8')
        self.ovgd_config["password"] = self.tempPwd
        self.ovgd_config["authLoginDomain"] = self.authLoginDomain
        self.ovgd_config["numAlertsProcessedAtStart"] = self.numAlertsProcessedAtStart

        retStatus = self.validate_ovgd_config()
        if retStatus != 0:
            logging.error("Please check OVGD config variables. Exiting.")
            sys.exit(1)

        return self.ovgd_config

    def validate_ovgd_config(self):

        self.retStatus = 0  # Assuming all details are available

        if self.ovgd_config["ovgd_host"] is None or "":
            logging.error('ovgd_host environment variable not set')
            self.retStatus = 1

        if self.ovgd_config["username"] is None or "":
            logging.error('ovgd_username environment variable not set')
            self.retStatus = 1

        if self.ovgd_config["password"] is None or "":
            logging.error('ovgd_password environment variable not set')
            self.retStatus = 1

        if self.ovgd_config["authLoginDomain"] is None or "":
            logging.error('ovgd_authLoginDomain environment variable not set')
            self.retStatus = 1

        if self.ovgd_config["numAlertsProcessedAtStart"] is None or "":
            logging.error('ovgd_numAlertsProcessedAtStart environment variable not set')
            self.retStatus = 1

        return self.retStatus

    def initialize_logging(self, logging_Level='INFO'):
        # Initialize the log file path, log format and log level
        self.logfiledir = os.getcwd() + os.sep + "logs" + os.sep + self.host
        # print("Debug logfiledir - {}".format(logfiledir))
        if not os.path.isdir(self.logfiledir):
            os.makedirs(self.logfiledir)

        self.logfile = self.logfiledir + os.sep + "OVGD_NETCOOL_{}.log".format(self.host)
        if os.path.exists(self.logfile):
            self.fStats = os.stat(self.logfile)
            if self.fStats.st_size >= 1024000:
                # Backing up logfile if size is more than 1MB and creating an empty file for use.
                self.timestamp = '{:%Y-%m-%d__%H-%M-%S}'.format(datetime.now())
                os.rename(self.logfile, self.logfiledir + os.sep + 'OVGD_NETCOOL_{}_'.format(self.host) + self.timestamp + ".log")
                open(self.logfile, 'a').close()
        else:
            # Create empty logfile
            open(self.logfile, 'a').close()

        # Init the logging module with default log level to INFO.
        logging.basicConfig(filename=self.logfile,
                            format='%(asctime)s - %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s',
                            datefmt='%d-%m-%Y:%H:%M:%S', level=self.logging_level)

    def process(self):

        self.init_ovgd_extr()

        try:
            if self.logging_level is None or "":
                logging.error('extractor_logging_level environment variable not set. Configure it and restart.')
                sys.exit(1)

        except Exception as e:
            # We will not be able to log this message since logging is not yet initialized, hence printing
            logging.error(e)
            logging.error("Error in reading config from env variables. Export all of them and try again. Exiting")
            sys.exit(1)

        return self.logging_level

    def module_init(self):

        self.retStat = self.log.init(logging,self.host)
        if self.retStat != 0:
            print("ERROR: Module init failed. Please check relevant export variables.")
            sys.exit(1)

    def get_last_sent_alert_timestamp(self):

        self.lastAlertTime = -1  # Assuming it is not existing. Assign appropriately if existing.

        ## Open the file in read mode if exists and return the timestamp
        ##
        if os.path.exists(self.gLastAlertTimestampFile):
            try:
                f = open(self.gLastAlertTimestampFile, 'r')
                self.alertTS = f.readline()
                self.lastAlertTime = dateParser.parse(self.alertTS)
            except Exception as e:
                logging.error("Failed to read timestamp of last sent alert - {}".format(e))
                logging.error("Assuming running for the first time.")

    def create_server_hardware_hostname_map(self):
        retVal = 0
        nextPageUri = 1  # Set this to TRUE initially.

        ## Initializing the counters
        self.totalServers = []  # Place holder for the alerts
        self.startIdx1 = 0  # Starting from index = 0
        self.numServersToRead = 500  # Trying to fetch 500 events per pass (Max number of objects that can be fetched at a time)
        self.flag1 = False  # Flag to determine continue to find servers or to break from while() loop
        self.serverMap1 = {}
        # continueFlag = True
        self.headers = {'Content-Type': 'application/json', 'X-Api-Version': '2', 'auth': self.auth_token}

        while (1):
            ## Sample URL: https://10.10.10.10/rest/server-hardware?start=0&count=500
            ##
            self.req_url = "https://{}/rest/server-hardware?start={}&count={}".format(self.host, self.startIdx1, self.numServersToRead)

            print("startIdx1-{} - {}".format(self, self.startIdx1))
            # if (startIdx >= 19500):
            # continueFlag=False
            # break
            self.resp = requests.get(self.req_url, headers=self.headers, verify=False)
            if (self.resp.status_code != 200):
                logging.error(
                    "Failed to read server details.! Status code = {}. Error Message = {}.".format(self.resp.status_code,
                                                                                                   self.resp.text))
                exit(1)
            self.jsonResp1 = self.resp.json()
            # logging.info("after query.. startIdx={}. numServersToRead={}".format(startIdx, numServersToRead))
            self.presentServers = self.jsonResp1["members"]

            if (self.jsonResp1["count"] > 0):  # If there are some more servers, proceed.
                for server in self.presentServers:
                    # print("Server - {}".format(server))
                    # key = id = server["originalUri"].split("/")[-1] # "originalUri" = "/rest/server-hardware/30373737-3237-4D32-3230-313530314752";
                    key = server["originalUri"].split("/")[
                        -1]  # "originalUri" = "/rest/server-hardware/30373737-3237-4D32-3230-313530314752"; Need only last part.
                    value = server["serverName"]
                    self.serverMap1[key] = value

                if (self.jsonResp1["count"] < self.numServersToRead):
                    # We have mapped all the server-hardware. Breaking from the loop.
                    # logging.info("We have mapped all the server-hardware.")
                    self.flag1 = True
                    # continueFlag = False
                    break
                else:
                    self.startIdx1 += self.jsonResp1["count"]
                    sleep(0.1)  # A small pause before continuing <TBD>
            else:
                logging.info("We have mapped all the server-hardware.")

        with open(self.gServersURItoHostnamesMap, 'w') as serverMapFile:
            json.dump(self.serverMap1, serverMapFile)
        # print("serverMap")
        # sleep(5)

        return retVal

    def get_server_hardware_hostname_map(self):

        if (self.refreshFlag) and os.path.exists(self.gServersURItoHostnamesMap):
            os.remove(self.gServersURItoHostnamesMap)

        # Make sure the map file exists. Else, create a new one.
        if not os.path.exists(self.gServersURItoHostnamesMap):
            self.create_server_hardware_hostname_map()

        with open(self.gServersURItoHostnamesMap) as json_file:
            self.serverMap = json.load(json_file)

        return self.serverMap

    def alert_name_change(self,alert,serverMap):
        # ----------------------
        self.alert = alert
        self.serverMap2 = serverMap
        if self.alert["physicalResourceType"] == "server-hardware":
            serverID = self.alert["resourceUri"].split("/")[-1]

            if serverID in self.serverMap2.keys():
                if (self.serverMap2[serverID] != None and len(self.serverMap2[serverID]) > 0):
                    print("ServerID - {} : Hostname - {}".format(serverID, self.serverMap2[serverID]))
                    self.alert["associatedResource"]["resourceName"] = self.serverMap2[serverID]
                else:
                    print("Hostname not assigned for serverID - {}".format(serverID))
            else:
                print("Server key - {}; not present. Recreate server map.".format(serverID))
                # print("Alert - {}".format(alert))

                # Recreate the server map with refreshFalg set.
                self.refreshFlag = 1
                self.serverMap2 = self.get_server_hardware_hostname_map()
                if serverID in self.serverMap2.keys():
                    if (self.serverMap2[serverID] != None and len(self.serverMap2[serverID]) > 0):
                        print(" (2nd time) ServerID - {} : Hostname - {}".format(serverID, self.serverMap2[serverID]))
                        self.alert["associatedResource"]["resourceName"] = self.serverMap2[serverID]
                    else:
                        print("Hostname not assigned for serverID - {}".format(serverID))

                else:
                    print("Key not present now also - {}".format(serverID))
                    print("Alert from server with UUID - {}. Server not present in OVGD".format(serverID))
                    logging.warning("Alert from server with UUID - {}. Server not present in OVGD".format(serverID))
                    self.alert["associatedResource"]["resourceName"] = "Non-existent-hardware"  # Tad_TBD

        elif self.alert["physicalResourceType"] == "appliance":
            self.alert["associatedResource"]["resourceName"] = self.alert["applianceLocation"]
            print("Alert from {}. Name changed to - {}.".format(self.alert["physicalResourceType"],
                                                                self.alert["associatedResource"]["resourceName"]))
        else:
            print(
                "Alert is not from server-hardware or appliance but from {}. Retaining the name as it is - {}.".format(
                    self.alert["physicalResourceType"], self.alert["associatedResource"]["resourceName"]))
        # -------------------------

        return self.alert, self.serverMap2

    def backup_alert_for_processing_next_time(self,alertID):
        retVal = 0
        ## File "gLastAlertTimestampFile" is supplied as global variable.
        ## The same file is used as reference for reading and updating
        ## the last processed event's timestamp
        ##
        try:
            if os.path.exists(self.gMissedAlertsInfoFile):
                self.f = open(self.gMissedAlertsInfoFile, 'a')
            else:
                self.f = open(self.gMissedAlertsInfoFile, 'w')

            print("Updating missed alert entry")
            logging.info("Updating missed alert entry")
            self.f.write(alertID + "\n")
            self.f.close
        except Exception as e:
            logging.error("Unable to update falied alert's ID{}. Reason  - {}.".format(alertID, e))
            retVal = 1

        return retVal

    def update_alert_timestamp(self,timeStamp):

        retVal = 0
        ## File "gLastAlertTimestampFile" is supplied as global variable.
        ## The same file is used as reference for reading and updating
        ## the last processed event's timestamp
        ##
        try:
            self.f = open(self.gLastAlertTimestampFile, 'w')
            self.f.write(timeStamp)
            self.f.close
        except Exception as e:
            logging.error(
                "Failed to update timestamp of last sent alert - {}. Might continue processing alerts from beginning.".format(
                    e))
            retVal = 1

        return retVal

    def alerts_and_events_process_firsttime(self):

        ## Initializing the counters
        self.allAlerts = []  # Place holder for all the alerts
        self.startIdx = 0  # Starting from index = 0
        self.countOfEvents = 500  # Fetching 500 events per pass (Max number of events that can be fetched at a time)
        self.flag = False  # Flag indicating whether we have processed all teh relevant alerts

        self.headers = {'Content-Type': 'application/json', 'X-Api-Version': '2', 'auth': self.auth_token}

        while (True):
            ## Sample URL: https://10.10.10.10/rest/resource-alerts?start=0&count=500&sort=created:desc
            ##
            self.req_url = "https://{}/rest/resource-alerts?start={}&count={}&sort=created:desc".format(self.host, self.startIdx,
                                                                                                   self.countOfEvents)

            self.resp = requests.get(self.req_url, headers=self.headers, verify=False)
            if (self.resp.status_code != 200):
                logging.error(
                    "Failed to alerts.! Status code = {}. Error Message = {}.".format(self.resp.status_code, self.resp.text))
                exit(1)
            self.jsonResp = self.resp.json()

            self.alertsNow = self.jsonResp["members"]
            self.lenCurrentAlerts = len(self.alertsNow)

            for self.alert in self.alertsNow:
                self.allAlerts.append(self.alert)

                if ((self.jsonResp["count"] == 0) or (len(self.allAlerts) >= self.numAlertsProcessedAtStart)):
                    # We have processed all the relevant events. Breaking from the loop.
                    self.flag = True
                    break  # From for loop

            if ((self.jsonResp["count"] == 0) or (len(self.allAlerts) >= self.numAlertsProcessedAtStart)):
                # We have processed all the relevant events. Need not read anymore alerts.
                break  # From while loop

            self.startIdx += self.jsonResp["count"]
            sleep(0.5)  # A small pause before continuing

        self.allAlerts.reverse()  # This is done to log events in order of occurance. If we need to log the latest event first, we can comment this.
        if len(self.allAlerts) > 0:
            print("Completed reading of all the relevant alerts")
        else:
            print("No alerts to process")
        self.refreshFlag = 0
        self.serverMap = self.get_server_hardware_hostname_map()

        # print("keys - {}".format(serverMap.keys()))

        self.procAlerts = 0
        for self.alert in self.allAlerts:

            self.alert, self.serverMap = self.alert_name_change(self.alert, self.serverMap)

            self.retStatus = self.log.execute(self.alert)
            if (self.retStatus == 0):  # Keeping track of success and failed alerts
               self.procAlerts += 1
            else:
                logging.warning("Failed  to process alert with ID - {}".format(self.alert["id"]))
                self.backup_alert_for_processing_next_time(self.alert["id"])

        logging.info("First time alerts to be processed - {}; Alerts successfully processed - {}".format(len(self.allAlerts),
                                                                                                         self.procAlerts))

        # Updating the timestamp of last processed alert
        self.update_alert_timestamp(self.alert["created"])

        return 0

    def process_alerts_if_any_from_lasttime(self):

        headers = {'Content-Type': 'application/json', 'X-Api-Version': '2', 'auth': self.auth_token}

        # List of alerts which are not processed in this routine
        self.newMissedAlerts = []

        ## There are any events which were missed processing in previous run,
        ## they will be logged in the file and processed in subsequent runs.
        ##
        ## Checking if there are any alerts missed processing last time
        #

        if os.path.exists(self.gMissedAlertsInfoFile):
            logging.info("Processing alerts which were not processed in previous run")
            print("Processing alerts which were not processed in previous run")
            with open(self.gMissedAlertsInfoFile) as f:
                self.missedAlertIDs = f.readlines()

            # You may also want to remove whitespace characters like `\n` at the end of each line
            self.missedAlertIDs = [x.strip() for x in self.missedAlertIDs]
            logging.info("Failed to process {} events from previous run. Processing now.".format(len(self.missedAlertIDs)))
            logging.info("Details - {} .".format(self.missedAlertIDs))
            f.close()

            self.refreshFlag = 0
            self.serverMap = self.get_server_hardware_hostname_map()

            # Process all the alerts that we have discovered now
            for id in self.missedAlertIDs:
                self.URI = "https://{}/rest/resource-alerts/{}".format(self.host, id)
                # req_url = "https://{}/rest/resource-alerts?start={}&count={}&sort=created:desc".format(ovgdHost, startIdx, countOfEvents)

                self.resp = requests.get(self.URI, headers=headers, verify=False)
                if (self.resp.status_code != 200):
                    logging.error(
                        "Failed to retrive alert with ID - {}. Status code = {}. Error Message = {}.".format(id,
                                                                                                             self.resp.status_code,
                                                                                                             self.resp.text))
                # exit(1)
                else:
                    # Process the alert
                    self.alert = self.resp.json()

                    self.alert, self.serverMap = self.alert_name_change(self.alert, self.serverMap)

                    # Notify and check if the alert went through.
                    retStatus = self.log.execute(self.alert)
                    if (retStatus == 0):
                        retStatus = 0  # When print is removed, we can change the logic to have a debug or info message or something else
                    else:
                        # Failed to send alert. Append it to list to cache again in "/tmp/ovgd_extr/missed_alerts" file.
                        #
                        self.newMissedAlerts.append(self.alert["id"])
                        print("URI - {}".format(self.alert["id"]))

            # Storing back the alert ids which we failed to send.
            if (len(self.newMissedAlerts) > 0):
                fd = open(self.gMissedAlertsInfoFile, 'w')
                logging.warning(
                    "Still failed to send some alerts from cached file ({} of them). Cache-ing them back again.".format(
                        len(self.newMissedAlerts)))
                for alertID in self.newMissedAlerts:
                    fd.write(alertID + "\n")
                fd.close
            else:
                os.remove(self.gMissedAlertsInfoFile)
        else:
            # print("No events/alerts missed from processing")
            logging.info("No events/alerts missed from processing")

    def get_current_ovgd_alerts_and_events(self):
        headers = {'Content-Type': 'application/json', 'X-Api-Version': '2', 'auth': self.auth_token}

        nextPageUri = 1  # Set this to TRUE initially.

        ## Initializing the counters
        self.relevantAlerts = []  # Place holder for the alerts
        self.startIdx2 = 0  # Starting from index = 0
        self.countOfEvents = 500  # Trying to fetch 500 events per pass (Max number of events that can be fetched at a time)
        self.flag = False

        while (1):
            ## Sample URL: https://10.10.10.10/rest/resource-alerts?start=0&count=500&sort=created:desc
            ##
            req_url = "https://{}/rest/resource-alerts?start={}&count={}&sort=created:desc".format(self.host, self.startIdx2,
                                                                                                   self.countOfEvents)

            self.resp = requests.get(req_url, headers=headers, verify=False)
            if (self.resp.status_code != 200):
                logging.error(
                    "Failed to alerts.! Status code = {}. Error Message = {}.".format(self.resp.status_code, self.resp.text))
                exit(1)
            self.jsonResp = self.resp.json()

            self.presentAlerts = self.jsonResp["members"]

            if (self.jsonResp["count"] > 0):  # If there are some events, proceed.
                for alert in self.presentAlerts:
                    self.thisAlertTime = dateParser.parse(alert["created"])

                    if (self.thisAlertTime <= self.lastAlertTime):
                        # We have received all the events. Breaking from the loop.
                        self.flag = True
                        break
                    else:
                        self.relevantAlerts.append(alert)

                if (self.flag == True):
                    break  # from while loop
                else:
                    self.startIdx2 += self.jsonResp["count"]
                    sleep(0.5)  # A small pause before continuing <TDB>
            else:
                logging.info("Events are already read and processed.")

        self.lenArray = len(self.relevantAlerts)

        if self.lenArray > 0:
            self.relevantAlerts.reverse()  # To process alerts in order of occurance. Else this is not required.

        return self.relevantAlerts

    def process_alerts_and_service_events(self):

        if self.lastAlertTime == -1:
            # Running for the first time as the timestamp is not logged in /tmp/ovgd_extr
            #
            logging.info(
                "Running for the first time. Configured to process upto {} of most recent alerts (or less) of the total alerts present".format(
                    self.numAlertsProcessedAtStart))
            self.alerts_and_events_process_firsttime()

        else:
            # Alerts are processed till sometime back. Processing the remaining alerts
            #
            self.process_alerts_if_any_from_lasttime()

            self.currentAlerts = self.get_current_ovgd_alerts_and_events()

            self.procAlerts = 0

            self.refreshFlag = 0
            self.serverMap = self.get_server_hardware_hostname_map()

            if (len(self.currentAlerts) > 0):
                for self.alert in self.currentAlerts:
                    self.alert, self.serverMap = self.alert_name_change(self.alert, self.serverMap)

                    retStatus = self.log.execute(self.alert)

                    # Keeping track of success and failed alerts
                    if (retStatus == 0):
                        self.procAlerts += 1
                    else:
                        self.backup_alert_for_processing_next_time(self.alert["id"])

                logging.info(
                    "New alerts to be processed - {}; Alerts successfully processed - {}".format(len(self.currentAlerts),
                                                                                                 self.procAlerts))

                # Updating the timestamp of last alert processed
                self.update_alert_timestamp(self.alert["created"])
            else:
                logging.info("No new alerts for processing")

def main():
    with open('/nms/hpOneView-integration/ovgd_extractor_module/Creds_json.json') as jsonfile:
        data = json.load(jsonfile)

    for key, values in data.items():
        x = threading.Thread(target=threads, args=(key, values))
        x.start()


def threads(key,values):

    print("Thread {}".format(key))
    creds_inst = values
    keys = instanses(creds_inst)
    keys.get_ovgd_config()
    keys.get_ovgd_token()
    keys.process()
    keys.initialize_logging()
    keys.module_init()
    keys.get_last_sent_alert_timestamp()
    keys.process_alerts_and_service_events()
    keys.log.cleanup()

    logging.info("OVGD extract utility exiting for RHO.\n")


#################################################################
# Start module
#
##################################################################

if __name__ == "__main__":

	sys.exit(main())