#! /usr/bin/python -tt

import subprocess,dynfwserv,firewalliot

subprocess.Popen(["python","mqtt_gwclient.py"])
dynfwserv.rule_manager()
