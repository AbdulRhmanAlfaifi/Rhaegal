#!/usr/bin/env python3

import argparse
from RhaegalLib import Rhaegal
import RhaegalLib
from datetime import datetime
import os
import psutil
import sys
import logging
import zipfile
import multiprocessing

__author__ = "AbdulRhman Alfaifi"
__version__ = "1.0.2"
__maintainer__ = "AbdulRhman Alfaifi"
__license__ = "GPL"
__status__ = "Production"

parser = argparse.ArgumentParser(description='Rhaegal, Windows Event Logs Processing and Detection Tool')
parser.add_argument("-l","--log",help='The log you want to run the rules against')
parser.add_argument("-lp","--logsPath", help='A path that contains Windows Event Logs files (EVTX) to run the rules against')
parser.add_argument("-r","--rule", help='Rhaegal rule you want to use')
parser.add_argument("-rp","--rulesPath", help='Path that contains Rhaegal rules')
parser.add_argument("--headers", help='Print the headers',action="store_true",default=False)
parser.add_argument("-v","--version", help='Print version number',action="store_true",default=False)
parser.add_argument("--processes", help='Number of processes to use',type=int,default=(psutil.cpu_count() // 2))

def InitLogger(logName="Rhaegal.log",debug=False):
    logger = logging.getLogger("Rhaegal")

    if debug:
        handler = logging.StreamHandler()
    else:
        handler = logging.FileHandler(logName,"w+")
    
    formatter = logging.Formatter('%(asctime)s.%(msecs)03d [ %(levelname)-0s ] %(message)s')
    handler.setFormatter(formatter)

    logger.addHandler(handler)
    logger.setLevel("DEBUG")
    return logger

def Unzip():
    path = os.getcwd()
    zip_ref = zipfile.ZipFile("rules.zip", 'r')
    zip_ref.extractall(path)
    zip_ref.close()	


if "__main__" == __name__:
    multiprocessing.freeze_support()
    args = parser.parse_args()
    if not os.path.exists(args.rulesPath):
        Unzip()
    logger = InitLogger(debug=False)
    p = psutil.Process(os.getpid())
    if "win" in sys.platform:
        p.nice(psutil.IDLE_PRIORITY_CLASS)
    else:
        p.nice(20)

    if args.version:
        print(f"Rhaegal v{__version__}")
        print(f"RhaegalLib v{RhaegalLib.__version__}")
        sys.exit()
    if not args.log and not args.logsPath:
        parser.error("Specify the logs to process. Use -l <logpath> or -lp <logsdir>")

    if not args.rule and not args.rulesPath:
        parser.error("Specify the rule/s to use. Use -r <rulepath> or -rp <rulesdir>")

    if args.headers:
        print('"Event Date And Time","EventRecordID/s","Rule Name","Rule Score","Discription","Refrence","Matched","Rule Return"')
    logger.info(f"Process started with the PID {os.getpid()}")
    if args.logsPath:
        # No Logging for multiprocessing
        regal = Rhaegal(rulePath=args.rule,rulesDir=args.rulesPath,logger=None)
        if len(regal.ruleSet) == 0:
            raise Exception(f"{__file__} was not able to load the rules !")
    elif args.log:
        regal = Rhaegal(rulePath=args.rule,rulesDir=args.rulesPath,logger=logger)
        if len(regal.ruleSet) == 0:
            raise Exception(f"{__file__} was not able to load the rules !")
    
    if args.logsPath:
        regal.MultiProcessingMatchLogDirectory(args.logsPath,args.processes)
    elif args.log:
        regal.MatchLogFile(args.log)
