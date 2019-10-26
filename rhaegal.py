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
__version__ = "1.0"
__maintainer__ = "AbdulRhman Alfaifi"
__license__ = "GPL"
__status__ = "Production"

parser = argparse.ArgumentParser(description='Rhaegal, Windows Event Logs Processig and Detection Tool')
parser.add_argument("-l","--log",help='The log you want to run the rules aginst')
parser.add_argument("-lp","--logsPath", help='A path that contains Windows Event Logs files (EVTX) to run the rules aginst')
parser.add_argument("-r","--rule", help='Rhaegal rule you want to use')
parser.add_argument("-rp","--rulesPath", help='Path that contains Rhaegal rules')
parser.add_argument("--headers", help='Print the headers',action="store_true",default=False)
parser.add_argument("-v","--version", help='Print version number',action="store_true",default=False)
parser.add_argument("--processes", help='Number of processes to use',type=int,default=(psutil.cpu_count() // 2))

def Unzip():
    #unzipFiles in current directory 
    path = os.getcwd()
    files = []
    # r=root, d=directories, f = files
    for r, d, f in os.walk(path):
        for file in f:
            if '.zip' in file:
                files.append(os.path.join(r, file))

    for f in files:
        zip_ref = zipfile.ZipFile(f, 'r')
        zip_ref.extractall(path)
        zip_ref.close()	


if "__main__" == __name__:
    multiprocessing.freeze_support()
    Unzip()
    p = psutil.Process(os.getpid())
    if "win" in sys.platform:
        p.nice(psutil.IDLE_PRIORITY_CLASS)
    else:
        p.nice(20)
    args = parser.parse_args()

    if args.version:
        print(f"Rhaegal v{__version__}")
        print(f"RhaegalLib v{RhaegalLib.__version__}")
        sys.exit()
    if not args.log and not args.logsPath:
        parser.error("Specify the logs to process. Use -l <logpath> or -lp <logsdir>")

    if not args.rule and not args.rulesPath:
        parser.error("Specify the rule/s to use. Use -r <rulepath> or -rp <rulesdir>")

    if args.headers:
        print('"Date And Time","EventRecordID/s","Rule Name","Rule Score","Discription","Refrence","Matched","Event (XML)"')
    #logging.basicConfig(format="%(asctime)s.%(msecs)03d [ %(levelname)-0s ] %(message)s",level=logging.INFO,datefmt="%Y-%m-%d %H:%M:%S")
    #logging.info(f"Process started with the PID {os.getpid()}")
    regal = Rhaegal(rulePath=args.rule,rulesDir=args.rulesPath)
    if len(regal.ruleSet) == 0:
        raise Exception(f"{__file__} was not able to load the rules !")
    #logging.info(f"The rules were parsed successfully. The total number of rules parsed are '{len(regal.ruleSet)}'")
    
    if args.logsPath:
        regal.MultiProcessingMatchLogDirectory(args.logsPath,args.processes)
    elif args.log:
        regal.MatchLogFile(args.log)
