import re
import yaml
from io import StringIO
import fnmatch
import Evtx.Evtx as evtx
from lxml import etree
from datetime import datetime
import threading
import os
import multiprocessing
import logging
import csv
import itertools


__author__ = "AbdulRhman Alfaifi"
__version__ = "1.0"
__maintainer__ = "AbdulRhman Alfaifi"
__license__ = "GPL"
__status__ = "Production"

# A class that represents an event record. it takes 'lxml' object as input.
class Event:
    def __init__(self,record):
        self.RawRecord = record
        self.SystemData = {}
        for systemChild in record[0]:
            onlyTag = systemChild.tag.split("}")[-1]
            if systemChild.text != None:
               self.SystemData.update({f"{onlyTag}":str(systemChild.text)})
            for atr in systemChild.attrib:
                self.SystemData.update({f"{onlyTag}.{atr}":str(systemChild.get(atr))})
        self.EventData = self.SystemData
        count = 0
        for EventDataChild in record[1]:
            if EventDataChild.get("Name") == None:
                self.EventData.update({f"Data{count}":str(EventDataChild.text)})
            else:
                self.EventData.update({f"Data.{EventDataChild.get('Name')}":str(EventDataChild.text)})
            count+=1
        for key, value in self.EventData.items():
            setattr(self, key.replace(".",""), value)
    def __str__(self):
        return str(self.EventData)

# A class that represents Rhaegal rule.
class Rule:
    def __init__(self,RuleString):
        self.RawRule = RuleString
        typeAndName = re.match("((public|private) [\w\d]+)",RuleString).group(0).split()
        self.type = typeAndName[0]
        self.name = typeAndName[1]
        ruleDateStr=""
        for line in re.findall("(\s+(.*:)(\s+.*[^\}])+)",RuleString)[0][0].split("\n"):
            if re.match("[\s]+#",line):
                pass
            else:
                ruleDateStr+=line+"\n"
        ruleData = yaml.safe_load(StringIO(ruleDateStr))
        self.author = ruleData.get("metadata").get("author")
        self.description = ruleData.get("metadata").get("description")
        self.reference = ruleData.get("metadata").get("reference")
        self.creationDate = ruleData.get("metadata").get("creationDate")
        self.include = ruleData.get("include")
        self.score = ruleData.get("metadata").get("score")
        self.channel = ruleData.get("Channel")
        self.exclude = ruleData.get("exclude")
        self.validateRule()
        
    def validateRule(self):
        if not isinstance(self.include,dict):
            raise ValueError(f"Error in the rule named '{self.name}'. The 'include' should be a dictionary.")
        if self.channel == None and not self.include.get("rule"):
            raise TypeError(f"Error in the rule named '{self.name}'. The filed 'Channel' is required.")
        if not self.score:
            self.score = 10
        if self.exclude == None:
            self.exclude = {}

    def __str__(self):
        return str(self.__dict__)

# Rhaegal main class that handles the processing and the trigger mechanism.
class Rhaegal:
    def __init__(self,rulePath=None,outputFormat="CSV",rulesDir=None):
        self.outputFormat = outputFormat
        self.PublicRulesContainsPrivateRules = []
        rex = re.compile('((public|private) .*(\n){0,1}{[\w\d\s\n\:\-\"\/\.\*\?\#\\\\\'\,\(\)\=\@\$]+})')
        rules=""
        self.channels=[]
        if not rulePath and rulesDir:
            for root, _, files in os.walk(rulesDir):
                for file in files:
                    if file.endswith(".gh"):
                        fullpath = os.path.abspath(os.path.join(root,file))
                        for line in open(fullpath).readlines():
                            if line.startswith("#"):
                                pass
                            else:
                                rules+=line
        elif rulePath and not rulesDir:
            for line in open(rulePath).readlines():
                if line.startswith("#"):
                    pass
                else:
                    rules+=line
        else:
            raise ValueError(f"You can pass only 'rulePath' or 'rulesDir' but not both")
        ruleSetStr = rex.findall(rules)
        self.ruleSet = []
        for rule in ruleSetStr:
            self.ruleSet.append(Rule(rule[0]))
        for rule in self.ruleSet:
            if rule.include.get("rule"):
                self.PublicRulesContainsPrivateRules.append(rule)
            if rule.channel not in self.channels and rule.channel != None:
                self.channels.append(rule.channel)
        self.channels = [s.lower() for s in self.channels]
    # Takes a string and a pattren. Return True if the pattren matches the string or False if it does not.
    def StringMatch(self,string,pattern):
        if string and pattern:
            string = string.lower()
            pattern = pattern.lower()
        return fnmatch.fnmatch(string,pattern)

    # The main matching function. tasks rule object and event object as input then returns the matched strings if the rule got triggered or False if not triggered.
    def match(self,rule,event):
        if rule.channel:
            if rule.channel.lower() != event.Channel.lower():
                return False
        triggired = True            
        matchStrs = []
        for key,value in rule.include.items():
            if key == "rule":
                for privateRuleName in value:
                    for privateRule in self.ruleSet:
                        if privateRule.name == privateRuleName:
                            triggired = triggired and self.match(privateRule,event)
            else:
                try:
                    if isinstance(rule.include.get(key),list):
                        oneMatched = False
                        for s in rule.include.get(key):
                            if event.EventData.get(key) == None:
                                oneMatched = False
                                break
                            if self.StringMatch(event.EventData.get(key),s):
                                oneMatched = oneMatched or True
                                matchStrs.append(event.EventData.get(key))
                            else:
                                oneMatched = oneMatched or False
                        triggired = triggired and oneMatched
                    else:
                        if self.StringMatch(event.EventData.get(key),value):
                            triggired = triggired and True
                            matchStrs.append(event.EventData.get(key))
                        else:
                            triggired = triggired and False
                except TypeError:
                    pass
        for key,value in rule.exclude.items():
            if key == "rule":
                for privateRuleName in value:
                    for privateRule in self.ruleSet:
                        if privateRule.name == privateRuleName:
                            triggired = triggired and self.match(privateRule,event)
            else:
                try:
                    if isinstance(rule.exclude.get(key),list):
                        oneMatched = False
                        for s in rule.exclude.get(key):
                            if event.EventData.get(key) == None:
                                oneMatched = True
                                break
                            if self.StringMatch(event.EventData.get(key),s):
                                oneMatched = oneMatched or True
                            else:
                                oneMatched = oneMatched or False
                        triggired = triggired and not oneMatched
                    else:
                        if self.StringMatch(event.EventData.get(key),value):
                            triggired = triggired and False
                        else:
                            triggired = triggired and True
                except TypeError:
                    pass
        if triggired:
            return matchStrs
        else:
            return False
    # Takes an event object as input and look that event on all of the available rules then display alert of the alert got triggered.
    def matchAll(self,event):
        for rule in self.ruleSet:
            if event.Channel.lower() not in self.channels:
                continue
            triggired = True
            if rule.type == "public":
                results = self.match(rule,event)
                if results:
                    triggired = triggired and True
                else:
                    triggired = triggired and False
                if triggired:
                    self.displayAlert(event,rule,results)
    
    # Formates the output in the choosen format.
    def displayAlert(self,event,rule,results="",privateRule=False,TriggeredEvents=[]):
        if self.outputFormat == "RAW":
            print(event)
        elif self.outputFormat == "CSV":
            row = StringIO()
            writer = csv.writer(row, quoting=csv.QUOTE_NONNUMERIC,lineterminator="\n")
            if privateRule:
                rules = []
                events = []
                recordIDs = []
                for event in TriggeredEvents:
                    recordIDs.append(event.EventRecordID)
                data = [datetime.now(), recordIDs, rule.name, rule.score, rule.description, rule.reference, results, "PRIVATE RULE"]
            else:
                data = [datetime.now(), event.EventRecordID, rule.name, rule.score, rule.description, rule.reference, results, etree.tostring(event.RawRecord,pretty_print=False).decode("utf-8").replace("\n","")]
           
            writer.writerow(data)
            print(row.getvalue(),end="")
    
    # Reads an EVTX file then process all of the event records.
    def MatchLogFile(self,filePath):
        with evtx.Evtx(filePath) as log:
            for record in log.records():
                try:
                    xmlObj = record.lxml()
                    event = Event(xmlObj)
                    self.matchAll(event)
                except (OSError, KeyError):
                    continue
    # Go through a directory looking for EVTX file then start processing them (single process).
    def MatchLogDirectory(self,directoryPath):
        self.ProcessPrivateRules(directoryPath)
        for root, _, files in os.walk(directoryPath):
            for file in files:
                if file.endswith(".evtx"):
                    fullpath = os.path.abspath(os.path.join(root,file))
                    self.MatchLogFile(fullpath)
    
    # Helper function for private rule matching that takes a list of events and return the events that happens within X milliseconds
    def ProcessTimeBetweenLogs(self,EventsList,within):
        MatchedEvent = []
        for EventSet in EventsList:
            datesList = []
            relativeTime = 0
            for event in EventSet:
                datesList.append(datetime.strptime(event.TimeCreatedSystemTime,"%Y-%m-%d %H:%M:%S.%f"))
            datesList.sort()
            relativeTime = (datesList[len(datesList)-1] - datesList[0]).total_seconds() * 1000
            relativeTime = int(relativeTime if relativeTime > 0 else relativeTime * -1)
            if relativeTime < within:
                MatchedEvent.append(EventSet)
        return MatchedEvent

    # This function gets triggred only if there is a public rule that calls private rules in the ruleset
    def ProcessPrivateRules(self,logspath):
        for pubrule in self.PublicRulesContainsPrivateRules:
            triggered = None
            privRules = []
            privRulesChannels = []
            TriggeredEvents = {}
            for privrulename in pubrule.include.get("rule"):
                for rule in self.ruleSet:
                    if rule.name == privrulename:
                        privRules.append(rule)
                        privRulesChannels.append(rule.channel.lower())
            for filePath in self.LogsToProcess:
                with evtx.Evtx(filePath) as log:
                    for record in log.records():
                        try:
                            xmlObj = record.lxml()
                            event = Event(xmlObj)
                            if event.Channel.lower() in privRulesChannels:
                                for prirule in privRules:
                                    if self.match(prirule,event):
                                        if triggered == None:
                                            triggered = True
                                        triggered = triggered and True
                                        if not TriggeredEvents.get(prirule):
                                            TriggeredEvents[prirule] = [event]
                                        else:
                                            TriggeredEvents[prirule].append(event)
                            else:
                                break
                        except (OSError, KeyError):
                            continue
            if len(TriggeredEvents) != len(privRules):
                return False

            TriggeredEventsList = []
            for key,val in TriggeredEvents.items():
                TriggeredEventsList.append(val)
            TriggeredEventsWithinTheSpecifiedTime  = self.ProcessTimeBetweenLogs(list(itertools.product(*TriggeredEventsList)),pubrule.include.get("if").get("within"))
            
            if TriggeredEventsWithinTheSpecifiedTime:
                for EventSet in TriggeredEventsWithinTheSpecifiedTime:
                    self.displayAlert(event,rule=pubrule,privateRule=True,TriggeredEvents=EventSet)
            else:
                return False

    # Go through a directory looking for EVTX file then start processing them (multiprocesses).
    def MultiProcessingMatchLogDirectory(self,directoryPath,numOfProcesses=1):
        self.LogsToProcess = []
        processes = []
        for root, _, files in os.walk(directoryPath):
            for file in files:
                if file.endswith(".evtx"):
                    fullpath = os.path.abspath(os.path.join(root,file))
                    self.LogsToProcess.append(fullpath)
        
        self.ProcessPrivateRules(directoryPath)
        for path in self.LogsToProcess:
            p = multiprocessing.Process(target=self.MatchLogFile,args=(path,))
            p.start()
            processes.append(p)
            while True:
                for thread in processes:
                    if not thread.is_alive():
                        processes.remove(thread)
                        if len(processes) < numOfProcesses:
                            break
                if len(processes) < numOfProcesses:
                    break
        while True:
            for thread in processes:
                if not thread.is_alive():
                    processes.remove(thread)

            if len(processes) == 0:
                break
