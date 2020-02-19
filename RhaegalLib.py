import re
import yaml
from io import StringIO
import fnmatch
from evtx import PyEvtxParser
import json
from datetime import datetime
import threading
import os
import multiprocessing
import logging
import csv
import itertools
from string import ascii_letters,digits
import ifaddr

__author__ = "AbdulRhman Alfaifi"
__version__ = "1.2.2"
__maintainer__ = "AbdulRhman Alfaifi"
__license__ = "GPL"
__status__ = "Development"

class Variables:
    def __init__(self):
        self.GetEnvVariables()
        self.GetIPAddresses()
    
    def GetEnvVariables(self):
        try:
            for env in os.environ:
                setattr(self,env,os.environ[env])
            return True
        except:
            return False

    def GetIPAddresses(self):
        try:
            ips = []
            for inet in ifaddr.get_adapters():
                for ip in inet.ips:
                    if isinstance(ip.ip,str):
                        ips.append(ip.ip)
            self.IPAddresses = ips
            return ips
        except:
            return False

class Modifier:
    def __init__(self,modstr):
        results = self.ParseModifier(modstr)
        self.field = results["field"]
        self.operation = results["operation"]
        self.value = results["value"]
    
    def ParseModifier(self,modstr):
        parts = modstr.split()
        results = {}
        if " $rex " in modstr:
            parts = modstr.split(" $rex ")
            results["field"] = parts[0]
            results["operation"] = "$rex"
            results["value"] = parts[1]
        else:
            if len(parts) == 3:
                results["field"] = parts[0]
                results["operation"] = parts[1]
                results["value"] = int(parts[2])
        return results

    def Check(self,event):
        eventValue = event.EventData.get(self.field)
        if eventValue:
            if self.operation == ">":
                return len(eventValue) > self.value
            elif self.operation == "<":
                return len(eventValue) < self.value
            elif self.operation == "<=":
                return len(eventValue) <= self.value
            elif self.operation == ">=":
                return len(eventValue) >= self.value
            elif self.operation == "==":
                return len(eventValue) == self.value
            elif self.operation == "$rex":
                return bool(re.findall(f"^{self.value}$",eventValue))

# A class that represents an event record. it takes 'lxml' object as input.
class Event:
    def __init__(self,record):
        self.RawRecord = record
        self.EventData = self.BuildEventData(record["Event"])
        # init System fields
        
        for key, value in self.EventData.items():
            setattr(self, key.replace(".",""), value)

    def BuildEventData(self,data,parentName=None):
        results = {}
        for key,val in data.items():
            if key == "xmlns":
                continue
            if isinstance(val,dict):
                if parentName:
                    if key == "#attributes":
                        results.update(self.BuildEventData(val,f"{parentName}"))
                    elif key == "Data" and parentName == "Data":
                        results.update(self.BuildEventData(val,f"{parentName}"))
                    else:
                        results.update(self.BuildEventData(val,f"{parentName}.{key}"))
                else:
                    if key == "EventData":
                        results.update(self.BuildEventData(val,"Data"))
                    elif key == "System":
                        results.update(self.BuildEventData(val))
                    else:
                        results.update(self.BuildEventData(val,key))
            else:
                if parentName:
                    if key == "#text":                          
                        if isinstance(val,list):
                            for i in range(len(val)):
                                results.update({f"{parentName}{i}":str(val[i])})
                        else:
                            results.update({f"{parentName}":str(val)})
                    else:
                        results.update({f"{parentName}.{key}":str(val)})
                elif val != None:
                    results.update({key:str(val)})

        return results

    def __str__(self):
        return str(self.EventData)

# A class that represents Rhaegal rule.
class Rule:
    def __init__(self,RuleString):
        self.RawRule = RuleString
        typeAndName = re.match("((public|private) (.*)+)",RuleString).group(0).split()
        self.type = typeAndName[0].lower()
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
        self.modifiers = ruleData.get("modifiers")
        self.returns = ruleData.get("returns")
        self.variables = ruleData.get("variables")
        self.validateRule()
        
    def validateRule(self):
        charset = ascii_letters+digits+"_().$"
        if not isinstance(self.include,dict):
            raise TypeError(f"Error in the rule named '{self.name}'. The 'include' should be a dictionary.")
        if self.channel == None and not self.include.get("rule"):
            raise TypeError(f"Error in the rule named '{self.name}'. The filed 'Channel' is required.")
        if not self.score:
            self.score = 10
        if self.exclude == None:
            self.exclude = {}
        if not self.modifiers:
            self.modifiers = []
        if not self.variables:
            self.variables = []
        if not self.returns:
            self.returns = []
        if not isinstance(self.returns,list):
            raise TypeError(f"Error in the rule named '{self.name}'. The 'returns' section should be a list not {type(self.returns)}")    
        if not isinstance(self.modifiers,list):
            raise TypeError(f"Error in the rule named '{self.name}'. The 'modifiers' section should be a list not {type(self.modifiers)}")
        if not isinstance(self.variables,list):
            raise TypeError(f"Error in the rule named '{self.name}'. The 'variables' section should be a list not {type(self.variables)}")
        if self.type != "public" and self.type != "private":
            raise TypeError(f"Error in the rule named '{self.name}'. The allowed rule type are 'public' or 'private' but you used '{self.type}'")
        for char in self.name:
            if char not in charset:
                raise ValueError(f"Error in the rule named '{self.name}'. The character '{char}' is not allowed in the rule name. The rule name should only contains letters, numbers and '_'")
        if not self.description:
            raise ValueError(f"Error in the rule named '{self.name}'. The 'metadata' secition should at least contain 'description' field")
        if self.type == "public" and self.include.get("rule"):
            if not self.include.get("rule") or not self.include.get("if"):
                raise ValueError(f"Error in the rule named '{self.name}'. private rule wrapper should contain 'rule' & 'if' fields inside 'include' section")
            if not self.include.get("if").get("within"):
                raise ValueError(f"Error in the rule named '{self.name}'.The 'if' field should contain 'within' field")
            if not isinstance(self.include.get("rule"),list):
                raise ValueError(f"Error in the rule named '{self.name}'.The 'rule' field should be a 'list' not '{type(self.include.get('rule'))}'")
    def __str__(self):
        return str(self.__dict__)

# Rhaegal main class that handles the processing and the trigger mechanism.
class Rhaegal:
    def __init__(self,rulePath=None,outputFormat="CSV",rulesDir=None,logger=None):
        self.logger = logger
        self.Variables = Variables()
        self.outputFormat = outputFormat
        self.PublicRulesContainsPrivateRules = []
        rex = re.compile('((public|private) .*(\n){0,1}\{(.*|\s)+?\})')
        # rex = re.compile('((public|private) .*(\n){0,1}{(\n.*)+})')
        rules=""
        self.channels=[]
        if not rulePath and rulesDir:
            for root, _, files in os.walk(rulesDir):
                for file in files:
                    if file.endswith(".gh"):
                        fullpath = os.path.abspath(os.path.join(root,file))
                        if logger:
                            logger.info(f"Reading Rhaegal rule file '{fullpath}'")
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

        if len(self.ruleSet) == 0:
            raise Exception(f"{__file__} was not able to load the rules !")
        # Validate the private rules called in the private rules wrapper are present.
        for rule in self.PublicRulesContainsPrivateRules:
            if not all([True if x in [i.name for i in self.ruleSet] else False for x in rule.include.get("rule")]):
                raise ValueError(f"Error in the rule named '{rule.name}'. The 'rule' field should be a list of private rules that are initialize")
        
        ruleNames = [x.name for x in self.ruleSet]
        if logger:
            logger.info(f"The rules were parsed successfully. The total number of rules parsed are '{len(self.ruleSet)}'")
            nl = '\n'
            logger.info(f"A list of all the rules that got parsed successfully : \n{nl.join([ ' - '+name for name in ruleNames])}")
        for rule in self.ruleSet:
            if ruleNames.count(rule.name) > 1:
                raise ValueError(f"Error in the rule named '{rule.name}'. Detected rule name duplication")

    # Takes a string and a pattren. Return True if the pattren matches the string or False if it does not.
    def StringMatch(self,string,pattern,event=None):
        if pattern.startswith("$"):
            if pattern == "$IP":
                return string in self.Variables.IPAddresses    
            else:
                try:
                    return self.StringMatch(string,getattr(self.Variables,pattern[1::]))    
                except AttributeError:
                    pass
                eventField = event.get(pattern[1::])
                if eventField:
                    return self.StringMatch(string,eventField)    
                else:
                    return False
        else:
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
                                if self.logger:
                                    self.logger.warning(f"Unable to find the field '{key}' from the rule '{rule.name}' in the following event : \n {event}")
                                oneMatched = False
                                break
                            if self.StringMatch(event.EventData.get(key),s,event.EventData):
                                oneMatched = oneMatched or True
                                matchStrs.append(event.EventData.get(key))
                            else:
                                oneMatched = oneMatched or False
                        triggired = triggired and oneMatched
                        if not triggired:
                            return False
                    else:
                        if event.EventData.get(key) == None:
                            if self.logger:
                                self.logger.warning(f"Unable to find the field '{key}' from the rule '{rule.name}' in the following event : \n {event}")
                        
                        if event.EventData.get(key) != None and self.StringMatch(event.EventData.get(key),value,event.EventData):
                            triggired = triggired and True
                            matchStrs.append(event.EventData.get(key))
                        else:
                            triggired = triggired and False
                        if not triggired:
                            return False
                except TypeError as e:
                    if self.logger:
                        self.logger.error(e,exc_info=True)
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
                                if self.logger:
                                    self.logger.warning(f"Unable to find the field '{key}' from the rule '{rule.name}'")
                                oneMatched = True
                                break
                            if self.StringMatch(event.EventData.get(key),s,event.EventData):
                                oneMatched = oneMatched or True
                            else:
                                oneMatched = oneMatched or False
                        triggired = triggired and not oneMatched
                    else:
                        if event.EventData.get(key) == None:
                            if self.logger:
                                self.logger.warning(f"Unable to find the field '{key}' from the rule '{rule.name}'")
                        if event.EventData.get(key) != None and self.StringMatch(event.EventData.get(key),value,event.EventData):
                            triggired = triggired and False
                        else:
                            triggired = triggired and True
                except TypeError as e:
                    if self.logger:
                        self.logger.error(e,exc_info=True)
                    pass
        
        modFlag = True

        for modifier in rule.modifiers:
            mod = Modifier(modifier)
            if mod.Check(event):
                modFlag = modFlag and True
                matchStrs.append(f"MOD : {modifier}")
            else:
                modFlag = modFlag and False
                break
        
        triggired = modFlag and triggired
        
        if triggired:
            if self.logger:
                self.logger.info(f"The rule named '{rule.name}' triggered on the event '{event}'")
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
                recordIDs = []
                triggeredEventsData = {}
                privRuleNames = rule.include.get("rule")
                privateRules = []
                for r in self.ruleSet:
                    if r.name in privRuleNames:
                        privateRules.append(r)

                for r in privateRules:
                    for e in TriggeredEvents:
                        if r.channel == e.Channel:
                            if r.returns:
                                fields = {}
                                for field in r.returns:
                                    fields.update({field:e.EventData.get(field)})
                                triggeredEventsData[r.name] = fields
                            else:
                                triggeredEventsData[r.name] = e.RawRecord
                for event in TriggeredEvents:
                    recordIDs.append(event.EventRecordID)
                data = [event.TimeCreatedSystemTime, recordIDs, rule.name, rule.score, rule.description, rule.reference, results, triggeredEventsData]
            else:
                if rule.returns:
                    returns = {}
                    for field in rule.returns:
                        returns[field] = event.EventData.get(field)
                    data = [event.TimeCreatedSystemTime, event.EventRecordID, rule.name, rule.score, rule.description, rule.reference, results, returns]
                else:
                    data = [event.TimeCreatedSystemTime, event.EventRecordID, rule.name, rule.score, rule.description, rule.reference, results, event.RawRecord]
           
            writer.writerow(data)
            print(row.getvalue(),end="")
    
    # Reads an EVTX file then process all of the event records.
    def MatchLogFile(self,filePath):
        parser = PyEvtxParser(filePath)
        for record in parser.records_json():
            try:
                data = json.loads(record["data"])
                event = Event(data)
                self.matchAll(event)
            except Exception as e:
                if self.logger:
                    self.logger.error(e,exc_info=True)
    # Go through a directory looking for EVTX file then start processing them (single process).
    def MatchLogDirectory(self,directoryPath):
        if self.logger:
            self.logger.info(f"Searching the directory '{directoryPath}' for Windows Event Logs (.evtx files) to process ...")
        self.ProcessPrivateRules(directoryPath)
        for root, _, files in os.walk(directoryPath):
            for file in files:
                if file.endswith(".evtx"):
                    fullpath = os.path.abspath(os.path.join(root,file))
                    if self.logger:
                        self.logger.info(f"Scanning the Windows Event Log '{fullpath}' ...")
                    self.MatchLogFile(fullpath)
                    if self.logger:
                        self.logger.info(f"Finished Scanning the Windows Event Log '{fullpath}' ...")
    
    # Helper function for private rule matching that takes a list of events and return the events that happens within X milliseconds
    def ProcessTimeBetweenLogs(self,EventsList,within):
        MatchedEvent = []
        for EventSet in EventsList:
            datesList = []
            relativeTime = 0
            for event in EventSet:
                datesList.append(datetime.strptime(event.TimeCreatedSystemTime,"%Y-%m-%dT%H:%M:%S.%fZ"))
            datesList.sort()
            relativeTime = (datesList[len(datesList)-1] - datesList[0]).total_seconds() * 1000
            relativeTime = int(relativeTime if relativeTime > 0 else relativeTime * -1)
            if relativeTime < within:
                MatchedEvent.append(EventSet)
        return MatchedEvent

    # This function gets triggred only if there is a public rule that calls private rules in the ruleset
    def ProcessPrivateRules(self,logspath):
        if self.logger:
            self.logger.info(f"Starting processing private rules on the logs in the directory '{logspath}' ...")
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
                parser = PyEvtxParser(filePath)
                for record in parser.records_json():
                    try:
                        data = json.loads(record["data"])
                        event = Event(data)
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
                    except (OSError, KeyError) as e:
                        if self.logger:
                            self.logger.error(e,exc_info=True)
                        continue
                    except Exception as e:
                        if self.logger:
                            self.logger.error(e,exc_info=True)
                            
            if len(TriggeredEvents) != len(privRules):
                return False

            TriggeredEventsList = []
            for key,val in TriggeredEvents.items():
                TriggeredEventsList.append(val)
            TriggeredEventsWithinTheSpecifiedTime  = self.ProcessTimeBetweenLogs(list(itertools.product(*TriggeredEventsList)),int(pubrule.include.get("if").get("within")))
            
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
