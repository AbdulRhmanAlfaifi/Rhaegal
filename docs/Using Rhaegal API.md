# Using Rhaegal API

In this section we will learn how to use Rhaegal on python scripts using `RhaegalLib.py`. RhaegalLib contains three class, And they are as follows:

* `Event` class : which is the class that responsible to parse windows event logs. Each object of this class represent a record/event.
* `Rule` class : each object of this class represents a Rhaegal rule.
* `Rhaegal` class : this is the main class that is responsible of rule matching with events.

# Functions and Properties

The following tables breakdown the functions and properties for each class:

## Event

### Functions

| Name        | Description                                                  |
| ----------- | ------------------------------------------------------------ |
| Event(lxml) | This is the constructor of the class that takes one argument of type `lxml` and return an Event object |

### Properties

This class generates properties dynamically, So there is not a fixed number of properties. Each event field will be available as property. For example the field `EventID` would be accessed using `<OBJECT_NAME>.EventID`. In case of fields that contain `.` on them such as `TimeCreated.SystemTime` you can reference them using `<OBJECT_NAME>.TimeCreatedSystemTime` (just remove `.` character). The following table shows the properties that are present every time you create new Event object:

| Name       | Description                                                  | Type        |
| ---------- | ------------------------------------------------------------ | ----------- |
| RawRecord  | This is the RAW lxml object that got passed to the constructor | lxml object |
| SystemData | This is a dictionary that contains the data inside `System` tag | Dictionary  |
| EventData  | This is a dictionary that contains the data inside `EventData` tag | Dictionary  |

## Rule

### Functions

| Name           | Description                                                  |
| -------------- | ------------------------------------------------------------ |
| Rule(rulestr)  | This is the constructor of this class. It takes a string as input which is the string version of the rule the parses it and creates rule object. |
| validateRule() | This rule is used to validate Rhaegal rule. This function will be called automatically when the rule parsing is finished. |

### Properties

| Name         | Description                                               | Type       |
| ------------ | --------------------------------------------------------- | ---------- |
| type         | the type of the rule. This can only be public or private. | String     |
| name         | rule name                                                 | String     |
| author       | the author field in the metadata section                  | String     |
| description  | the description field in the metadata section             | String     |
| reference    | the reference field in the metadata section               | String     |
| creationDate | the creationDate field in the metadata section            | String     |
| score        | the score field in the metadata section                   | Int        |
| channel      | the channel of the log that this rule applies to          | String     |
| include      | this field contains all the fields in the include section | Dictionary |
| exclude      | this field contains all the fields in the exclude section | Dictionary |

## Rhaegal

### Functions

| Name                                                         | Description                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| Rhaegal(rulePath=None,outputFormat="CSV",rulesDir=None)      | This is the constructor for this class. it accepts a single rule file, a path to multiple rules and output format RAW or CSV (Default). |
| StringMatch(string,pattern)                                  | Helper function that takes a string and a pattern then return True if the pattern matches the string or False if it is not. |
| match(rule,event)                                            | This is the main matching function. It takes a rule object and an event object and return the matched strings if there is a match or False if there is no match. |
| matchAll(event)                                              | This function takes an event object as an argument and matches all the ruleset to the given event object |
| displayAlert(event,rule,results="",privateRule=False,TriggeredEvents=[]): | This function handles the output.                            |
| MatchLogFile(filePath)                                       | Takes a path to EVTX file as argument and search through it using the ruleset. |
| MatchLogDirectory(directoryPath)                             | Takes a path to a directory that contains EVTX files to search through using the ruleset. |
| ProcessTimeBetweenLogs(EventsList,within)                    | This function is a helper function for the private rules.    |
| ProcessPrivateRules(logspath)                                | This function will only get called if there is a private rule. |
| MultiProcessingMatchLogDirectory(directoryPath,numOfProcesses=1) | This function is the same as the MatchLogDirectory(). the only deference is that this function utilizes multiprocessing |

### Properties

| Name                            | Description                                                  | Type   |
| ------------------------------- | ------------------------------------------------------------ | ------ |
| outputFormat                    | The output format. This can only be `RAW` to print the raw event that got triggered or `CSV` to print the output as CSV (Default) | String |
| ruleSet                         | A list of Rule objects that got parsed from the rule file/s  | List   |
| channels                        | A list of all the rules channels. This is used to improve the performance if the scanning where Rhaegal will scan only the logs in this list | List   |
| PublicRulesContainsPrivateRules | A list of rule objects that contains private rules (public rules that wraps private rules) | List   |

# Example

Let's use Rhaegal API in a script ! in this example we will write a script that read a single Windows Event Log and a single Rhaegal rule and output the results. Here how the script will look like:

```python
from RhaegalLib import Rhaegal

if "__main__" == __name__:
    rhaegalObj = Rhaegal("Malcious_PowerShell.gh")
    rhaegalObj.MatchLogFile("Windows PowerShell.evtx")
```

This scripts look for malicious PowerShell execution on the event log called `Windows PowerShell.evtx`.