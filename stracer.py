#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Github/Twitter: @zom3y3
# Email: zom3y3@gmail.com
# Based on https://github.com/johnlcf/Stana

import io
import sys
import getopt
import re
import json
import traceback
import logging
import shutil
import ssdeep
import os
import hashlib
def file_md5(file):
    if os.path.exists(file):
        f = open(file, 'rb')
        m = hashlib.md5(f.read())
        md5 = m.hexdigest()
        f.close()
        return md5
        
DROP_FLODER = '/tmp/'


from optparse import OptionParser
from datetime import timedelta, time, datetime
from collections import defaultdict, deque

class StraceParser:
    """
    StraceParser

    This is the strace parser. It parses each system call lines into a dict, and
    then call the registered stat modules to process.

    The defination of dict: please refer to _parseLine
    """
    def __init__(self):
        self._completeSyscallCallbackHook = defaultdict(list)
        self._rawSyscallCallbackHook = defaultdict(list)

        # regex compiled for _parseLine
        self._rePointer = re.compile(r"\[([0-9a-z?]*)\]")
        self._reCompleteSyscall = re.compile(r"([^(]+)\((.*)\)[ ]+=[ ]+([a-fx\d\-?]+)(.*)")
        self._reUnfinishedSyscall = re.compile(r"([^(]+)\((.*) <unfinished ...>")
        self._reResumedSyscall = re.compile(r"\<\.\.\. ([^ ]+) resumed\> (.*)\)[ ]+=[ ]+([a-fx\d\-?]+)(.*)")
        return

    def registerSyscallHook(self, fullSyscallName, func):
        self._registerHookInTable(fullSyscallName, self._completeSyscallCallbackHook, func)

    def registerRawSyscallHook(self, fullSyscallName, func):
        self._registerHookInTable(fullSyscallName, self._rawSyscallCallbackHook, func)

    def _registerHookInTable(self, name, table, func):
        table[name].append(func)

    def startParse(self, reader, straceOptions):
        self._parse(reader, straceOptions)

    def autoDetectFormat(self, reader):
        """ autoDetectFormat - Detect the strace output line format, return a
            dict with following:

            straceOptions["havePid"] = True/False
            straceOptions["haveTime"] = ""/"t"/"tt"/"ttt"
            straceOptions["haveTimeSpent"] True/False

            It use peek() on the reader so it will not abvance the position of
            the stream.
        """
        buf = reader.buffer.peek(4096);

        failCount = 0
        for line in buf.split('\n'):
            if failCount == 3:
                return None
            if "unfinish" in line or "resume" in line:
                continue
            straceOptions = self._detectLineFormat(line)
            if straceOptions:
                return straceOptions
            else:
                failCount += 1
        return None

    def _detectTimeFormat(self, timeStr):
        if ":" not in timeStr and "." in timeStr:
            return "ttt"
        if ":" in timeStr:
            if "." in timeStr:
                return "tt"
            else:
                return "t"
        logging.debug("_detectTimeFormat: Failed: unable to detect time format.")
        return None

    def _detectLineFormat(self, line):
        havePid = False
        haveTime = ""
        haveTimeSpent = False
        havePointer = False
        remainLine = line

        m = re.match(r"([0-9:. ]*)([a-z]+\(.*[ ]+=[ ]+[-0-9]+)(.*)", line)
        m2 = re.match(r"([0-9:. ]*)(\[[0-9a-z]*\] )([a-z]+\(.*[ ]+=[ ]+[-0-9]+)(.*)", line)
        if m:
            pre = m.group(1)
            mid = m.group(2)
            post = m.group(3)
        elif m2:
            pre = m2.group(1)
            pointer = m2.group(2)
            mid = m2.group(3)
            post = m2.group(4)
            havePointer = True
        else:
            print "_detectLineFormat: Failed: unable to match the line, give up detection."
            return

        if pre != '':
            preList = pre.strip().split()
            if len(preList) > 2:
                print "_detectLineFormat: Failed: more the 2 parts in pre."
                return
            if len(preList) == 2:
                haveTime = self._detectTimeFormat(preList[1])
                havePid = True
            else:
                if ':' in pre or '.' in pre:
                    havePid = False
                    haveTime = self._detectTimeFormat(preList[0])
                else:
                    havePid = True
                    haveTime = ""

        if post != '':
            if re.search(r"(<[0-9.]+>)", line):
                haveTimeSpent = True
            else:
                haveTimeSpent = False

        straceOptions = {}
        straceOptions["havePid"] = havePid
        straceOptions["haveTime"] = haveTime
        straceOptions["havePointer"] = havePointer
        straceOptions["haveTimeSpent"] = haveTimeSpent

        return straceOptions

    def _parse(self, reader, straceOptions):
        syscallListByPid = {}

        unfinishedSyscallStack = {}
        if not reader:
            logging.error("Cannot read file")
            return

        for line in reader:

            if "restart_syscall" in line:      # TODO: ignore this first
                continue

            if "+++ exited with" in line:
                continue

            unfinishedSyscall = False
            reconstructSyscall = False
            if "<unfinished ...>" in line:     # store the unfinished line for reconstruct
                unfinishedSyscall = True
                if straceOptions["havePid"]:
                    pid = (line.partition(" "))[0]
                    unfinishedSyscallStack[pid] = line
                else:
                    unfinishedSyscallStack[0] = line
            elif "resumed>" in line:         # get back the unfinished line and reconstruct
                if straceOptions["havePid"]:
                    pid = (line.partition(" "))[0]
                    if pid not in unfinishedSyscallStack:
                        continue                        # no <unfinished> line before, ignore
                    existLine = unfinishedSyscallStack[pid]
                else:
                    if 0 not in unfinishedSyscallStack:
                        continue                        # no <unfinished> line before, ignore
                    existLine = unfinishedSyscallStack[0]
                lineIndex = line.find("resumed>") + len("resumed>")
                reconstructLine = existLine.replace("<unfinished ...>", line[lineIndex:])
                reconstructSyscall = True
                #print "debug reconstructed line:", line


            # Parse the line
            result = self._parseLine(line, straceOptions)
            # hook here for every (raw) syscalls
            if result:
                if result["syscall"] in self._rawSyscallCallbackHook:
                    for func in self._rawSyscallCallbackHook[result["syscall"]]:
                        func(result)
                if "ALL" in self._rawSyscallCallbackHook:
                    for func in self._rawSyscallCallbackHook["ALL"]:
                        func(result)

            # determine if there is a completeSyscallResult
            if unfinishedSyscall:
                completeSyscallResult = None
            elif reconstructSyscall:
                completeSyscallResult = self._parseLine(reconstructLine, straceOptions)
            else:   # normal completed syscall
                completeSyscallResult = result

            # hook here for every completed syscalls:
            if completeSyscallResult:
                if completeSyscallResult["syscall"] in self._completeSyscallCallbackHook:
                    for func in self._completeSyscallCallbackHook[completeSyscallResult["syscall"]]:
                        func(completeSyscallResult)
                if "ALL" in self._completeSyscallCallbackHook:
                    for func in self._completeSyscallCallbackHook["ALL"]:
                        func(completeSyscallResult)

        return

    def _timeStrToTime(self, timeStr, timeFormat):
        """ _timeStrToTime

            timeFormat: "t"   = "%H:%M:%S"
                        "tt"  = "%H:%M:%S.%f"
                        "ttt" = "timestamp.%f"
        """
        if timeFormat == "ttt":
            return datetime.utcfromtimestamp(float(timeStr))
        else:
            timeList = timeStr.split(":")
            # in order to use datetime object for calculation, pad the time with 1970-1-1
            # TODO: should handle the day boundary case in _parse function
            if timeFormat == "tt":
                secondList = timeList[2].split(".")
                return datetime(1970, 1, 1, int(timeList[0]), int(timeList[1]), int(secondList[0]), int(secondList[1]))
            else:
                return datetime(1970, 1, 1, int(timeList[0]), int(timeList[1]), int(timeList[2]))

    def _timeStrToDelta(self, timeStr):
        return timedelta(seconds=float(timeStr))

    def _parseLine(self, line, straceOptions):
        #
        #   _parseLine
        #
        #   It parse a complete line and return a dict with the following:
        #   pid :       pid (if havePid enabled)
        #   startTime : start time of the call (if haveTime enabled)
        #   syscall :   system call function
        #   args :      a list of arguments ([] if no options)
        #   return :    return value (+/- int string or hex number string or '?' (e.g. exit syscall)), not exist if it is an unfinished syscall
        #   timeSpent : time spent in syscall (if haveTimeSpent enable. But even so, it may not exist in some case (e.g. exit syscall) and None will be stored in this field)
        #   type :      Type of syscall ("completed", "unfinished", "resumed")
        #
        #   Return null if hit some error
        #
        #   (Not implemented) signalEvent : signal event (no syscall, args, return)
        #
        result = {}
        remainLine = line

        try:
            if straceOptions["havePid"]:
                result["pid"], remainLine = remainLine.split(None, 1)
                result["pid"] = result["pid"].encode('utf-8')

            if straceOptions["haveTime"] != "":
                timeStr, remainLine = remainLine.split(None, 1)
                result["startTime"] = self._timeStrToTime(timeStr, straceOptions["haveTime"])

            if straceOptions["havePointer"]:
                pointerStr, remainLine = remainLine.split(None, 1)
                m = self._rePointer.match(pointerStr)
                result["pointer"] = m.group(1)

            if "--- SIG" in remainLine:        # a signal line
                #result["signalEvent"] = remainLine
                #return result
                ### Ignore signal line now
                return

            # If it is unfinished/resumed syscall, still parse it but let the
            # caller (_parse) determine what to do
            if "<unfinished ...>" in remainLine:
                result["type"] = "unfinished"
                m = self._reUnfinishedSyscall.match(remainLine)
                result["syscall"] = m.group(1).encode('utf-8')
                result["args"] = self._parseArgs(m.group(2).strip().encode('utf-8')) # probably only partal arguments
            elif "resumed>" in remainLine:
                result["type"] = "resumed"
                m = self._reResumedSyscall.match(remainLine)
                result["syscall"] = m.group(1).encode('utf-8')
                result["args"] = self._parseArgs(m.group(2).strip().encode('utf-8')) # probably only partal arguments
                result["return"] = m.group(3).encode('utf-8')
                remainLine = m.group(4)
            else:
                # normal system call
                result["type"] = "completed"
                m = self._reCompleteSyscall.match(remainLine)
                result["syscall"] = m.group(1).encode('utf-8')
                result["args"] = self._parseArgs(m.group(2).strip().encode('utf-8'))
                result["return"] = m.group(3).encode('utf-8')
                remainLine = m.group(4)
                remains = remainLine.split('>')
                if len(remains) == 3:
                    result["return"] += remains[0] + '>'
                    remainLine = remains[1] + '>'

            if result["type"] != "unfinished" and result["return"] == '-1':
                m = re.search(r" \(([^\n]*)\)", remainLine)
                if m:
                    result["error"] = m.group(1).encode('utf-8')
                else:
                    result["error"] = ''
            else:
                result["error"] = ''

            if result["type"] != "unfinished" and straceOptions["haveTimeSpent"]:
                m = re.search(r"<([\d.]*)>", remainLine)
                if m:
                    result["timeSpent"] = self._timeStrToDelta(m.group(1))
                else:
                    result["timeSpent"] = ''

        except AttributeError:
            # logging.warning("_parseLine: Error parsing this line: " + line)
            # print sys.exc_info()
            #exctype, value, t = sys.exc_info()
            #print traceback.print_exc()
            #print sys.exc_info()
            return

        return result

    def _countPrecedingBackslashes(self, s, pos):
        initialPos = pos
        while pos > 0 and s[pos-1] == '\\':
            pos-=1
        return (initialPos-pos)

    def _parseStringArg(self, argString):
        """
        Parses to the end of a string parameter.

        argString must begin with a quote character. _parseStringArg() parses
        to the corresponding terminating quote character.
        Returns the parsed string (including quotes) and the unparsed
        remainder of argString.
        """
        searchEndSymbolStartAt = 1
        while True:
            endSymbolIndex = argString.find('"', searchEndSymbolStartAt)

            if endSymbolIndex == -1:
                logging.warning("_parseStringArg: strange, can't find end symbol in this arg:" + argString)
                endSymbolIndex = 0
                break

            numPrecedingBackslashes = self._countPrecedingBackslashes(argString, endSymbolIndex)
            if numPrecedingBackslashes % 2 == 1:
                # if preceded by an odd number of backslashes, the quote character is escaped
                searchEndSymbolStartAt = endSymbolIndex + 1
            else:
                break
        return ( argString[0:endSymbolIndex+1], argString[endSymbolIndex+1:] )

    def _parseBlockArg(self, argString, parseBlock=False):
        """
        Parses a list of arguments, recursing into blocks.

        argString must be a string of comma-separated arguments.
        If parseBlock is True, argString must start with [ or {,
        and _parseBlockArg() will only parse to the end of the matching
        bracket.
        Returns the parsed arguments and the unparsed remainder of argString.
        """
        endSymbols = {'{':'}', '[':']', '"':'"'}
        resultArgs = []

        currIndex = 0
        if parseBlock:
            endChar = endSymbols[argString[0]]
            currIndex+=1

        lengthArgString = len(argString)
        remainderString = argString
        while currIndex < lengthArgString:
            if argString[currIndex] == ' ': # ignore space
                currIndex += 1
                continue

            content = None
            if argString[currIndex] == '"':
                # inner string; parse recursively till end of string
                (content, remainderString) = self._parseStringArg(argString[currIndex:])
            elif argString[currIndex] in ['{', '[']:
                # inner block; parse recursively till end of this block
                (content, remainderString) = self._parseBlockArg(argString[currIndex:], True)
            else:
                # normal parameter; find next comma
                remainderString = argString[currIndex:]

            nextCommaPos = remainderString.find(', ')
            if parseBlock:
                nextTerminatorPos = remainderString.find(endChar)
                if nextTerminatorPos == -1:
                    logging.warning("_parseBlockArg: strange, can't find end symbol '%s' in this arg: '%s'" % (endChar, argString))
                    return (argString, "")
            else:
                nextTerminatorPos = lengthArgString

            finished = False
            if nextCommaPos == -1 or nextTerminatorPos < nextCommaPos:
                # we've parsed last parameter in block
                contentString = remainderString[:nextTerminatorPos]
                remainderString = remainderString[nextTerminatorPos+1:]
                finished = True
            elif nextTerminatorPos > nextCommaPos:
                # there is another parameter in this block:
                contentString = remainderString[:nextCommaPos]
                remainderString = remainderString[nextCommaPos+1:]
            else:
                assert False, "internal error (this case shouldn't be hit)"

            if content is None:
                # block parser didn't return any value, or current parameter is a non-block value;
                # so use entire raw string as "content"
                content = contentString

            resultArgs.append(content)

            if finished:
                break

            assert(remainderString)
            currIndex = len(argString) - len(remainderString)
            currIndex+=1

        return (resultArgs, remainderString)

    def _parseArgs(self, argString):
        """
        Parses an argument string and returns a (possibly nested) list of arguments.
        """
        endSymbol = {'{':'}', '[':']', '"':'"'}
        # short-cut: if there is no {, [, " in the whole argString, use split
        if all([sym not in argString for sym in endSymbol.keys()]):
            # remove the comma and space at the end of argString, then split
            # it by ', '
            resultArgs = argString.rstrip(' ,').split(', ')
            # remove all empty split
            return filter(len, resultArgs)

        # otherwise, use a complex method to break the argument list, in order
        # to ensure the comma inside {}, [], "" would not break things.
        (content, remainderString) = self._parseBlockArg(argString, False)
        assert not(remainderString), "remainder left after parsing: '%s'" % remainderString
        return content

class StatBase(object):
    """ The base class of stat plugins """

    def optionHelp(self):
        """ Should return a dict for all options for this plugin.
            The dict keys are the option names and dict Values are the
            description of the options.
            E.g. {"output":"Write the output to this file instead of stdout"}

            It will be used for a help text in the command line. And it will
            be used to check if user input a correct option: If an
            option is specified for this plugin by user but it is not specified
            here, the command line will show error.
        """
        return {}

    def setOption(self, pluginOptionDict):
        """ The pluginOptionDict contains the key value pair of options for
            specified by user in the command line for this plugin.
            E.g. {"output":"/tmp/output.txt"}

            If no option specified, pluginOptionDict will be an empty dict ({}).
            Return False if there is some problem in the options so that this
            plugin would not be used.
        """
        return True

    def isOperational(self, straceOptions):
        """ Should return true if this plugin works in the current strace
            options.
            The straceOptions should be a dict contains at least:
            straceOptions["havePid"] = 1/0
            straceOptions["haveTime"] = "", "t", "tt", or "ttt"
            straceOptions["haveTimeSpent"] = 1/0

            If isOperational return false, the register function will not be
            called.
        """
        return True

    def getSyscallHooks(self):
        """ Hook the processing function for each completed syscall.

            The uncomplete/resumed syscall will be merged before passing to the
            hook function. And if it cannot merged then it will be ignored.
            (If you want to get uncomplete/resumed saperately, use
             getRawSyscallHooks instead.)

            Should return a dict with key = syscall name and value = hook function
            E.g. return_dict["open"] = self.funcHandleOpenSyscall
                 return_dict["close"] = self.funcHandleCloseSyscall
                 return_dict["ALL"] = self.funcHandleALLSyscall
        """
        return None

    def getRawSyscallHooks(self):
        """ Hook the processing function for each syscall (which may be
            unfinished/resumed)

            Should return a dict similar to that of getSyscallHooks
        """
        return None

    def jsonOutput(self):
        """ Should print the output to console. Would be called after parsing is
            finished.
        """
        pass

class StatProcessTree(StatBase):
    """ Print the process fork tree in the strace file """

    def __init__(self):
        self._allPid = set()
        self._childDict = defaultdict(list)
        self._childExecName = {}
        self.processtree = {}
        self.processtree['result'] = ''

    def isOperational(self, straceOptions):
        if not straceOptions["havePid"]:
            return False
        return True

    def getSyscallHooks(self):
        return {"ALL": self.statProcessTree}

    def statProcessTree(self, result):
        if "pid" not in result:
            # logging.warning("statProcessTree: no pid info in line")
            return
        pid = result["pid"]
        self._allPid.add(pid)
        if result["syscall"] in ['clone', 'fork', 'vfork']:
            if result["return"] != '?':
                childPid = result["return"]
                self._childDict[pid].append(childPid)
                # Copy the execuation name of parent process to child process.
                # It will be overwritten by next execve call of child
                if pid in self._childExecName:
                    if result["syscall"] == 'clone':
                        self._childExecName[childPid] = "(clone)"

                    elif result["syscall"] in ['fork', 'vfork']:
                        self._childExecName[childPid] = "(fork)"

        if result["syscall"] == "execve":
            exe_cmd = ''
            for s in result["args"][1]:
                if ' ' in s:
                    s = s
                else:
                    s = s.replace('"', '')
                exe_cmd = exe_cmd + s + ' '
            exe_cmd = exe_cmd[:-1]
            self._childExecName[pid] = exe_cmd

    def getProcessChildern(self, pid):
        return self._childDict[pid]

    def getProcessExecName(self, pid):
        return self._childExecName[pid]

    def jsonOutput(self):
        # headPid = remove child pid in _allPid, so it contains only head pid
        headPid = self._allPid
        for childPidList in self._childDict.values():
            for childPid in childPidList:
                headPid.remove(childPid)

        self.processtree['result'] = self._printTree(sorted(headPid))
        return self.processtree

    def _printTree(self, pids, indent='', level=0):
        r = []
        for n, pid in enumerate(pids):
            if level == 0:
                s, cs = '', ''
            elif n < len(pids) - 1:
                s, cs = '  ├─', '  │ '
            else:
                s, cs = '  └─', '    '
            if pid in self._childExecName:
                name = self._childExecName[pid]
                children = sorted(self._childDict[pid])
                if children:
                    ccs = '  │ '
                else:
                    ccs = '    '
                name = name.replace('\n', '\n' + indent + cs + ccs + '    ')
                r.append(indent + s + '{} {}\n'.format(pid, name))
                r.append(self._printTree(children, indent+cs, level+1))
        return ''.join(r)

class StatFileIO(StatBase):
    """ Stat and print file IO of strace"""

    def __init__(self):
        self._fileStatList = {}
        self._fidStatList = {}
        self._pluginOptionDict = {}
        self._straceOptions = {}
        self.fileopts = {}
        self.fileopts['failed'] = []
        self.fileopts['sucess'] = {}
        self.fileopts['sucess']['total_file'] = []
        self.fileopts['sucess']['read'] = []
        self.fileopts['sucess']['write'] = []
        self.fileopts['sucess']['open'] = []
        self.fileopts['sucess']['modify'] = []

    def optionHelp(self):
        return {"output":"Write the output to this file instead of stdout"}

    def setOption(self, pluginOptionDict):
        self._pluginOptionDict = pluginOptionDict
        return True

    def getSyscallHooks(self):
        return_dict = {}
        for syscall in ["read", "write", "open", "openat", "close"]:
            return_dict[syscall] = self.statFileIO
        return return_dict

    def isOperational(self, straceOptions):
        self._straceOptions = straceOptions
        return True

    def statFileIO(self, result):
        if result["syscall"] in ["read", "write", "open", "openat", "close"]:
            if result["return"] == "-1":
                open_error = {}
                if result["syscall"] == "open":
                    open_error['pid'] = int(result["pid"]) if self._straceOptions["havePid"] else 0
                    open_error['error'] = result["error"]
                    open_error['file'] = result["args"][0].replace('"', '')
                    self.fileopts['failed'].append(open_error)
                elif result["syscall"] == "openat":
                    open_error['pid'] = int(result["pid"]) if self._straceOptions["havePid"] else 0
                    open_error['error'] = result["error"]
                    open_error['file'] = result["args"][1].replace('"', '')
                    self.fileopts['failed'].append(open_error)
                return

            if result["syscall"] in ["open", "openat"]:
                fid = result["return"]
            else:
                fid = result["args"][0]

            if self._straceOptions["havePid"]:
                pid = int(result["pid"])
            else:
                pid = 0
            if pid not in self._fidStatList:
                self._fidStatList[pid] = {}
            if pid not in self._fileStatList:
                self._fileStatList[pid] = {}

            # file close
            if result["syscall"] == "close":
                if fid in self._fidStatList[pid]:
                    #print self._fidStatList[fid]
                    filename = self._fidStatList[pid][fid][0]
                    if filename not in self._fileStatList[pid]:
                        self._fileStatList[pid][filename] = [1, self._fidStatList[pid][fid][1], self._fidStatList[pid][fid][2], self._fidStatList[pid][fid][3], self._fidStatList[pid][fid][4], self._fidStatList[pid][fid][5], self._fidStatList[pid][fid][6], self._fidStatList[pid][fid][7], self._fidStatList[pid][fid][8]]
                    else:
                        self._fileStatList[pid][filename][0] += 1
                        for i in [1, 2, 3, 4, 5, 6, 7, 8]:
                            self._fileStatList[pid][filename][i] += self._fidStatList[pid][fid][i]
                    #file close
                    self._fileStatList[pid][filename][8] = 1
                    #when file close del fid avoid the same fid
                    del self._fidStatList[pid][fid]
                # else if fid not in self._fidStatList[pid] and this is a close syscall, just ignore and return
                return

            # if read/write/open
            if fid not in self._fidStatList[pid]:
                if result["syscall"] == "open":
                    # self._fidStatList[pid][fid] = [filename, read count, read acc bytes, write count, write acc bytes, read data, write data, fid, isclose]
                    self._fidStatList[pid][fid] = [result["args"][0], 0, 0, 0, 0, '', '', fid, 0]
                elif result["syscall"] == "openat":
                    self._fidStatList[pid][fid] = [result["args"][1], 0, 0, 0, 0, '', '', fid, 0]
                else:
                    self._fidStatList[pid][fid] = ["unknown:"+fid, 0, 0, 0, 0, '', '', fid, 0]
            # ISSUE #8: if fid in self._fidStatList[pid] but the syscall is open/openat, that mean
            # we missed a close syscall, we should update _fileStatList before we move on

            # stat read/write
            if result["syscall"] == "read":
                self._fidStatList[pid][fid][1] += 1
                self._fidStatList[pid][fid][2] += int(result["return"])
                self._fidStatList[pid][fid][5] += result["args"][1][1:-1].decode("string_escape")
            if result["syscall"] == "write":
                self._fidStatList[pid][fid][3] += 1
                self._fidStatList[pid][fid][4] += int(result["return"])
                self._fidStatList[pid][fid][6] += result["args"][1][1:-1].decode("string_escape")
            return

    def jsonOutput(self):
        for pid in self._fidStatList:
            for fid in self._fidStatList[pid]:
                #print self._fidStatList[pid][fid]
                filename = self._fidStatList[pid][fid][0]
                if filename not in self._fileStatList[pid]:
                    # pass
                    # unclosed file
                    self._fileStatList[pid][filename] = [1] + self._fidStatList[pid][fid][1:9]
                else:
                    self._fileStatList[pid][filename][0] += 1
                    for i in [1, 2, 3, 4, 5, 6, 7, 8]:
                        self._fileStatList[pid][filename][i] += self._fidStatList[pid][fid][i]
        for pid in self._fileStatList:
            for filename in self._fileStatList[pid]:
                if filename.startswith('unknown:'):
                    continue

                self.fileopts['sucess']['total_file'].append(filename[1:-1])
                #read
                if self._fileStatList[pid][filename][2] > 0:
                    tmp_read = {}
                    if self._straceOptions["havePid"]:
                        tmp_read['pid'] = pid
                    tmp_read['file_name'] = filename
                    tmp_read['is_close'] = self._fileStatList[pid][filename][8]
                    tmp_read['fd'] = self._fileStatList[pid][filename][7]
                    tmp_read['read_count'] = self._fileStatList[pid][filename][1]
                    tmp_read['read_bytes'] = self._fileStatList[pid][filename][2]
                    tmp_read['data'] = self._fileStatList[pid][filename][5]
                    self.fileopts['sucess']['read'].append(tmp_read)
                #write
                if self._fileStatList[pid][filename][4] > 0:
                    tmp_write = {}
                    if self._straceOptions["havePid"]:
                        tmp_write['pid'] = pid
                    tmp_write['file_name'] = filename
                    tmp_write['is_close'] = self._fileStatList[pid][filename][8]
                    tmp_write['fd'] = self._fileStatList[pid][filename][7]
                    tmp_write['write_count'] = self._fileStatList[pid][filename][3]
                    tmp_write['write_bytes'] = self._fileStatList[pid][filename][4]
                    tmp_write['data'] = self._fileStatList[pid][filename][6]
                    self.fileopts['sucess']['write'].append(tmp_write)
                #read & write
                if self._fileStatList[pid][filename][2] > 0 and self._fileStatList[pid][filename][4] > 0:
                    tmp_modify = {}
                    if self._straceOptions["havePid"]:
                        tmp_modify['pid'] = pid
                    tmp_modify['file_name'] = filename
                    self.fileopts['sucess']['modify'].append(tmp_modify)
                #open only
                if self._fileStatList[pid][filename][2] == 0 and self._fileStatList[pid][filename][4] == 0:
                    tmp_open = {}
                    if self._straceOptions["havePid"]:
                        tmp_open['pid'] = pid
                    tmp_open['file_name'] = filename
                    self.fileopts['sucess']['open'].append(tmp_open)
        return self.fileopts

class StatSpecialSyscall(StatBase):
    """ Stat and print DynamicAnalysis of strace"""
    def __init__(self):
        self._pluginOptionDict = {}
        self._straceOptions = {}
        self.mkdir_syscalls = ["mkdir", "mkdirat"]
        self.open_syscalls = ["open"]
        self.write_syscalls = ["write"]
        self.unlink_syscalls = ["unlink", "unlinkat"]
        self.execve_syscalls = ["execve"]
        self.socket_syscalls = ["socket"]
        self.connect_syscalls = ["connect"]
        self.kill_syscalls = ["kill", "killpg"]
        self.syscalls = []
        self.syscalls.extend(self.mkdir_syscalls)
        self.syscalls.extend(self.open_syscalls)
        self.syscalls.extend(self.write_syscalls)
        self.syscalls.extend(self.unlink_syscalls)
        self.syscalls.extend(self.execve_syscalls)
        self.syscalls.extend(self.socket_syscalls)
        self.syscalls.extend(self.connect_syscalls)
        self.syscalls.extend(self.kill_syscalls)
        self.specials = {}
        self.specials['mkdir'] = []
        self.specials['create'] = []
        self.specials['unlink'] = []
        self.specials['execve'] = []
        self.specials['network'] = []
        self.specials['kill'] = []
        self.specials['stdout'] = []
        self.specials['stderr'] = []
        self.network = {}
        self.network['socket'] = []
        self.network['connect'] = []

    def optionHelp(self):
        return {"output":"Write the output to this file instead of stdout"}

    def setOption(self, pluginOptionDict):
        self._pluginOptionDict = pluginOptionDict
        return True

    def getSyscallHooks(self):
        return_dict = {}
        for syscall in self.syscalls:
            return_dict[syscall] = self.statDynamicAnalysis
        return return_dict

    def isOperational(self, straceOptions):
        self._straceOptions = straceOptions
        return True

    def parseSpecials(self, result, type, index=0):
        tmp_specials = {}
        tmp_specials['pid'] = int(result["pid"]) if self._straceOptions["havePid"] else 0
        tmp_specials['file_name'] = result["args"][index]
        if tmp_specials['file_name'][0] == '"' and tmp_specials['file_name'][-1] == '"':
            tmp_specials['file_name'] = tmp_specials['file_name'][1:-1]
        if result["return"] == "-1":
            tmp_specials['error'] = 1
            tmp_specials['error_info'] = result['error']
        else:
            tmp_specials['error'] = 0
        self.specials[type].append(tmp_specials)

    def statDynamicAnalysis(self, result):
        if result["syscall"] in self.syscalls:
            if self._straceOptions["havePid"]:
                pid = int(result["pid"])
            else:
                pid = 0

            if result["syscall"] in self.mkdir_syscalls:
                if result["syscall"] == 'mkdirat':
                    self.parseSpecials(result, 'mkdir', 1)
                elif result["syscall"] == 'mkdir':
                    self.parseSpecials(result, 'mkdir')

            if result["syscall"] in self.open_syscalls and 'O_CREAT' in result["args"][1]:
                self.parseSpecials(result, 'create')

            if result["syscall"] in self.write_syscalls and result["args"][0] == '1':
                tmp_stdout = {}
                tmp_stdout['pid'] = int(result["pid"]) if self._straceOptions["havePid"] else 0
                tmp_stdout['data'] = result["args"][1][1:-1]
                tmp_stdout['bytes'] = result["args"][2]
                self.specials['stdout'].append(tmp_stdout)

            if result["syscall"] in self.write_syscalls and result["args"][0] == '2':
                tmp_stderr = {}
                tmp_stderr['pid'] = int(result["pid"]) if self._straceOptions["havePid"] else 0
                tmp_stderr['data'] = result["args"][1][1:-1]
                tmp_stderr['bytes'] = result["args"][2]
                self.specials['stderr'].append(tmp_stderr)

            if result["syscall"] in self.unlink_syscalls:
                if result["syscall"] == 'unlinkat':
                    self.parseSpecials(result, 'unlink', 1)
                elif result["syscall"] == 'unlink':
                    self.parseSpecials(result, 'unlink')

            if result["syscall"] in self.execve_syscalls:
                tmp_execve = {}
                tmp_execve['pid'] = int(result["pid"]) if self._straceOptions["havePid"] else 0
                exe_cmd = ''
                for s in result["args"][1]:
                    if ' ' in s:
                        s = s
                    else:
                        s = s.replace('"', '')
                    exe_cmd = exe_cmd + s + ' '
                exe_cmd = exe_cmd[:-1]
                tmp_execve['command'] = exe_cmd
                if result["return"] == "-1":
                    tmp_execve['error'] = 1
                    tmp_execve['error_info'] = result['error']
                else:
                    tmp_execve['error'] = 0
                self.specials['execve'].append(tmp_execve)

            if result["syscall"] in self.socket_syscalls:
                tmp_socket = {}
                tmp_socket['pid'] = int(result["pid"]) if self._straceOptions["havePid"] else 0
                tmp_socket['args'] = result["args"]
                tmp_socket['fd'] = str(result["return"])
                tmp_socket['timestamp'] = result["startTime"]
                self.network['socket'].append(tmp_socket)

            if result["syscall"] in self.connect_syscalls:
                tmp_connect = {}
                tmp_connect['pid'] = int(result["pid"]) if self._straceOptions["havePid"] else 0
                tmp_connect['fd'] = str(result["args"][0])
                tmp_connect['timestamp'] = result["startTime"]
                tmp_connect['args'] = result["args"][1]
                self.network['connect'].append(tmp_connect)

            if result["syscall"] in self.kill_syscalls:
                tmp_kill = {}
                tmp_kill['pid'] = int(result["pid"]) if self._straceOptions["havePid"] else 0
                tmp_kill['kill_pid'] = result["args"][0]
                if result["return"] == "-1":
                    tmp_kill['error'] = 1
                    tmp_kill['error_info'] = result['error']
                else:
                    tmp_kill['error'] = 0
                self.specials['kill'].append(tmp_kill)

    def jsonOutput(self):
        last_time = datetime.utcfromtimestamp(0)
        # print self.network['connect']
        # print self.network['socket']
        # FIXME
        for conn in self.network['connect']:
            for socks in self.network['socket']:
                if conn['pid'] == socks['pid'] and conn['fd'] == socks['fd']:
                    if (conn['timestamp'] > last_time) and (conn['timestamp'] > socks['timestamp']):
                        tmp_socket = {}
                        tmp_socket['timestamp'] = str(conn['timestamp'])
                        tmp_socket['pid'] = conn['pid']
                        tmp_socket['fd'] = conn['fd']
                        tmp_socket['socket_args'] = socks['args']
                        tmp_socket['connect_args'] = conn['args']
                        self.specials['network'].append(tmp_socket)
                        self.network['socket'].remove(socks)
                        last_time = conn['timestamp']
                        break
                else:
                    last_time = socks['timestamp']
        return self.specials

class StatStatics(StatBase):
    """ Summarize of syscall of strace, like strace -c output"""

    def __init__(self):
        self._syscallCount = defaultdict(int)
        self._syscallTime = defaultdict(timedelta)
        self._straceOptions = {}
        self.result = {}
        self.syscall_order = ''
        self.result['syscall'] = []
        self.result['syscall_ssdeep'] = ''

    def getSyscallHooks(self):
        return {"ALL": self.record}

    def isOperational(self, straceOptions):
        self._straceOptions = straceOptions
        if not straceOptions["haveTimeSpent"]:
            return False
        return True

    def record(self, result):
        self._syscallCount[result["syscall"]] += 1
        if result["timeSpent"]:
            self._syscallTime[result["syscall"]] += result["timeSpent"]
        tmp_syscall = {}
        tmp_syscall['pid'] = int(result["pid"]) if self._straceOptions["havePid"] else 0
        tmp_syscall['timestamp'] = str(result["startTime"])
        tmp_syscall['pointer'] = result['pointer'] if self._straceOptions["havePointer"] else 0
        tmp_syscall['syscall'] = result["syscall"]
        self.syscall_order += result["syscall"] + '\n'
        tmp_syscall['args'] = result["args"]
        tmp_syscall['return'] = result["return"]
        tmp_syscall['error'] = result['error']
        tmp_syscall['timespent'] = str(result["timeSpent"])
        self.result['syscall'].append(tmp_syscall)

    def jsonOutput(self):
        self.result['syscall_ssdeep'] = ssdeep.hash(self.syscall_order)
        jsonresult = ''
        jsonresult += "\n  time     seconds     calls syscall"
        jsonresult += "\n------ ----------- --------- ----------------"
        totalCount = sum(self._syscallCount.values())
        totalTime = reduce(lambda x,y: x+y, self._syscallTime.values())
        for syscall in sorted(self._syscallTime, key=self._syscallTime.get, reverse=True):
            percent = self._syscallTime[syscall].total_seconds() * 100 / totalTime.total_seconds()
            usecsPerCall = self._syscallTime[syscall] / self._syscallCount[syscall]
            jsonresult += "\n%6.2f %11.6f %9d %s" % (percent, self._syscallTime[syscall].total_seconds(), self._syscallCount[syscall], syscall)

        jsonresult += "\n------ ----------- --------- ----------------"
        jsonresult += "\n%6.2f %11.6f %11d %9d %s" % (100, totalTime.total_seconds(), totalTime.total_seconds()*(10**6) / totalCount, totalCount, "total")
        self.result['summary'] = jsonresult
        return self.result

class StraceAnalysiser:
    def __init__(self, filename):
        self.filename = filename
        self.reader = None
        self.parser = None
        self.options = None
        self.report = {}
        self.report['ptree'] = {}
        self.report['file'] = {}
        self.report['network'] = []
        self.report['stats'] = {}
        self.report['special'] = {}
        self.report['special']['std'] = {}
        self.report['special']['kill'] = []
        self.report['special']['mkdir'] = []
        self.report['special']['unlink'] = []
        self.report['special']['execve'] = []


    def parser_model(self, obj):
        self.reader = io.open(self.filename)
        self.parser = StraceParser()
        self.options = self.parser.autoDetectFormat(self.reader)
        obj.isOperational(self.options)
        hooks = obj.getSyscallHooks()
        if hooks:
            for syscall, func in hooks.iteritems():
                self.parser.registerSyscallHook(syscall, func)
        hooks = obj.getRawSyscallHooks()
        if hooks:
            for syscall, func in hooks.iteritems():
                self.parser.registerRawSyscallHook(syscall, func)

        ## Go ahead and parse the file
        self.parser.startParse(self.reader, self.options)

        ## print the result of the stat plugins
        self.reader.close()
        return obj.jsonOutput()

    def parser_ptree(self):
        obj = StatProcessTree()
        self.report['ptree'] = self.parser_model(obj)

    def parser_fileio(self):
        obj = StatFileIO()
        file_data = self.parser_model(obj)
        total_file_list = []
        #failed open
        self.report['file']['open_failed'] = file_data['failed']
        for failed_file in file_data['failed']:
            total_file_list.append(failed_file['file'])
        # total_file
        file_list = file_data['sucess']['total_file']
        total_file_list.extend(file_list)
        self.report['file']['total'] = list(set(total_file_list))

        # read
        read_list = file_data['sucess']['read']
        self.report['file']['read'] = []
        if len(read_list) > 0:
            for read in read_list:
                tmp_file = {}
                filename = "read_" + read['file_name'][1:-1].replace('/', '_')
                tmp_file['pid'] = str(read['pid'])
                tmp_file['file_name'] = read['file_name'][1:-1]
                tmp_file['file_size'] = str(read['read_bytes'])
                tmp_file['is_close'] = str(read['is_close'])
                self.report['file']['read'].append(tmp_file)

        write_list = file_data['sucess']['write']
        self.report['file']['create'] = []
        if len(write_list) > 0:
            for write in write_list:
                tmp_file = {}
                filename = "write_" + write['file_name'][1:-1].replace('/', '_')
                filepath = os.path.join(DROP_FLODER, filename)
                f = open(filepath, 'wb')
                f.write(write['data'])
                f.close()
                filemd5 = file_md5(filepath)
                new_path = os.path.join(DROP_FLODER, filemd5)
                shutil.move(filepath, new_path)
                tmp_file['pid'] = str(write['pid'])
                tmp_file['file_name'] = write['file_name'][1:-1]
                tmp_file['file_path'] = new_path
                tmp_file['file_size'] = str(write['write_bytes'])
                tmp_file['file_md5'] = filemd5
                tmp_file['is_close'] = str(write['is_close'])
                self.report['file']['create'].append(tmp_file)

    def parser_special(self):
        obj = StatSpecialSyscall()
        special_list = self.parser_model(obj)
        tmp_std = {}
        tmp_std['stdout'] = special_list['stdout']
        tmp_std['stderr'] = special_list['stderr']
        self.report['special']['std'] = tmp_std

        unlink_list = special_list['unlink']
        self.report['special']['unlink'] = unlink_list

        mkdir_list = special_list['mkdir']
        self.report['special']['mkdir'] = mkdir_list

        kill_list = special_list['kill']
        self.report['special']['kill'] = kill_list

        execve_list = special_list['execve']
        self.report['special']['execve'] = execve_list

        network_list = special_list['network']
        for net in network_list:
            family = ''
            type = ''
            port = ''
            ip = ''
            tmp_conn = {}
            if net['socket_args'][0] in ['AF_INET', 'PF_INET']:
                family = 'IPv4'
            elif net['socket_args'][0] in ['AF_INET6', 'PF_INET6']:
                family = 'IPv6'
            elif net['socket_args'][0] in ['PF_UNIX', 'AF_UNIX', 'PF_LOCAL', 'AF_LOCAL']:
                family == 'UNIX'
            else:
                family = 'UNKNOWN'

            if 'SOCK_DGRAM' in net['socket_args'][1] and net['socket_args'][2] in ['IPPROTO_IP', 'IPPROTO_UDP']:
                type = 'UDP'
            elif 'SOCK_STREAM' in net['socket_args'][1] and net['socket_args'][2] in ['IPPROTO_IP', 'IPPROTO_TCP']:
                type = 'TCP'
            elif net['socket_args'][2] == 'IPPROTO_ICMP':
                type = 'ICMP'
            else:
                type = 'UNKNOWN'

            if len(net['connect_args']) == 3:
                port = net['connect_args'][1].replace('sin_port=htons(', '').replace(')', '')
                ip = net['connect_args'][2].replace('sin_addr=inet_addr("', '').replace('")', '')

            if family != 'UNKNOWN' and type != 'UNKNOWN':
                tmp_conn['family'] = family
                tmp_conn['type'] = type
                tmp_conn['ip'] = ip
                tmp_conn['port'] = port
                self.report['network'].append(tmp_conn)

    def parser_stats(self):
        obj = StatStatics()
        self.report['stats'] = self.parser_model(obj)

    def runstats(self):
        f = open(self.filename, 'r')
        lines = f.readlines()
        last_line = lines[-1]
        f.close()
        m1 = re.search(r'killed by ([^\n]*) ', last_line)
        m2 = re.search(r'exited with ([^\n]*) ', last_line)
        run_flag = 1
        tmp_run = {}
        error_info = ''
        error_type = ''
        if m1:
            error_info = m1.group(1)
            run_flag = 0
            error_type = 'killed'
        elif m2:
            error_info = m2.group(1)
            run_flag = 0
            error_type = 'exited'
        tmp_run['stats'] = run_flag
        tmp_run['type'] = error_type
        tmp_run['error_info'] = error_info
        self.report['runlog'] = tmp_run

    def handle(self):
        self.runstats()
        self.parser_ptree()
        self.parser_fileio()
        self.parser_special()
        self.parser_stats()


if __name__ == "__main__":
    s = StraceAnalysiser(sys.argv[1])
    s.handle()
    # j = json.dumps(s.report, sort_keys=True, indent=4, separators=(',', ': '))
    # f = open('test_strace.json', 'wb')
    # f.write(j)
    # f.close()
    print '************** Strace Analysiser **************'
    if s.report:
        print '> Run log: '
        if s.report['runlog']['stats']:
            print 'Stats: Sucess'
        else:
            print 'Stats: Failed', "Type:", s.report['runlog']['type'], "Info:", s.report['runlog']['error_info']

        print '> Strace summary: '
        print s.report['stats']['summary']

        print '> Syscall ssdeep: '
        # print s.report['stats']['syscall_order']

        print s.report['stats']['syscall_ssdeep']

        print '> Process Tree: '
        print s.report['ptree']['result']

        creates = s.report['file']['create']
        if len(creates) > 0:
            print '> Create Files: '
            for create in creates:
                flag = ''
                if create['is_close'] == '1':
                    flag = ''
                else:
                    flag = '*'

                print '\t' + create['file_name'] + ' ' + flag + '\t' + create['file_md5'] + '\t' + create['file_size']

        std = s.report['special']['std']
        if len(std['stdout']) > 0:
            print '> Std Out: '
            for stdout in std['stdout']:
                print '\t'+ str(stdout['data'])

        if len(std['stderr']) > 0:
            print '> Std Error: '
            for stderr in std['stderr']:
                print '\t'+ str(stderr['data'])

        execves = s.report['special']['execve']
        if len(execves) > 0:
            print '> Execve Commands: '
            for execve in execves:
                if execve['error']:
                    print '\t' + execve['command'], execve['error_info']
                else:
                    print '\t'+ execve['command']

        unlinks = s.report['special']['unlink']
        if len(unlinks) > 0:
            print '> Unlink: '
            for unlink in unlinks:
                if unlink['error']:
                    print '\t' + unlink['file_name'], unlink['error_info']
                else:
                    print '\t' + unlink['file_name']

        mkdirs = s.report['special']['mkdir']
        if len(unlinks) > 0:
            print '> Mkdir: '
            for mkdir in mkdirs:
                if mkdir['error']:
                    print '\t' + mkdir['file_name'], mkdir['error_info']
                else:
                    print '\t' + mkdir['file_name']

        networks = s.report['network']
        if len(networks) > 0:
            print '> Network: '
            for network in networks:
                print '\t' + network['family'] + '\t' + network['type'] + '\t' + network['ip'] + ':' + network['port']
