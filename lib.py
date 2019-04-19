import sys
import json
from datetime import datetime
import hashlib
import codecs

"""
Basic and essential functions
"""

__author__ = "tfukuda"
__version__ = "0.1"
__date__ = "2018_9_14"

MOD_SEPARATOR_NUM = 2
WELLKNOWN_MODS_2 = [
    ["com", "google"],
    ["com", "android"],
    ["libcore", "io"],
    ["libcore", "net"],
    ["dalvik"],
    ["android"],
    ["okhttp3"],
    ["okio"],
    ["java"],
    ["javax"]
]
MUSTJOIN_PTR = [
    ["jp", "co"],
    ["jp", "ne"],
    ["net", "jp"],
    ["org", "apache"]
]


def getColors():
    ecp = "\033["
    return {
        "GRAY": ecp + str(90) + ";2m",
        "RED": ecp + str(91) + ";2m",
        "GREEN": ecp + str(92) + ";2m",
        "YELLOW": ecp + str(33) + ";2m",
        "BLUE": ecp + str(94) + ";2m",
        "PURPLE": ecp + str(95) + ";2m",
        "CYAN": ecp + str(96) + ";2m",
        "GRAY_E": ecp + str(90) + ";1m",
        "RED_E": ecp + str(91) + ";1m",
        "GREEN_E": ecp + str(92) + ";1m",
        "YELLOW_E": ecp + str(33) + ";1m",
        "BLUE_E": ecp + str(94) + ";1m",
        "PURPLE_E": ecp + str(95) + ";1m",
        "CYAN_E": ecp + str(96) + ";1m",
        "GRAY_U": ecp + str(90) + ";4m",
        "RED_U": ecp + str(91) + ";4m",
        "GREEN_U": ecp + str(92) + ";4m",
        "YELLOW_U": ecp + str(33) + ";4m",
        "BLUE_U": ecp + str(94) + ";4m",
        "PURPLE_U": ecp + str(95) + ";4m",
        "CYAN_U": ecp + str(96) + ";4m",
        "CLEAR": ecp + str(0) + "m"
    }


def getCurrentTime():
    return datetime.now().strftime("%Y/%m/%d/%H:%M:%S")


def loadJson(path):
    ret = None
    f = codecs.open(path, "r", "utf-8")
    try:
        ret = json.loads(f.read(), strict=False)
    except json.JSONDecodeError as e:
        tb = sys.exc_info()[2]
        msgs = "{0}".format(e.with_traceback(tb))
        f.seek(0, 0)
        if len(msgs) > 3 and msgs[3].isdigit() and int(msgs[3]) == len(f.readlines()):
            f.close()
            f = open(path, "a")
            f.write("]}")
            f.close()
            ret = json.load(open(path, "r"))
        else:
            raise e
    f.close()

    return ret


def set_default(obj):
    if isinstance(obj, set):
        return list(obj)


def writeJson(loaded, path):
    with open(path, "w") as f:
        f.write(json.dumps(loaded, indent=2, default=set_default, sort_keys=True))


def printJson(loaded):
    print(json.dumps(loaded, indent=2, default=set_default, sort_keys=True))


def setAnalyzedHistory(loaded, analysisType):
    if not "analyzed_histories" in loaded:
        loaded["analyzed_histories"] = []
    loaded["analyzed_histories"].append({getCurrentTime(): analysisType})


def str2millitime(strTime):
    """
    Log time format of API Tracer format is [hour]:[min]:[sec].[millisec]
    
    """
    sep1 = strTime.split(":")
    weight = 1
    sep2 = sep1[2].split(".")

    ret = 0
    ret += int(sep2[1])
    weight *= 1000
    ret += int(sep2[0]) * weight
    weight *= 60
    ret += int(sep1[1]) * weight
    weight *= 60
    ret += int(sep1[0]) * weight

    return ret


def splitStackframe(stackframe):
    """
    Return value is (splited_class[], method)
    """
    if "***" in stackframe:
        return None
    splited = stackframe.split(".")
    return (splited[0:-1], splited[-1])


def md5(target):
    return hashlib.md5(target.encode("utf-8")).hexdigest()


def sha1(target):
    return hashlib.sha1(target.encode("utf-8")).hexdigest()


def sha256(target):
    return hashlib.sha256(target.encode("utf-8")).hexdigest()


def sha512(target):
    return hashlib.sha512(target.encode("utf-8")).hexdigest()


def hexstr2ipaddr(target):
    if len(target) != 8:
        return None
    return str(int(target[0:2], 16)) + ":" + str(int(target[2:4], 16)) + ":" + str(int(target[4:6], 16)) + ":" + str(
        int(target[6:8], 16))


def stacks2modules(stacks, sepNum=MOD_SEPARATOR_NUM, wellknowns=WELLKNOWN_MODS_2):
    ret = set([])
    for frame in stacks:
        sepframe = splitStackframe(frame)
        if sepframe == None:
            continue
        klass = sepframe[0]
        wellknownModule = False
        for wellknown in wellknowns:
            if len(wellknown) <= len(klass) and wellknown == klass[0:len(wellknown)]:
                wellknownModule = True
                break
        if wellknownModule:
            continue
        mustjoin = False
        for must in MUSTJOIN_PTR:
            if len(must) <= len(klass) and must == klass[0:len(must)]:
                mustjoin = True
                break
        if mustjoin and len(klass) > sepNum:
            klass = klass[0:sepNum + 1]
        elif len(klass) >= sepNum:
            klass = klass[0:sepNum]
        klass_name = ""
        for namespace in klass:
            klass_name += namespace + "."
        klass_name = klass_name[0:len(klass_name) - 1]
        # ignore special case(obfuscation, etc...)
        complexed_klass_len = klass_name.find('$')
        if len(klass_name) < 5:
            pass
        elif complexed_klass_len != -1 and complexed_klass_len < 5:
            pass
        else:
            ret.add(klass_name)
    return ret


isFirstProgress = True


def showProgress(number, denom, msg):
    global isFirstProgress
    o = sys.stdout.write
    ecp = "\033["
    per = float(number) / denom
    progLen = 25

    if isFirstProgress:
        o("\n")
        isFirstProgress = False

    o(ecp + "1F" + ecp + "K" + ecp + "0G")
    o("[")
    for i in range(0, progLen):
        if per * 100 >= (float(100) / progLen) * (i + 1):
            o("#")
        else:
            o(".")
    o(":" + "{:.2%}".format(per) + "]")
    o(" " + msg + "\n")
    sys.stdout.flush()
