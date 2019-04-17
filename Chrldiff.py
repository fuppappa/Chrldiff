#!/usr/bin/python3
from argparse import ArgumentParser
import json
import codecs
import sys
import ipaddress
import parser
import threading
from datetime import datetime as tm
import copy
import binascii
import diff
import difflib

COL = {
    'CLEAR': '\033[0m',
    'BLACK': '\033[30m',
    'RED': '\033[91m',
    'GREEN': '\033[92m',
    'YELLOW': '\033[93m',
    'BLUE': '\033[34m',
    'PURPLE': '\033[35m',
    'CYAN': '\033[36m',
    'WHITE': '\033[37m'
}

# 無視するapiの名前を列挙ただメソッド名入れない
TARGETAPI_PROFILESLIST = ["java.net.URL",  # 0
                          "com.android.okhttp.internal.huc.HttpURLConnectionImpl",  # 1
                          "org.apache.http.impl.client.DefaultRequestDirector",  # 2
                          "libcore.io.Posix",  # 3
                          "java.net.PlainSocketImpl",  # 4
                          "com.android.org.conscrypt.OpenSSLSocketImpl$SSLOutputStream",  # 5
                          "org.conscrypt.OpenSSLSocketImpl$SSLOutputStream",  # 6
                          "android.webkit.WebView"  # 7
                          ]

# 観測対象のapiに対してどの値を取りたいかを記述する
SENDAPI_PROFILES = {}
# 0 ok
SENDAPI_PROFILES[TARGETAPI_PROFILESLIST[0]] = {
    "time": "trace_time",
    "api": "trace_api",
    "method": "trace_method",
    "stack_frame": "stack",
    "http_method": "return_value.method",
    "host": "return_value.url.host",
    "file": "return_value.url.file",
    "port": "return_value.url.port",
    "data_string": "request_predict"
}
# 1
SENDAPI_PROFILES[TARGETAPI_PROFILESLIST[1]] = {
    "time": "trace_time",
    "api": "trace_api",
    "method": "trace_method",
    "stack_frame": "stack",
    "http_method": "this.httpEngine.networkRequest.method",
    "url": "this.httpEngine.networkRequest.urlString",
    "data_string": "request_predict"
}
# 2
SENDAPI_PROFILES[TARGETAPI_PROFILESLIST[2]] = {
    "time": "trace_time",
    "api": "trace_api",
    "method": "trace_method",
    "stack_frame": "stack",
    "http_method": "",
    "host": "inetAddress.hostName",
    "uri": ""
}
# 3　 able observe http connection
SENDAPI_PROFILES[TARGETAPI_PROFILESLIST[3]] = {
    "time": "trace_time",
    "api": "trace_api",
    "method": "trace_method",
    "stack_frame": "stack",
    "send_data": "bytes",
    "data_size": "byteCount",
    "host": "inetAddress.hostName",
    "data_string": "encoded_byte"
}
# 4
SENDAPI_PROFILES[TARGETAPI_PROFILESLIST[4]] = {
    "time": "trace_time",
    "api": "trace_api",
    "method": "trace_method",
    "stack_frame": "stack",
    "host": "this.address.hostName",
    "ip": "this.address.ipaddress",
    "data_string": "request_predict"

}
# 5 able observe http connection
SENDAPI_PROFILES[TARGETAPI_PROFILESLIST[5]] = {
    "time": "trace_time",
    "api": "trace_api",
    "method": "trace_method",
    "stack_frame": "stack",
    "send_data": "buf",
    "data_size": "byteCount",
    "data_string": "encoded_buf"
}
# 6 able observe http connection
SENDAPI_PROFILES[TARGETAPI_PROFILESLIST[6]] = {
    "time": "trace_time",
    "api": "trace_api",
    "method": "trace_method",
    "stack_frame": "stack",
    "send_data": "buf",
    "data_size": "byteCount",
    "data_string": "encoded_buf"
}
SENDAPI_PROFILES[TARGETAPI_PROFILESLIST[7]] = {
    "time": "trace_time",
    "api": "trace_api",
    "method": "trace_method",
    "stack_frame": "stack",
    "url": "send_url",
    "post": "postData",
    "data_string": "encoded_onlyUrl",
    "data_string2": "url+postData"
}

DEEPDIFF_RESULTLIST = []


class LogParser:
    def __init__(self, jsnfile):
        self.jsnfile = jsnfile
        self.log = self.jsnimport()

    def jsnimport(self):
        try:
            with open(self.jsnfile, 'r') as fd:
                log = json.load(fd)
        except json.JSONDecodeError as e:
            print(sys.exc_info())
            print(e)
            return False
        return log

    def jsnexport(self, data, out):
        try:
            with open(out, 'w') as fd:
                json.dump(data, fd, ensure_ascii=False, indent=4, sort_keys=True, separators=(',', ': '))
        except json.JSONDecodeError as e:
            print(sys.exc_info())
            print(e)
            return False


class ChrlsParser(LogParser):
    def __init__(self, jsnfile):
        super().__init__(jsnfile)
        self.targets_list = []

    def base64tohex_decoder(self, string):
        byte = codecs.encode(string, 'utf-8')
        encoded = codecs.encode(byte, "hex")

        return encoded.decode()

    def utf8tohex_decoder(self, string):
        byte = codecs.encode(string, 'utf-8')
        encoded = codecs.encode(byte, "hex")

        return encoded.decode()

    def parser(self):
        chrlparse_info = {"chrlparse_info": {}}
        chrlparse_info["chrlparse_info"]["time"] = "{}-{}-{} {}:{}:{}".format(tm.now().year, tm.now().month,
                                                                              tm.now().day, tm.now().hour,
                                                                              tm.now().minute, tm.now().second)
        chrlparse_info["chrlparse_info"]["total length"] = len(self.log)
        self.targets_list.append(chrlparse_info)
        for i in range(len(self.log)):
            log = self.log[i]
            infos = {"infos": {}, "data": {}}
            print("parsing {}element now".format(i))
            if "CONNECT" == log["method"]:
                continue
            else:
                if "GET" == log["method"]:
                    infos["infos"]["time"] = log["times"]["requestBegin"]
                    infos["infos"]["ip"] = log["remoteAddress"].split("/")[1]
                    infos["infos"]["method"] = log["method"]
                    infos["infos"]["host"] = log["host"]
                    infos["infos"]["path"] = log["path"]
                    infos["infos"]["protocolVersion"] = log["protocolVersion"]
                    infos["data"]["header"] = {}
                    infos["data"]["header"]["firstLine"] = log["request"]["header"]["firstLine"]
                    infos["data"]["header"]["headers"] = log["request"]["header"]["headers"]

                elif "POST" == log["method"]:
                    infos["infos"]["time"] = log["times"]["requestBegin"]
                    infos["infos"]["ip"] = log["remoteAddress"].split("/")[1]
                    infos["infos"]["method"] = log["method"]
                    infos["infos"]["host"] = log["host"]
                    infos["infos"]["path"] = log["path"]
                    infos["infos"]["protocolVersion"] = log["protocolVersion"]
                    infos["data"]["header"] = {}
                    infos["data"]["header"]["firstLine"] = log["request"]["header"]["firstLine"]
                    infos["data"]["header"]["headers"] = log["request"]["header"]["headers"]
                    infos["body"] = {}
                    try:
                        if "charset" in log["request"]["body"] or "encoding" in log["request"]["body"]:
                            if "charset" in log["request"]["body"]:
                                infos["body"]["format"] = log["request"]["body"]["charset"]
                                infos["body"]["data"] = log["request"]["body"]["text"]
                            elif "encoding" in log["request"]["body"]:
                                infos["body"]["format"] = log["request"]["body"]["encoding"]
                                infos["body"]["data"] = log["request"]["body"]["encoded"]
                    except KeyError as e:
                        print(COL["RED"] + "[ERROR]: not found key in {} element ".format(i + 1) + COL["CLEAR"])
                        print(sys.exc_info())
                        print(e)
                        print(log)

            self.targets_list.append(infos)


class APITraceParser(LogParser):
    def __init__(self, jsnfile):
        super(APITraceParser, self).__init__(jsnfile)
        self.api_list = []

    def ip_encoder(self, hexip):

        split_ip = binascii.unhexlify(hexip)
        try:
            ip = ipaddress.IPv4Address(split_ip)
        except ipaddress.AddressValueError as e:
            print(sys.exc_info())
            print(e)
            print(COL["RED"] + "[ERROR]: hexip of this function variable is not ipaddress" + COL["CLEAR"])
        return ip.exploded

    def utf8_encoder(self, hexstring):
        try:
            print(hexstring)
            if len(hexstring) % 2 != 0:
                hexstring = hexstring[0:len(hexstring) - 1]
            encoded = codecs.decode(hexstring, 'hex_codec').decode('utf-8')
        except UnicodeDecodeError as e:
            print(sys.exc_info())
            print(e)
            print(COL["RED"] + '[ERROR]: failed encoded method of class APITraceParser ' + COL["CLEAR"])
            encoded = ""

        return encoded

    def parser(self):
        target_api = []
        ttl = 0
        tracelogparse_info = {"tracerlogparse_info": {}}
        tracelogparse_info["tracerlogparse_info"]["parseBegin_time"] = "{}-{}-{} {}:{}:{}".format(tm.now().year,
                                                                                                  tm.now().month,
                                                                                                  tm.now().day,
                                                                                                  tm.now().hour,
                                                                                                  tm.now().minute,
                                                                                                  tm.now().second)
        tracelogparse_info["tracerlogparse_info"]["api_total length"] = len(self.log["logs"])
        tracelogparse_info["tracerlogparse_info"]["api_target length"] = ttl
        self.api_list.append(tracelogparse_info)
        for i in range(len(self.log["logs"])):
            flags = False
            if "api_infos" in self.log["logs"][i]:
                for n in range(len(TARGETAPI_PROFILESLIST)):

                    if TARGETAPI_PROFILESLIST[n] == self.log["logs"][i]["reference"]:
                        flags = True
                        break
                if flags:
                    target_api.append(self.log["logs"][i])

        for m in range(len(target_api)):
            for sendapi_num in range(len(TARGETAPI_PROFILESLIST)):
                if target_api[m]["reference"] == TARGETAPI_PROFILESLIST[sendapi_num]:
                    ttl += 1
                    preformat_api = {}
                    preformat_api[TARGETAPI_PROFILESLIST[sendapi_num]] = target_api[m].copy()
                    temp = self.formatter(preformat_api.copy(), TARGETAPI_PROFILESLIST[sendapi_num])
                    self.api_list.append(temp.copy())
                    print("[{}{}] parsing {}element now".format(__class__, sys._getframe().f_code.co_name, m))
        self.api_list[0]["tracerlogparse_info"]["api_target length"] = ttl

    def formatter(self, target, reference):
        global TARGETAPI_PROFILESLIST
        global SENDAPI_PROFILES
        api = target[reference]
        api_num = 0
        for ref in range(len(TARGETAPI_PROFILESLIST)):
            if reference == TARGETAPI_PROFILESLIST[ref]:
                api_num = ref
                break
        return_api = {"api_infos": {}, "data": {}}
        api_profile = SENDAPI_PROFILES[TARGETAPI_PROFILESLIST[api_num]]
        return_api["api_infos"][api_profile["time"]] = api["time"]
        return_api["api_infos"][api_profile["api"]] = TARGETAPI_PROFILESLIST[api_num]
        return_api["api_infos"][api_profile["method"]] = api["method"]
        return_api["api_infos"][api_profile["stack_frame"]] = api["api_infos"]["stack"]
        if api_num == 0:
            return_api["data"][api_profile["http_method"]] = api["api_infos"][api_profile["http_method"]]
            return_api["data"][api_profile["host"]] = api["api_infos"][api_profile["host"]]
            return_api["data"][api_profile["file"]] = api["api_infos"][api_profile["file"]]
            return_api["data"][api_profile["port"]] = api["api_infos"][api_profile["port"]]
            method = return_api["data"][api_profile["http_method"]]
            host = return_api["data"][api_profile["host"]]
            file = return_api["data"][api_profile["file"]]
            return_api[api_profile["data_string"]] = method + " " + host + file
        elif api_num == 1:
            return_api["data"][api_profile["http_method"]] = api["api_infos"][api_profile["http_method"]]
            return_api["data"][api_profile["url"]] = api["api_infos"][api_profile["url"]]
            method = return_api["data"][api_profile["http_method"]]
            url = return_api["data"][api_profile["url"]]
            return_api[api_profile["data_string"]] = method + " " + url

        elif api_num == 2:
            pass

        elif api_num == 3:
            pre_bytes = api["api_infos"]["bytes"]
            return_api["data"][api_profile["send_data"]] = pre_bytes
            return_api["data"][api_profile["data_size"]] = api["api_infos"]["byteCount"]

            if not "<ERROR>" == api["api_infos"]["inetAddress.hostName"]:
                return_api["data"][api_profile["host"]] = api["api_infos"]["inetAddress.hostName"]
            encoded = self.utf8_encoder(pre_bytes)
            index = encoded.find("\u0000\u0000\u0000")
            if not index == -1:
                encoded = encoded[:index - len(encoded)]
            return_api[api_profile["data_string"]] = encoded

        elif api_num == 4:
            if not "<ERROR>" == api["api_infos"]["this.address.hostName"]:
                return_api["data"][api_profile["host"]] = api["api_infos"]["this.address.hostName"]

            if not "<ERROR>" == api["api_infos"][api_profile["ip"]]:
                pre_ip = api["api_infos"][api_profile["ip"]]
                return_api["data"][api_profile["ip"]] = self.ip_encoder(copy.copy(pre_ip))
            else:
                return_api["data"][api_profile["ip"]] = "[ERROR]"

        elif api_num == 5:

            pre_buf = api["api_infos"]["buf"]
            return_api["data"][api_profile["send_data"]] = pre_buf
            return_api["data"][api_profile["data_size"]] = api["api_infos"]["byteCount"]
            buf = self.utf8_encoder(pre_buf)
            index = buf.find("\u0000\u0000\u0000")
            if not index == -1:
                buf = buf[:index - len(buf)]
            return_api[api_profile["data_string"]] = buf

        elif api_num == 6:
            pre_buf = api["api_infos"]["buf"]
            return_api["data"][api_profile["send_data"]] = pre_buf
            return_api["data"][api_profile["data_size"]] = api["api_infos"]["byteCount"]
            buf = self.utf8_encoder(pre_buf)
            index = buf.find("\u0000\u0000\u0000")
            if not index == -1:
                buf = buf[:index - len(buf)]
            return_api[api_profile["data_string"]] = buf

        elif api_num == 7 and "loadUrl":
            pre_url = api["api_infos"]["url"]
            return_api["data"][api_profile["url"]] = pre_url
            url = self.utf8_encoder(pre_url)
            return_api[api_profile["data_string"]] = url[1:-1]
            if "postUrl" == api["method"]:
                pre_url = api["api_infos"]["url"]
                return_api["data"]["url"] = pre_url
                pre_urlpostData = api["api_infos"]["url+postData"]
                url = self.utf8_encoder(pre_url)
                urlpostData = self.utf8_encoder(pre_urlpostData)
                return_api[api_profile["data_string"]] = url
                return_api[api_profile["data_string2"]] = urlpostData

        else:
            print("[ERROR] your selected api is not found")

        return return_api


def utf8_decoder(string):
    byte = codecs.encode(string, 'utf-8')
    encoded = codecs.encode(byte, "hex")

    return encoded.decode()


class Chrl_Diff():
    def __init__(self, chrl, tracer):
        self.total = 0
        self.chrl = chrl
        self.tracer = tracer
        self.result_list = {"mc": 0, "ad": 0, "rm": 0}
        self.now = 0
        self.target_ch = []
        self.target_tracer = []

    def diff_deep_result(self, result_list, m, n):
        global DEEPDIFF_RESULTLIST
        i = 0
        self.result_list["mc"] = 0
        self.result_list["ad"] = 0
        self.result_list["rm"] = 0
        while i < len(result_list):
            if result_list[i].dir == 's':
                print(COL['CLEAR'] + "  " + str(n[result_list[i].ni]), end="")
                self.result_list["mc"] += 1
            elif result_list[i].dir == 'r':
                print(COL['GREEN'] + "+ " + str(n[result_list[i].ni]), end="")
                self.result_list["ad"] += 1
            elif result_list[i].dir == 'b':
                print(COL['RED'] + "- " + str(m[result_list[i].mi]), end="")
                self.result_list["rm"] += 1
            i += 1
        print("-----------------------------------------------------")

    def diff_cmp(self, ch, tr):
        self.total += 1
        ch_t=tm.strptime(ch["time"], "%H:%M:%S")
        tr_t =tm.strptime(tr["time"], "%H:%M:%S")
        delta1 = ch_t - tr_t
        delta2 = tr_t -ch_t
        deltabool = delta1.seconds <= 150 or delta2.seconds <= 150
        if difflib.SequenceMatcher(None, ch["data"], tr["data"]).ratio() >= 0.70 and deltabool:
            return True
        else:
            return False

    # tracer is a element in tracer list
    def chose_target(self, chrl, tracer):

        for i in range(len(chrl)):
            ch = chrl[i]["data"]["header"]["firstLine"]
            for j in range(len(chrl[i]["data"]["header"]["headers"])):
                ch_p = chrl[i]["data"]["header"]["headers"][j]
                ch_pp = ch_p["name"] + " " + ch_p["value"]
                ch = ch + ch_pp + "\r\n"

            ch_time = chrl[i]["infos"]["time"][11:-10]
            # hex_ch = utf8_decoder(ch)
            temp = {"data": ch, "time": ch_time}
            self.target_ch.append(temp)

        for g in range(len(tracer)):

            tr_type = TARGETAPI_PROFILESLIST.index(tracer[g]["api_infos"]["trace_api"])
            '''
            api_target = tracer[g]["data"][SENDAPI_PROFILES[TARGETAPI_PROFILESLIST[tr_type]]["send_data"]]
            index = api_target.find("000000000000000000000000000000000000000000000000")
            if not index == -1:
                api_target = api_target[:index - len(api_target)]
            '''
            api_target = tracer[g][SENDAPI_PROFILES[TARGETAPI_PROFILESLIST[tr_type]]["data_string"]]
            tr_time =  tracer[g]["api_infos"][SENDAPI_PROFILES[TARGETAPI_PROFILESLIST[tr_type]]["time"]][:-4]
            temp1 = {"data": api_target, "time": tr_time}
            self.target_tracer.append(temp1)
        diff.diff(self.target_ch, self.target_tracer, self.diff_cmp, diff.default_print_result)

    # target 3,5,6
    def exportdiff(self):
        target_apilist = [TARGETAPI_PROFILESLIST[3], TARGETAPI_PROFILESLIST[5], TARGETAPI_PROFILESLIST[6]]
        apidiff_target = []
        chrl_target = []
        for i in range(1, len(self.tracer)):
            if self.tracer[i]["api_infos"]["trace_api"] in target_apilist:
                apidiff_target.append(self.tracer[i])
        for m in range(1, len(self.chrl)):
            chrl_target.append(self.chrl[m])

        self.chose_target(chrl_target, apidiff_target)


def get_args():
    parser = ArgumentParser()

    parser.add_argument('arg1', help='charles log')
    parser.add_argument('arg2', help='APItracer log')

    args = parser.parse_args()

    return (args)


def main():
    args = get_args()
    print('you inputed {} {}'.format(args.arg1, args.arg2))
    chrl = ChrlsParser(args.arg1)
    tracer = APITraceParser(args.arg2)
    chrl.parser()
    tracer.parser()
    differ = Chrl_Diff(chrl.targets_list.copy(), tracer.api_list.copy())
    differ.exportdiff()


if __name__ == '__main__':
    print(tm.now())
    main()
