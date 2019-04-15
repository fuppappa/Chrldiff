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
    def __init__(self, jsnfile=None):
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


def get_args():
    parser = ArgumentParser()

    parser.add_argument('arg1', help='charles log')
    parser.add_argument('arg2', help='APItracer log')

    args = parser.parse_args()

    return (args)


def diff_deep_result(result_list, m, n):
    global DEEPDIFF_RESULTLIST
    i = 0
    mc_count = 0
    ad_count = 0
    rm_count = 0

    while i < len(result_list):
        if result_list[i].dir == 's':
            print(COL['CLEAR'] + "  " + str(n[result_list[i].ni]))
            mc_count += 1
        elif result_list[i].dir == 'r':
            print(COL['GREEN'] + "+ " + str(n[result_list[i].ni]))
            ad_count += 1
        elif result_list[i].dir == 'b':
            print(COL['RED'] + "- " + str(m[result_list[i].mi]))
            rm_count += 1
        i += 1
    DEEPDIFF_RESULTLIST.append(mc_count)
    DEEPDIFF_RESULTLIST.append(ad_count)
    DEEPDIFF_RESULTLIST.append(rm_count)


def diff_compare(ch, tr):
    if TARGETAPI_PROFILESLIST[3] == tr["api_infos"]["trace_api"]:
        if not "" == tr["data"][SENDAPI_PROFILES[TARGETAPI_PROFILESLIST[3]]["data_string"]]:
            api_target = tr["data"][SENDAPI_PROFILES[TARGETAPI_PROFILESLIST[3]]["data_string"]]
            ch_p = ch["data"]["header"]["firstLine"]

            for i in range(len(ch["data"]["header"]["headers"])):
                ch_p = ch_p + ch["data"]["header"]["headers"][i]

            diff.diff(ch_p, api_target, diff.default_compare, diff_deep_result)
            if DEEPDIFF_RESULTLIST[0] >= len(ch) // 1.7:
                return True
            else:
                return False
    else:
        ch_p = ch["data"]["header"]["firstLine"]

        for i in range(len(ch["data"]["header"]["headers"])):
            ch_p = ch_p + ch["data"]["header"]["headers"][i]
        api_target = tr["data"][SENDAPI_PROFILES[TARGETAPI_PROFILESLIST[3]]["data"]["send_data"]]
        c = ChrlsParser()
        diff.diff(c.utf8_decoder(ch_p), api_target, diff.default_compare, diff_deep_result)
        if DEEPDIFF_RESULTLIST[0] >= len(ch) // 1.7:
            return True
        else:
            return False

    if TARGETAPI_PROFILESLIST[5] == tr["api_infos"]["trace_api"]:
        if not "" == tr["data"][SENDAPI_PROFILES[TARGETAPI_PROFILESLIST[5]]["data_string"]]:
            api_target = tr["data"][SENDAPI_PROFILES[TARGETAPI_PROFILESLIST[5]]["data_string"]]
            ch_p = ch["data"]["header"]["firstLine"]

            for i in range(len(ch["data"]["header"]["headers"])):
                ch_p = ch_p + ch["data"]["header"]["headers"][i]

            diff.diff(ch_p, api_target, diff.default_compare, diff_deep_result)
            if DEEPDIFF_RESULTLIST[0] >= len(ch) // 1.7:
                return True
            else:
                return False
    else:
        ch_p = ch["data"]["header"]["firstLine"]

        for i in range(len(ch["data"]["header"]["headers"])):
            ch_p = ch_p + ch["data"]["header"]["headers"][i]
        api_target = tr["data"][SENDAPI_PROFILES[TARGETAPI_PROFILESLIST[5]]["data"]["send_data"]]
        diff.diff(ch_p, api_target, diff.default_compare, diff_deep_result)
        if DEEPDIFF_RESULTLIST[0] >= len(ch) // 1.7:
            return True
        else:
            return False


    if TARGETAPI_PROFILESLIST[6] == tr["api_infos"]["trace_api"]:
        if not "" == tr["data"][SENDAPI_PROFILES[TARGETAPI_PROFILESLIST[6]]["data_string"]]:
            api_target = tr["data"][SENDAPI_PROFILES[TARGETAPI_PROFILESLIST[6]]["data_string"]]
            ch_p = ch["data"]["header"]["firstLine"]

            for i in range(len(ch["data"]["header"]["headers"])):
                ch_p = ch_p + ch["data"]["header"]["headers"][i]

            diff.diff(ch_p, api_target, diff.default_compare, diff_deep_result)
            if DEEPDIFF_RESULTLIST[0] >= len(ch) // 1.7:
                return True
            else:
                return False
    else:
        ch_p = ch["data"]["header"]["firstLine"]

        for i in range(len(ch["data"]["header"]["headers"])):
            ch_p = ch_p + ch["data"]["header"]["headers"][i]
        api_target = tr["data"][SENDAPI_PROFILES[TARGETAPI_PROFILESLIST[6]]["data"]["send_data"]]
        diff.diff(ch_p, api_target, diff.default_compare, diff_deep_result)
        if DEEPDIFF_RESULTLIST[0] >= len(ch) // 1.7:
            return True
        else:
            return False




# target 3,5,6
def exportdiff(chrls, tracer):
    target_apilist = [TARGETAPI_PROFILESLIST[3], TARGETAPI_PROFILESLIST[5], TARGETAPI_PROFILESLIST[6]]
    apidiff_target = []
    for i in range(1, len(tracer)):
        if tracer[i]["api_infos"]["trace_api"] in target_apilist:
            apidiff_target.append(tracer[i])

    del chrls[0]
    diff.diff(chrls, apidiff_target, diff_compare, diff.default_print_result)


def main():
    args = get_args()
    print('you inputed {} {}'.format(args.arg1, args.arg2))
    chrl = ChrlsParser(args.arg1)
    tracer = APITraceParser(args.arg2)
    chrl.parser()
    tracer.parser()
    exportdiff(chrl.targets_list.copy(), tracer.api_list.copy())


if __name__ == '__main__':
    print(tm.now())
    a = APITraceParser("log/com.Lukaku.pictures.backgrounds.photos.images.hd.free.sports_2019_3_30_15-2-9_shaping.json")
    a.parser()
    b = ChrlsParser(
        "log/com.Lukaku.pictures.backgrounds.photos.images.hd.free.sports_2019_3_30_15-2-9_charles_shaping.json")
    b.parser()
    exportdiff(b.targets_list.copy(), a.api_list.copy())
