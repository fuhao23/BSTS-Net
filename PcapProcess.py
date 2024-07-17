import json
import os

import numpy as np

from utils.FileUtils import readDataFromJson

def readZeekLog(filepath):
    filedata = list()
    with open(filepath, "r", encoding="utf8") as f:
        for line in f:
            filedata.append(json.loads(line.strip()))
    return filedata

def readMarkedZeekJsonLog(filepath):
    filedata = list()
    with open(filepath, "r", encoding="utf8") as f:
        filedata= json.loads(f.read())
        return filedata

def aggPktToFlow(logdata):
    logdata=sorted(logdata,key=lambda flowinfo:flowinfo["timestamp"])
    res=dict()
    for finfo in logdata:
        key=(finfo["srcip"],str(finfo["srcport"]),finfo["dstip"],str(finfo["dstport"]))
        key_reversed=(finfo["dstip"],str(finfo["dstport"]),finfo["srcip"],str(finfo["srcport"]),)
        if key not in res and key_reversed not in res:
            res[key]={
                "flowinfo":list(),
            }
            res[key]["flowinfo"].append({
                "is_orig":finfo["is_orig"],
                "applayerlength":finfo["applayerlength"],
                "timestamp":finfo["timestamp"],
                "appinfo":finfo["appinfo"] if "appinfo" in finfo else ""
            })
        elif key in res:
            res[key]["flowinfo"].append({
                "is_orig":finfo["is_orig"],
                "applayerlength":finfo["applayerlength"],
                "timestamp":finfo["timestamp"],
                "appinfo":finfo["appinfo"] if "appinfo" in finfo else ""
            })
        else:
            res[key_reversed]["flowinfo"].append({
                "is_orig":not finfo["is_orig"],
                "applayerlength":finfo["applayerlength"],
                "timestamp":finfo["timestamp"],
                "appinfo":finfo["appinfo"] if "appinfo" in finfo else ""
            })
    return res

def aggregatePacketToFlowSorted(data: list):
    flow_u_data = dict()
    data_len=len(data)
    for pkt_i in range(data_len):
        uid=data[pkt_i]["uid"]
        if uid not in flow_u_data:
            flow_u_data[uid]=list()
        del data[pkt_i]["uid"]
        flow_u_data[uid].append(data[pkt_i])
    flow_data = dict()
    for uid,fdata in flow_u_data.items():
        srcip=fdata[0]["srcip"]
        srcport=fdata[0]["srcport"]
        dstip=fdata[0]["dstip"]
        dstport=fdata[0]["dstport"]
        fuid=(srcip,srcport,dstip,dstport)
        if fuid not in flow_data:
            flow_data[fuid]=list()
        for f_i,_ in enumerate(fdata):
            del fdata[f_i]["srcip"]
            del fdata[f_i]["srcport"]
            del fdata[f_i]["dstip"]
            del fdata[f_i]["dstport"]
        flow_data[fuid].append(fdata)
    del flow_u_data
    for fid,data in flow_data.items():
        if len(data)>2:
            begainTss=[item[0]["timestamp"] for item in data]
            begainTssSortedIndexs=np.argsort(begainTss)
            new_data=list()
            for item in begainTssSortedIndexs:
                new_data.extend(data[item])
            flow_data[fid]=new_data
        else:
            flow_data[fid]=data[0]
    return flow_data

def getDataFromPkt(logfilepath,marked=False):
    feas=dict()
    if not marked:
        flow_datas= aggregatePacketToFlowSorted(readZeekLog(logfilepath))
    else:
        flow_datas= aggregatePacketToFlowSorted(readMarkedZeekJsonLog(logfilepath))
    for flowId,flows in flow_datas.items():
        feas[flowId]=dict()
        feas[flowId]["lens"]=[item["applayerlength"] for item in flows]
        feas[flowId]["tss"]=[item["timestamp"] for item in flows]
        feas[flowId]["dirs"]=[item["is_orig"] for item in flows]
        feas[flowId]["infos"]=list()
        if marked:
            feas[flowId]["labels"]=[item["label"] for item in flows]
        for flowData in flows:
            f_info=flowData["appinfo"] if "appinfo" in flowData else ""
            feas[flowId]["infos"].append(f_info)
    feas_sorted = sorted(feas.items(), key=lambda x: x[1]["tss"][0])
    feas_sorted_dict={key:value for key,value in feas_sorted}
    feas=feas_sorted_dict
    return feas

def getDataFromFlow(logfilepath):
    feas=dict()
    flow_datas= readDataFromJson(logfilepath)
    for flowId,flows in flow_datas.items():
        feas[flowId]=dict()
        feas[flowId]["lens"]=[item["applayerlength"] for item in flows["flowinfo"]]
        feas[flowId]["tss"]=[item["timestamp"] for item in flows["flowinfo"]]
        feas[flowId]["dirs"]=[item["is_orig"] for item in flows["flowinfo"]]
        feas[flowId]["infos"]=list()
        feas[flowId]["labels"]=flows["labels"]
        for flowData in flows:
            f_info=flowData["appinfo"] if "appinfo" in flowData else ""
            feas[flowId]["infos"].append(f_info)
    feas_sorted = sorted(feas.items(), key=lambda x: x[1]["tss"][0])
    feas_sorted_dict={key:value for key,value in feas_sorted}
    feas=feas_sorted_dict
    return feas