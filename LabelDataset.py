import datetime
import json
import os
import pytz
import pandas as pd

from utils.FileUtils import readDataFromJson, saveDataToJson
pd.set_option('display.max_columns',None)
pd.set_option('display.max_rows',None)


def readLabelds(filepath):
    with open(filepath) as f:
        for line in f:
            headers=line.strip().split(",")
            break
    headerType=dict()
    for item in headers:
        headerType[item]=str
    data=pd.read_csv(filepath,dtype=headerType,encoding_errors="ignore")
    data=data.dropna(axis=0,how='all') 
    return data

def labelData(flowdata,labelsList,saveFilename):
    for labels in labelsList:
        labelinfodict=dict()
        for labelinfo in labels:
            srcip,srcport,dstip,dstport=labelinfo[1:5]
            labelKey=(srcip,srcport,dstip,dstport)
            labelKeyReversed=(dstip,dstport,srcip,srcport,)
            if labelKey not in labelinfodict and labelKeyReversed not in labelinfodict:
                labelinfodict[labelKey]=list()
                labelinfodict[labelKey].append(labelinfo[-1])
            elif labelKey in labelinfodict:
                labelinfodict[labelKey].append(labelinfo[-1])
            else:
                labelinfodict[labelKeyReversed].append(labelinfo[-1])
        for flowkey,flowlabels in labelinfodict.items():
            srcip,srcport,dstip,dstport=flowkey
            labelKey=(srcip,srcport,dstip,dstport)
            labelKeyReversed=(dstip,dstport,srcip,srcport,)
            if labelKey not in flowdata and labelKeyReversed not in flowdata:
                continue
            elif labelKey in flowdata:
                flowdata[labelKey]["labels"]=flowlabels
            else:
                flowdata[labelKeyReversed]["labels"]=flowlabels
    flowdatasave={str(k):v for k,v in flowdata.items()}
    saveDataToJson(flowdatasave,saveFilename)
    
def labelDataByIp(flowdata,srcip,dstip,label,saveFilename):
    for flowid,_ in flowdata.items():
        if flowid[0]==srcip and flowid[2]==dstip or flowid[2]==srcip and flowid[0]==dstip :
            flowdata[flowid]["labels"]=[label]
        else:
            flowdata[flowid]["labels"]=["BENIGN"]
    flowdatasave={str(k):v for k,v in flowdata.items()}
    saveDataToJson(flowdatasave,saveFilename)
    
def filterUnlabeledData(markedFilepath): 
    data=readDataFromJson(markedFilepath)
    for flowid in list(data):
        if "labels" not in data[flowid]:
            del data[flowid]
    return data
            
if __name__ == "__main__": 
    pass