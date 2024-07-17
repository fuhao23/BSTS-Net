
from utils.StatisticalUtils import getDataNumStatic


def getSegByDirs(data):
    res=list()
    cur_dir=data[0]
    cur_start=0
    for d_index,d_item in enumerate(data):
        if d_item!=cur_dir:
            res.append([cur_start,d_index])
            cur_start=d_index
            cur_dir=d_item
    res.append([cur_start,len(data)])
    return res
    
def getDataBySegIndex(data,indexSegs):  
    res=[data[g_index[0]:g_index[1]] for g_index in indexSegs]
    return res
            
def getDataByBiDirs(datas,dirs):
    res={
        True:list(),
        False:list()
    }
    for d_index,item in enumerate(dirs):
        res[item].append(datas[d_index])
    res[True]=getDataNumStatic(res[True])
    res[False]=getDataNumStatic(res[False])
    return res

def splitDataByIp(data):
    res=dict()
    for fid,fdata in data.items():
        srcip,srcport,dstip,dstport=fid
        ipid=(srcip,dstip)
        if ipid not in res:
            res[ipid]=list()
        res[ipid].append([(srcport,dstport),fdata])
    return res

def getInfoByFlowid(data,flowid):
    return data[flowid]["infos"]