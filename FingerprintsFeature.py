

def getFlowCyclicalFingerprints(data):    
    datanums=dict()
    for s_data in data:
        if len(s_data)>1 and len(set(s_data))==1:
            ele=s_data[0]
            if ele not in datanums:
                datanums[ele]=len(s_data)
            else:
                datanums[ele]+=len(s_data)
    if 0 in datanums and datanums[0]<6:
        del datanums[0]
    return datanums

def getFlowDuplicateFingerprints(data):
    timeData=dict()
    dataCombind=list(zip(data[1:],data[:-1]))
    for data in dataCombind:
        new_data=tuple([tuple(set(data[0])),tuple(set(data[1]))])
        if new_data not in timeData:
            timeData[new_data]=1
        else:
            timeData[new_data]+=1
    for key, value in list(timeData.items()):
        if key==((0,),(0,)):
            del timeData[key]
        elif value<2:
            del timeData[key]
    return timeData

def getFlowSameFingerprints(data):
    if len(set(data))==1:
        return data[0],len(data)
    else:
        return -1,-1

