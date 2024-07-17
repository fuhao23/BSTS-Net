from collections import Counter


def getDataNumStatic(data):
    return dict(Counter(data))
  
def getCommonDict(data):
    keyset=set()
    commonkey=list()
    for item in data:
        keyset.update(list(item.keys()))
    for key in keyset:
        all_exist=True
        for item in data:
            if key not in item:
                all_exist=False
                break
        if all_exist:
            commonkey.append(key)
    res={item:-1 for item in commonkey} 
    for key in commonkey:
        for item in data:
            f_num=item[key]
            if res[key]==-1:
                res[key]=f_num
            else:
                if item[key]<res[key]:
                    res[key]=item[key]
    return res
          
def getCommonIpSegs(data):
    true_data=[getDataNumStatic(item[True]) for item in data]
    false_data=[getDataNumStatic(item[False]) for item in data]
    trueCommonSegs=getCommonDict(true_data)
    falseCommonSegs=getCommonDict(false_data)
    return trueCommonSegs,falseCommonSegs
    
def calTimeGaps(timedata):
    if len(timedata)==1:
        return [0]
    return [j-i for i,j in zip(timedata[:-1],timedata[1:])]