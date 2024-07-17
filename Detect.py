from collections import Counter
import random
from numpy import mean
from sklearn.cluster import DBSCAN, KMeans
from sklearn.decomposition import PCA
from sklearn.metrics import f1_score, precision_score, recall_score,accuracy_score

from PcapProcess import getDataFromFlow, getDataFromPkt
from utils.FileUtils import readConfig, readDataFromJson, saveDataToJson

configGlobal=readConfig('./testData/config.yml')

def clusterFlowById(filepath,saveFilepath):
    FEANUM=configGlobal["FEANUM"]
    SAME_DELTA=configGlobal["FEANUM"]
    ipdata=readDataFromJson(filepath)
    ippairFeas=dict()
    for _,ipinfo in ipdata.items():
        for flowinfo in ipinfo:
            srcip=flowinfo["srcip"]
            dstip=flowinfo["dstip"]
            srcport=flowinfo["srcport"]
            dstport=flowinfo["dstport"]
            dstFea=flowinfo["dstportfea"]
            if srcip not in ippairFeas:
                ippairFeas[srcip]=dict()
            keys=(srcip,srcport,dstip,dstport)
            ippairFeas[srcip][keys]={
                "dstfea":list(dstFea.values())[:FEANUM],
                "infos":list(dstFea.values())[FEANUM],
                "labels":flowinfo["label"],
                "srcip":srcip,
                "dstip":dstip
            }
    res=dict()
    for srcip,ippairinfo in ippairFeas.items():
        dstportFea=dict()
        for fg4key,f_fea in ippairinfo.items():
            dstport=fg4key[3]
            if dstport not in dstportFea:
                dstportFea[dstport]=list()
            dstportFea[dstport].append([f_fea["dstfea"],f_fea["infos"],f_fea["labels"],f_fea["srcip"],f_fea["dstip"],fg4key[1]]) 
        srcportFea=dstportFea
        portcls=dict()
        for port,flows in srcportFea.items():
            if len(flows)<2:
                continue
            cluster=list()
            for flow in flows:
                if not cluster:
                    new_g=[flow]
                    cluster.append(new_g)
                else:                        
                    paired=False
                    for curg_i,cur_g in enumerate(cluster):
                        for cur_f in cur_g:
                            if cur_f[0][0]==flow[0][0] and flow[0][0]!=-1:
                                cluster[curg_i].append(flow)
                                paired=True
                            else:
                                samenum=0
                                for i in range(1,FEANUM):
                                    if cur_f[0][i]==flow[0][i] and flow[0][i]!=-1:
                                        samenum+=1
                                        if samenum>=SAME_DELTA:
                                            cluster[curg_i].append(flow)
                                            paired=True
                                            break
                            if paired:
                                break
                    if not paired:
                        new_g=[flow]
                        cluster.append(new_g)
            if len(cluster)==0:
                continue
            else:
                portcls[port]=cluster
        res[srcip]=portcls 
    saveDataToJson(res,saveFilepath)
    
def getDataPairByCluster(filepath,flowdatapath,saveFilepath):
    data=readDataFromJson(filepath)
    flowdata=getDataFromFlow(flowdatapath)
    data_byPort=dict()
    for ip,ipinfo in data.items():
        for port,clu in ipinfo.items():
            if port not in data_byPort:
                data_byPort[port]=dict()
            data_byPort[port][ip]=clu
    res=dict()
    mostnum=1*10000
    for port,ipinfo in data_byPort.items():
        for ip,cluster in ipinfo.items():
            if len(cluster)<2:
                continue
            for g_i,g in enumerate(cluster):
                for g_comp_i,g_comp in enumerate(cluster):
                    if g_comp_i==g_i:
                        continue
                    if len(g)<2:
                        continue
                    same_items = random.sample(g, 2)
                    samefeas=[flowdata[str((item[3],item[5],item[4],port))]["lens"] for item in same_items]
                    samelabels=[item[2] for item in same_items]
                    dift_items = random.sample(g_comp, 1)
                    diftfeas=[flowdata[str((item[3],item[5],item[4],port))]["lens"] for item in dift_items]
                    diftlabels=[item[2] for item in dift_items]
                    if port not in res:
                        res[port]=list()
                    res[port].append({
                        "act":{
                            "fea":samefeas[0],
                            "label":samelabels[0]
                        },
                        "neg":{
                            "fea":samefeas[1],
                            "label":samelabels[1]
                        },
                        "anc":{
                            "fea":diftfeas[0],
                            "label":diftlabels[0]
                        },
                    })
                    if len(res[port])>=mostnum:
                        break
                if port not in res or len(res[port])>=mostnum:
                    break
            if port not in res or  len(res[port])>=mostnum:
                break
    saveDataToJson(res,saveFilepath)
                    
def clusterFlow(featuredata):
    X=[item["feas"] for item in featuredata]
    Y=[item["label"] for item in featuredata]
    res=KMeans(n_clusters=100).fit_predict(X)
    res_labels=dict()
    for cls_i,item in enumerate(res):
        if item not in res_labels:
            res_labels[item]=list()
        res_labels[item].append(Y[cls_i])   
    info=dict()
    for _,g in res_labels.items():
        info[len(g)]=set(g)    
    a1 = sorted(info.items(),key = lambda x:x[0],reverse = True)
    for k,v in a1:
        print(k,v)
        
def scanClusterIpByBehaver(flowdatapath):
    flowdata=getDataFromFlow(flowdatapath) 
    ipfeas=dict()
    for flowid,flowinfo in flowdata.items():
        srcip=flowid[0]
        dstport=flowid[3]
        if dstport not in ipfeas:
            ipfeas[dstport]=dict()
        if srcip not in ipfeas[dstport]:
            ipfeas[dstport][srcip]=list()
        ipfeas[dstport][srcip].append( [flowinfo["tss"][0],flowid[2],flowinfo["labels"][0]]) 
    for portnum,feas in ipfeas.items():
        if len(feas)==1:
            continue
        for srcip,fea in feas.items():
            if len(fea)==1:
                continue
            for item_i,item1 in enumerate(fea):
                if item_i==0:
                    continue
                item_j=item_i-1
                if item_j>=len(fea):
                    continue
                item2=fea[item_j]
                ipfeas[portnum][srcip][item_j][0]=item1[0]-item2[0]

def clusterIPByTpy(feafilepath,flowpath):
    WINSIZE=configGlobal["WINSIZE"]
    STEP=int(WINSIZE/2)
    fealen=configGlobal["fealen"]
    classNums=configGlobal["classNums"]
    flowfeadata=readDataFromJson(feafilepath) 
    rawdata=getDataFromPkt(flowpath,True) 
    portfeas=dict()
    for item1,item2 in zip(flowfeadata,rawdata):
        srcip,srcport,dstip,dstport=item2
        feas=item1["feas"]
        tss=item1["tss"]
        label=item1["label"] 
        if dstport not in portfeas:
            portfeas[dstport]=dict()
        if srcip not in portfeas[dstport]:
            portfeas[dstport][srcip]=list()
        line_fea=[srcip,srcport,dstip,dstport,label,feas,tss]
        portfeas[dstport][srcip].append(line_fea)
    for port,portfea in portfeas.items():
        mostTs=-1
        for srcip,srcipfea in portfea.items():
            if len(srcipfea)==1:
                portfeas[port][srcip][0][-1]=0
            else:
                for i in range(len(srcipfea)-1,0,-1):
                    portfeas[port][srcip][i][-1]=srcipfea[i][-1]-srcipfea[i-1][-1]
                    if portfeas[port][srcip][i][-1]>mostTs:
                        mostTs=portfeas[port][srcip][i][-1]
                portfeas[port][srcip][0][-1]=0
        for srcip,srcipfea in portfea.items():
            if len(srcipfea)==1:
                continue
            else:
                for i in range(len(srcipfea)-1,0,-1):
                    portfeas[port][srcip][i][-1]=portfeas[port][srcip][i][-1]/mostTs
    winFeas=dict()
    for port,portfea in portfeas.items():
        if port not in winFeas:
            winFeas[port]=dict()
        for srcip,srcipfea in portfea.items():
            if srcip not in winFeas[port]:
                winFeas[port][srcip]=list()
            if len(srcipfea)<=WINSIZE:
                cur_winfea=[srcipfea]
            else:
                cur_winfea=list()
                for i in range(WINSIZE,len(srcipfea),STEP):
                    cur_winfea.append(srcipfea[i-WINSIZE:i])
            winFeas[port][srcip]=cur_winfea
    import math
    def entropy(data):
        counter=dict(Counter(data))
        res = 0.0
        for _, num in counter.items():
            p = float(num) / len(data)
            res -= p * math.log2(p)
        return res
    allreal=list()
    allpred=list()
    for port,portfea in winFeas.items():
        samplesize=sum([len(item) for _,item in portfea.items()])
        if samplesize<classNums:
            continue
        srcipFeas=list()
        srcipEntropy=list()
        srcipLabels=list()
        port_ipnums=0
        for srcip,srcipWinfea in winFeas[port].items():
            port_ipnums+=len(srcipWinfea)
            for srcipfea in srcipWinfea:
                feasNew=[0]*fealen
                ts=mean([item[-1] for item in srcipfea]) 
                dstips=[item[2] for item in srcipfea] 
                dstips_counter=list(dict(Counter(dstips)).values())
                dstipnum=len(set(dstips)) 
                for item in srcipfea:
                    item=item[-2]
                    for i in range(fealen):
                        feasNew[i]+= pow(item[i],2)
                for item in srcipfea:
                    for i in range(fealen):
                        feasNew[i]=math.sqrt(feasNew[i])/(len(srcipfea)*fealen)
                feasNew.append(ts)
                feasNew.append(50/dstipnum)
                srcipFeas.append(feasNew)
                alllabels=list(set([item[-3] for item in srcipfea]))
                srcipEntropy.append(entropy(dstips_counter))
                srcipLabels.append(alllabels)
        if len(srcipFeas)<classNums:
            continue
        cls_methord=KMeans(n_clusters=classNums)
        y_pred = cls_methord.fit_predict(srcipFeas)
        res=[list() for _ in range(classNums)]
        res_g_fea=[list() for _ in range(classNums)]
        res_g_entropy=[list() for _ in range(classNums)]
        for y_index,y_pred_res in enumerate(y_pred):
            res[y_pred_res].append(srcipLabels[y_index])
            res_g_fea[y_pred_res].append(srcipFeas[y_index])
            res_g_entropy[y_pred_res].append(srcipEntropy[y_index])
        minEnt=100000000
        minIndex=-1
        for g_i,g_entlist in enumerate(res_g_entropy):
            gent=mean(g_entlist)
            if gent<minEnt:
                minEnt=gent
                minIndex=g_i
        predictlabel=list()
        reallabel=list()
        Delta_1=configGlobal["Delta_1"]
        Delta_2=configGlobal["Delta_2"]
        Delta_3=configGlobal["Delta_3"]
        for g_i,g in enumerate(res):
            g_label=[int(item[0]!="BENIGN" and item[0]!="MAL:absent") for item in g]
            reallabel.extend(g_label)
            g_prelabel=list()
            if port_ipnums>len(rawdata)/Delta_2:
                g_prelabel.extend([0]*len(g))
            elif len(g)<Delta_1:
                g_prelabel.extend([0]*len(g))
            elif g_i==minIndex:
                if len(g)<Delta_3:
                    g_prelabel.extend([0]*len(g))
                else:
                    g_prelabel.extend([1]*len(g))
            else:
                g_prelabel.extend([0]*len(g))
            predictlabel.extend(g_prelabel)
        allreal.extend(reallabel)
        allpred.extend(predictlabel)

    return allreal,allpred
    

if __name__ == '__main__':
    name="Patator"
    flowfeaFilepath=f"./testData/FlowNetoutFea{name}.json"
    flowpath=f"./testData/{name}.json"
    all_labels,all_preds=clusterIPByTpy(flowfeaFilepath,flowpath)
    accuracy=accuracy_score(all_labels,all_preds)
    precision=precision_score(all_labels,all_preds)
    recall=recall_score(all_labels,all_preds)
    f1=f1_score(all_labels,all_preds)
    print("Results:")
    print("acc:",accuracy)
    print("pre:",precision)
    print("recall:",recall)
    print("f1:",f1)
        
   