from collections import Counter
import ipaddress
import networkx as nx
import numpy as np
import pandas
from sklearn.decomposition import PCA
import matplotlib.pyplot as plt

from Detect import getDataFromPkt
from utils.FileUtils import readDataFromJson
plt.rcParams['font.sans-serif'] = ['Microsoft YaHei']


def drawTraffic(filepath,labeled):
    trafficData=readDataFromJson(filepath)
    import networkx as nx
    G=nx.Graph()
    labeltotal=set()
    for _,v in trafficData.items():
        for f in v:
            srcip=f["srcip"]
            dstip=f["dstip"]
            if labeled:
                label=f['label'][0]
                labeltotal.add(label)
                if label=="BENIGN" or label=="absent":
                    G.add_node(srcip)
                    G.add_node(dstip)
                    G.add_edge(srcip,dstip,color="blue")
                else:
                    G.add_node(srcip,name=srcip)
                    G.add_node(dstip,node_color='red',name=dstip)
                    G.add_edge(srcip,dstip,color='red',name=label)
    pos = nx.kamada_kawai_layout(G)
    nx.draw(G, pos,node_size=100,edge_color=[G[u][v]['color'] for u, v in G.edges])
    node_labels = nx.get_node_attributes(G, 'name')
    nx.draw_networkx_labels(G, pos, labels=node_labels,font_size=8)
    edge_labels = nx.get_edge_attributes(G, 'name')
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels)
    plt.show()

def drawFlow(filepath,day):
    trafficData=getDataFromPkt(filepath)
    feas=dict()
    for flowid,flowfea in trafficData.items():
        if len(flowfea["lens"])<32:
            flowfea["lens"].extend([-1]*(32-len(flowfea["lens"])))
        else:
            flowfea["lens"]=flowfea["lens"][:32]
        
        feas[flowid]=[flowfea["lens"],flowfea["labels"][0]]
    pca=PCA(n_components=2)
    pure_feas=list()
    labels=list()
    for _,v in feas.items():
        pure_feas.append(v[0])
        labels.append(v[1])
    pure_feas=pca.fit_transform(pure_feas)
    pure_feas_white=list()
    pure_feas_black=list()
    for fea,label in zip(pure_feas,labels):
        if label=='BENIGN':
            pure_feas_white.append(fea)
        else:
            pure_feas_black.append(fea)
    pure_feas_white=np.array(pure_feas_white)
    pure_feas_black=np.array(pure_feas_black)
    s1=plt.scatter(pure_feas_white[:,0],pure_feas_white[:,1],s=0.001,c='g')
    s2=plt.scatter(pure_feas_black[:,0],pure_feas_black[:,1],s=0.001,c='r')
    l1 = plt.scatter([], [], s=5, c='g')
    l2 = plt.scatter([], [], s=5, c='r')
    plt.legend((l1,l2),("Benign","Malicious"),loc='best')
    plt.savefig("./"+day+".png",dpi=600)

def drawIpId(filepath,day):
    trafficData=readDataFromJson(filepath)
    feas=dict()
    for _,ipfea in trafficData.items():
        for item in ipfea:
            flowids=(item["srcip"],item["srcport"],item["dstip"],item["dstport"],)
            feas[flowids]=[item["dstportfea"],item["label"]]
    pca=PCA(n_components=2)
    pure_feas=list()
    labels=list()
    for _,v in feas.items():
        pure_feas.append(list(v[0].values())[:5])
        labels.append(v[1][0])
    pure_feas=pca.fit_transform(pure_feas)
    pure_feas_white=list()
    pure_feas_black=list()
    for fea,label in zip(pure_feas,labels):
        if label=='BENIGN':
            pure_feas_white.append(fea)
        else:
            pure_feas_black.append(fea)
    pure_feas_white=np.array(pure_feas_white)
    pure_feas_black=np.array(pure_feas_black)
    s1=plt.scatter(pure_feas_white[:,0],pure_feas_white[:,1],s=0.001,c='g')
    s2=plt.scatter(pure_feas_black[:,0],pure_feas_black[:,1],s=0.001,c='r')
    l1 = plt.scatter([], [], s=5, c='g')
    l2 = plt.scatter([], [], s=5, c='r')
    plt.legend((l1,l2),("Benign","Malicious"),loc='best')
    plt.savefig("./ipid"+day+".png",dpi=600)
    
def drawTrainLoss(filepath):
    data=pandas.read_csv(filepath).values
    plt.plot(data[:,1], data[:,-1],c="b")
    plt.xlabel("step")
    plt.ylabel("Loss")
    plt.vlines(10, 0, 0.4, colors = "r", linestyles = "dashed")
    plt.savefig("loss.png",dpi=600)    

def drawFlowLenOutFeas(filepath,day):
    data=readDataFromJson(filepath)
    pca=PCA(n_components=2)
    pure_feas=list()
    labels=list()
    for flowinfo in data:
        pure_feas.append(flowinfo["feas"])
        labels.append(flowinfo["label"])
    pure_feas=pca.fit_transform(pure_feas)
    pure_feas_white=list()
    pure_feas_black=list()
    for fea,label in zip(pure_feas,labels):
        if label=='BENIGN':
            pure_feas_white.append(fea)
        else:
            pure_feas_black.append(fea)
    pure_feas_white=np.array(pure_feas_white)
    pure_feas_black=np.array(pure_feas_black)
    s1=plt.scatter(pure_feas_white[:,0],pure_feas_white[:,1],s=0.001,c='g')
    s2=plt.scatter(pure_feas_black[:,0],pure_feas_black[:,1],s=0.001,c='r')
    l1 = plt.scatter([], [], s=5, c='g')
    l2 = plt.scatter([], [], s=5, c='r')
    plt.legend((l1,l2),("Benign","Malicious"),loc='best')
    plt.savefig("./FlowFeaOut"+day+".png",dpi=600)
 
def drawClusterIPByTpy(feafilepath,flowpath):
    WINSIZE=32
    STEP=16
    fealen=16
    classNums=8
    mostGDelta=63 
    flowfeadata=readDataFromJson(feafilepath) 
    rawdata=getDataFromPkt(flowpath)
    portfeas=dict()
    for item1,item2 in zip(flowfeadata,rawdata):
        srcip,srcport,dstip,dstport=item2
        feas=item1["feas"]
        tss=item1["tss"]
        label=item1["label"]
        if label=="MAL:PortScan":
            continue
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
    for port,portfea in winFeas.items():
        if port!=21:
            continue
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
                ts=np.mean([item[-1] for item in srcipfea])
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
                feasNew.append(1/dstipnum)
                srcipFeas.append(feasNew)
                alllabels=list(set([item[-3] for item in srcipfea]))
                srcipEntropy.append(entropy(dstips_counter))
                srcipLabels.append(alllabels)
        srcipLabels=[item[0] for item in srcipLabels]
        if len(set(srcipLabels))==1:
            continue
        pca=PCA(n_components=2)
        pure_feas=srcipFeas
        labels=srcipLabels
        pure_feas=pca.fit_transform(pure_feas)
        pure_feas_white=list()
        pure_feas_black=list()
        for fea,label in zip(pure_feas,labels):
            if label=='BENIGN':
                pure_feas_white.append(fea)
            else:
                pure_feas_black.append(fea)
        pure_feas_white=np.array(pure_feas_white)
        pure_feas_black=np.array(pure_feas_black)
        s1=plt.scatter(pure_feas_white[:,0],pure_feas_white[:,1],s=1,c='g')
        s2=plt.scatter(pure_feas_black[:,0],pure_feas_black[:,1],s=1,c='r')
        l1 = plt.scatter([], [], s=5, c='g')
        l2 = plt.scatter([], [], s=5, c='r')
        plt.legend((l1,l2),("Benign","Malicious"),loc='best')
        save_filepath="ResTuesday.png"
        plt.savefig(save_filepath,dpi=600)
        
    
    
    
   