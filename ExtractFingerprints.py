from Detect import getSameFeas
from ExtractFingerprints_extend import analusisByPort, classifyFlowByFingerPoint
from FingerprintsFeature import getFlowCyclicalFingerprints, getFlowDuplicateFingerprints, getFlowSameFingerprints
from PcapProcess import getDataFromFlow, getDataFromPkt
from utils.DataUtils import getInfoByFlowid, splitDataByIp
from utils.FileUtils import readDataFromJson, saveDataToJson
from utils.StatisticalUtils import calTimeGaps, getDataByBiDirs, getDataBySegIndex, getSegByDirs
 

def getIpFlowLenFingers(data):
    datalen=len(data)
    if datalen==1:
        return data
    figs=list()
    for d_i in range(datalen):
        bestCommonNum=-1
        bestSegs=None
        for d_j in range(datalen):
            if d_j==d_i: 
                continue
            fi=data[d_i] 
            fj=data[d_j] 
            commonNums=0
            commonSegs=list()
            for s_i in range(len(fi)): 
                s_j=s_i 
                if s_j>=len(fj): 
                    break
                segi=fi[s_i] 
                segj=fj[s_j] 
                if segi==segj:
                    commonNums+=len(segi)
                    commonSegs.append(segi)
                    continue
                if abs(sum(segi)-sum(segj))<=1: 
                    commonNums+=len(segi)
                    commonSegs.append(segi)
                    continue
                segs_ci=list() 
                for item in segi: 
                    if item in segj: 
                        segs_ci.append(item)
                        commonNums+=1
                    elif s_j+2<len(fj) and item in fj[s_j+2]: 
                        segs_ci.append(item)
                        commonNums+=1
                    else:
                        segs_ci.append(-1)
                commonSegs.append(segs_ci)
            if commonNums>bestCommonNum:
                bestCommonNum=commonNums
                bestSegs=commonSegs
        figs.append(bestSegs)
    return figs         
            
     
def getIpFlowPktFingers(data):
    datalen=len(data)
    if datalen==1: 
        return {
            True:[data[0][True]],
            False:[data[0][False]],
        }
    truedata=[item[True] for item in data]
    falsedata=[item[False] for item in data]
    figbi={
        True:None,
        False:None
    }
    data=truedata
    figs=list()
    for d_i in range(datalen):
        bestCommonNum=0
        bestSegs=None
        fi=data[d_i] 
        for d_j in range(datalen):
            if d_j==d_i: 
                continue
            fj=data[d_j] 
            commonNums=0
            commonSegs=dict()
            for i_pktlen,i_num in fi.items(): 
                if i_pktlen in fj:
                    if i_num>fj[i_pktlen]:
                        commonNums+=fj[i_pktlen]
                        commonSegs[i_pktlen]=fj[i_pktlen]
                    else:
                        commonNums+=i_num
                        commonSegs[i_pktlen]=i_num
            if commonNums>bestCommonNum:
                bestCommonNum=commonNums
                bestSegs=commonSegs
        if bestCommonNum>0:
            figs.append(bestSegs)
        else:
            figs.append(fi)
    figbi[True]=figs
    data=falsedata
    figs=list()
    for d_i in range(datalen):
        bestCommonNum=0
        bestSegs=None
        for d_j in range(datalen): 
            if d_j==d_i: 
                continue
            fi=data[d_i]
            fj=data[d_j] 
            commonNums=0
            commonSegs=dict()
            for i_pktlen,i_num in fi.items(): 
                if i_pktlen in fj:
                    if i_num>fj[i_pktlen]:
                        commonNums+=fj[i_pktlen]
                        commonSegs[i_pktlen]=fj[i_pktlen]
                    else:
                        commonNums+=i_num
                        commonSegs[i_pktlen]=i_num
            if commonNums>bestCommonNum:
                bestCommonNum=commonNums
                bestSegs=commonSegs
        if bestCommonNum>0:
            figs.append(bestSegs)
        else:
            figs.append(fi)
    figbi[False]=figs
    return figbi   

def scanData(feas):    
    for fid,fdata in feas.items():
        print("-----------------------------------")
        print(fid)
        print(fdata["lens"][:50])
        print("-----------------------------------")

def splitFlowByBiPort(feas):
    res=dict()
    for fid,fdata in feas.items():
        f_srcport=fid[1]
        f_dstport=fid[3]
        for port in [f_srcport,f_dstport]:
            if port not in res:
                res[port]=dict()
            res[port][fid]=fdata
    return res
    
def analysisByPort(data):
    ipdatas=splitDataByIp(data)
    flowFeas=dict()
    for ipid,ipdata in ipdatas.items():                
        iplensegs=list()
        iplensegs1=list()
        iplenFIds=list()
        for fid,fdata in ipdata:
            new_f_id=(ipid[0],fid[0],ipid[1],fid[1]) 
            flowFeas[new_f_id]=dict() 
            fdata_pktlens=fdata["lens"]
            fdata_tss=fdata["tss"]
            fdata_tss_gaps=calTimeGaps(fdata_tss)
            fdata_tss_gaps=[int(item) if item>0 else 0 for item in fdata_tss_gaps]
            fdata_dirs=fdata["dirs"] 
            pktlen,nums=getFlowSameFingerprints(fdata_pktlens)
            if nums!=-1:
                flowFeas[new_f_id]["pktlenfea_allsame"]={pktlen:nums}
                continue
            fdata_lensegs=getDataBySegIndex(fdata_pktlens,getSegByDirs(fdata_dirs)) 
            iplensegs.append(getDataByBiDirs(fdata_pktlens,fdata_dirs)) 
            iplensegs1.append(fdata_lensegs) 
            iplenFIds.append(new_f_id) 
            flowFeas[new_f_id]["pktlenfea_repeatSegs"]=getFlowCyclicalFingerprints(fdata_lensegs)
            flowFeas[new_f_id]["pktlenfea_circleSegs"]=getFlowDuplicateFingerprints(fdata_lensegs)
        ipPktsFings=getIpFlowPktFingers(iplensegs)
        ipSegsFings=getIpFlowLenFingers(iplensegs1)
        for f_i,fid in enumerate(iplenFIds):
            flowFeas[fid]["pktlenfea_pktfootpoints"]={
                True:ipPktsFings[True][f_i],
                False:ipPktsFings[False][f_i],
            }
            flowFeas[fid]["pktlenfea_footpoints"]=ipSegsFings[f_i]
    return flowFeas

def classifyFlowByFingerprint(feas,alldata):
    pktlensameDict=dict()
    pktlenfingerponitDict=dict()
    pktlenpktfingerponitDict=dict()
    pktlenMaxRepeatDict=dict()
    pktlenCircleDict=dict()
    for fid,f_fing in feas.items():
        if "pktlenfea_allsame" in f_fing:
            pktsamelen=list(f_fing["pktlenfea_allsame"].keys())[0]
            if pktsamelen not in pktlensameDict:
                pktlensameDict[pktsamelen]=dict()
            pktlensameDict[pktsamelen][fid]=[item.split("name0(")[-1].split(")")[0] for item in getInfoByFlowid(alldata,fid) if item!="" and "name0" in item]
            continue
        if "pktlenfea_footpoints" in f_fing:
            pktfingerpoints=f_fing["pktlenfea_footpoints"]
            pktfingerpointsNew=list()
            for item in pktfingerpoints:
                pktfingerpointsNew.append(tuple(item))
            pktfingerpoints=tuple(pktfingerpointsNew)
            if not pktlenfingerponitDict:
                pktlenfingerponitDict[pktfingerpoints]=dict()
                pktlenfingerponitDict[pktfingerpoints][fid]=[item.split("name0(")[-1].split(")")[0] for item in getInfoByFlowid(alldata,fid) if item!="" and "name0" in item]
            else:
                pairAdded=False
                for gfing,_ in pktlenfingerponitDict.items():
                    hasPaired=True
                    for g_i,g_finp in enumerate(gfing):
                        f_i=g_i 
                        if f_i>=len(pktfingerpoints):
                            hasPaired=False
                            break
                        f_data=pktfingerpoints[f_i] 
                        if g_finp!=f_data:
                            if sum(g_finp)!=sum(f_data):
                                for s_pkt in g_finp:
                                    if s_pkt==-1:
                                        continue
                                    if s_pkt not in f_data:
                                        if f_i+2>=len(pktfingerpoints):
                                            hasPaired=False
                                            break
                                        if s_pkt not in pktfingerpoints[f_i+2]:
                                            hasPaired=False
                                            break
                    if hasPaired:
                        pairAdded=True
                        pktlenfingerponitDict[gfing][fid]=[item.split("name0(")[-1].split(")")[0] for item in getInfoByFlowid(alldata,fid) if item!="" and "name0" in item]
                        
                if not pairAdded:
                    pktlenfingerponitDict[pktfingerpoints]=dict()
                    pktlenfingerponitDict[pktfingerpoints][fid]=[item.split("name0(")[-1].split(")")[0] for item in getInfoByFlowid(alldata,fid) if item!="" and "name0" in item]
        if "pktlenfea_pktfootpoints" in f_fing:
            pktfingerpoints=f_fing["pktlenfea_pktfootpoints"]
            trueFing=tuple((k,v) for k,v in f_fing["pktlenfea_pktfootpoints"][True].items())
            falseFing=tuple((k,v) for k,v in f_fing["pktlenfea_pktfootpoints"][False].items())
            pktfingerpoints=(trueFing,falseFing)
            if not pktlenpktfingerponitDict:
                pktlenpktfingerponitDict[pktfingerpoints]=dict()
                pktlenpktfingerponitDict[pktfingerpoints][fid]=[item.split("name0(")[-1].split(")")[0] for item in getInfoByFlowid(alldata,fid) if item!="" and "name0" in item]
            else:
                hasPaired=False
                for gfing,_ in pktlenpktfingerponitDict.items():
                    g_true_fing=[item[0] for item in gfing[0]]
                    g_false_fing=[item[0] for item in gfing[1]]
                    cur_true_fing=[item[0] for item in pktfingerpoints[0]]
                    cur_false_fing=[item[0] for item in pktfingerpoints[1]]
                    truePaired=True
                    for item in cur_true_fing:
                        if item not in g_true_fing:
                            truePaired=False
                            break
                    if not truePaired:
                        falsePaired=True
                        for item in cur_false_fing:
                            if item not in g_false_fing:
                                falsePaired=False
                                break
                        if falsePaired:
                            hasPaired=True
                            pktlenpktfingerponitDict[gfing][fid]=[item.split("name0(")[-1].split(")")[0] for item in getInfoByFlowid(alldata,fid) if item!="" and "name0" in item]
                            break
                    else:
                        hasPaired=True
                        pktlenpktfingerponitDict[gfing][fid]=[item.split("name0(")[-1].split(")")[0] for item in getInfoByFlowid(alldata,fid) if item!="" and "name0" in item]
                        break
                if not hasPaired:
                    pktlenpktfingerponitDict[pktfingerpoints]=dict()
                    pktlenpktfingerponitDict[pktfingerpoints][fid]=[item.split("name0(")[-1].split(")")[0] for item in getInfoByFlowid(alldata,fid) if item!="" and "name0" in item]
        if "pktlenfea_repeatSegs" in f_fing:
            pktreapeats=f_fing["pktlenfea_repeatSegs"]
            if pktreapeats:
                validKeys=list()
                for lens,num in pktreapeats.items():
                    if num<3:
                        continue
                    validKeys.append(lens)
                validKeys=tuple(validKeys)       
                if validKeys not in pktlenMaxRepeatDict:
                    pktlenMaxRepeatDict[validKeys]=dict()
                pktlenMaxRepeatDict[validKeys][fid]=[item for item in getInfoByFlowid(alldata,fid) if item!=""]
        if "pktlenfea_circleSegs"  in f_fing and f_fing["pktlenfea_circleSegs"]:
            pktcirs=f_fing["pktlenfea_circleSegs"]
            if pktcirs: 
                for item in pktcirs.keys():
                    itemReversed=tuple(reversed(item))
                    if item not in pktlenCircleDict and itemReversed not in pktlenCircleDict:
                        pktlenCircleDict[item]=dict()
                    if item in pktlenCircleDict:
                        pktlenCircleDict[item][fid]=[item for item in getInfoByFlowid(alldata,fid) if item!=""]
                    elif itemReversed in pktlenCircleDict:
                        pktlenCircleDict[itemReversed][fid]=[item for item in getInfoByFlowid(alldata,fid) if item!=""]
    pktlensameClsIDs=dict()
    Curid=0
    for _,data in pktlensameDict.items():
        for fid,_ in data.items():
            pktlensameClsIDs[fid]=Curid
        Curid+=1
    pktlenFingerClsIDs=dict()
    Curid=0
    for _,data in pktlenpktfingerponitDict.items():
        for fid,_ in data.items():
            pktlenFingerClsIDs[fid]=Curid
        Curid+=1
    pktlensegFingerClsIDs=dict()
    Curid=0
    for _,data in pktlenfingerponitDict.items():
        for fid,_ in data.items():
            pktlensegFingerClsIDs[fid]=Curid
        Curid+=1
    pktlenSameFlowClsIDs=dict()
    Curid=0
    for _,data in pktlenMaxRepeatDict.items():
        for fid,_ in data.items():
            pktlenSameFlowClsIDs[fid]=Curid
        Curid+=1
    pktlenCircleFlowClsIDs=dict()
    Curid=0
    for _,data in pktlenCircleDict.items():
        for fid,_ in data.items():
            pktlenCircleFlowClsIDs[fid]=Curid
        Curid+=1
    resID=dict()
    for fid in feas.keys():
        resID[fid]={
            "sameLenID":-1,
            "fingerID":-1,
            "segfingerID":-1,
            "repeatSegID":-1,
            "circleSegID":-1
        }
        if fid in pktlensameClsIDs:
            resID[fid]["sameLenID"]=pktlensameClsIDs[fid]
        if fid in pktlenFingerClsIDs:
            resID[fid]["fingerID"]=pktlenFingerClsIDs[fid]
        if fid in pktlensegFingerClsIDs:
            resID[fid]["segfingerID"]=pktlensegFingerClsIDs[fid]
        if fid in pktlenSameFlowClsIDs:
            resID[fid]["repeatSegID"]=pktlenSameFlowClsIDs[fid]
        if fid in pktlenCircleFlowClsIDs:
            resID[fid]["circleSegID"]=pktlenCircleFlowClsIDs[fid]
        resID[fid]["infos"]=[item for item in getInfoByFlowid(alldata,fid) if item!=""]
    return resID
            
def analysisAllPort(feas,alldata):
    res=dict()
    step=0
    for port,data in feas.items():
        step+=1
        flowFea=analusisByPort(data)
        resID=classifyFlowByFingerPoint(flowFea,alldata)
        res[port]=resID
    return res
    
def classFlowAndSave(filepath,marked=False):
    data=getDataFromPkt(filepath,marked)
    portGFeas=splitFlowByBiPort(data)
    res=analysisAllPort(portGFeas,data)
    saveres=dict()
    for port,pdata in res.items():
        saveres[port]=dict()
        for key,v in pdata.items():
            saveres[port][str(key)]=v
    filename=filepath.split("/")[-1].split(".")[0]
    saveDataToJson(saveres,"./"+filename+"_flowid.json")
    
def assignIpIDAndSave(idfilepath,flowfilepath):
    iddata=readDataFromJson(idfilepath)
    flowdata=getDataFromFlow(flowfilepath)
    ipClsIds=dict()
    for fid,fdata in flowdata.items():
        srcip,srcport,dstip,dstport=fid
        if srcip not in ipClsIds:
            ipClsIds[srcip]=list()
        if dstip not in ipClsIds:
            ipClsIds[dstip]=list()
        feas={
            "srcportfea":iddata[str(srcport)][str(fid)],
            "srcport":srcport,
            "dstportfea":iddata[str(dstport)][str(fid)],
            "dstport":dstport,
            "srcip":srcip,
            "dstip":dstip,
            "label":fdata["labels"]
        }
        ipClsIds[srcip].append(feas)
        ipClsIds[dstip].append(feas)
    saveDataToJson(ipClsIds,"ipid_"+idfilepath.split("/")[-1].split(".")[0]+".json")
    
def splitIdsByStepGroup(data,winsize,step):
    return [data[i-winsize:i] for i in range(winsize,len(data),step)]

def judgeSimilarityBetweenIds(ids1,ids2):
    idslen=len(ids1)-2
    if ids1[-2]==ids2[-2]:
        return True if sum([ ids1[i]==ids2[i]!=-1 for i in range(int(idslen/2))  ])>0 else False
    if ids1[-1]==ids2[-1]:
        return True if sum([ ids1[i]==ids2[i]!=-1 for i in range(int(idslen/2),idslen)   ])>0 else False
    return "error"
    
def judgeSimilarityBetweenGroups(g1,g2):
    totalSimNum=0
    for flowIds1 in g1:
        for flowIds2 in g2:
            portSim=flowIds1[-3]==flowIds2[-3] or flowIds1[-2]==flowIds2[-2]
            if not portSim:
                continue
            if judgeSimilarityBetweenIds(flowIds1[:-1],flowIds2[:-1]):
                totalSimNum+=1
    return totalSimNum
    
if __name__ == '__main__':
    for filename in ["Monday","Tuesday","Wednesday","Thursday","Friday"]:
        zeeklogpath="dataset/cicds2017/zeekMarkedLog/"+filename+".json"
        labeled=True
        classFlowAndSave(zeeklogpath,labeled)
        flowidpath= zeeklogpath.split("/")[-1].split(".")[0]+"_flowid.json" 
        assignIpIDAndSave(flowidpath,zeeklogpath,marked=labeled)
