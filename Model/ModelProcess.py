from Model.Dataset import FlowDataset
from Model.Network import Net
import torch
from numpy import mean
import torch.nn as nn

from utils.FileUtils import readConfig, saveDataToJson
configGlobal=readConfig('../testData/config.yml')
def train(feadatafilepath,name):
    device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
    net=Net()
    net=net.to(device)
    dataset=FlowDataset(feadatafilepath)
    from torch.utils.data import DataLoader
    dataloader = DataLoader(dataset, batch_size=64, shuffle=True,drop_last=True)
    learn_lr=configGlobal["learn_lr"]
    adam=torch.optim.Adam(net.parameters(),lr=learn_lr)
    triplet_loss = nn.TripletMarginLoss(margin=1.0, p=2, eps=1e-7)
    epochnums=configGlobal["epochnums"]
    train_step=configGlobal["train_step"]
    minloss=configGlobal["minloss"]
    net.train()
    from torch.utils.tensorboard import SummaryWriter
    writer = SummaryWriter('runs/train')
    for epoch in range(epochnums):
        losslist=list()
        for data in dataloader:
            data=data.to(device)
            out_act,out_neg,out_anc=net(data[:,0,:],data[:,1,:],data[:,2,:])
            loss=triplet_loss(out_act,out_neg,out_anc)
            if loss<minloss:
                minloss=loss
                torch.save(net,"./flownet"+name+".pt")
            losslist.append(loss.cpu().detach().numpy())
            adam.zero_grad()
            loss.backward()
            adam.step()
            train_step+=1
        writer.add_scalar("Loss/Train",mean(losslist),epoch)
    writer.close()
    
    
def predict(logdata,saveFilepath,name):
    device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
    net=torch.load("./flownet"+name+".pt")
    net.eval()
    res=list()
    step=0
    for flowid,flowinfo in logdata.items():
        flowid=eval(flowid)
        step+=1
        lens=flowinfo["lens"]
        labels=flowinfo["labels"]
        ts=flowinfo["tss"][0]
        if len(lens)<127:
            feas_input=lens+[-1]*(127-len(lens))
        else:
            feas_input=lens[:127]
        feas_input.insert(0, int(flowid[3]))
        feas_input=torch.Tensor([feas_input]).to(device)
        feas=net.forward_once(feas_input).cpu().detach().numpy().tolist()[0]
        if len(set(labels))==1 and "BENIGN" in labels:
            label_select="BENIGN"
        else:
            label_select="MAL:"+labels[0]
        res.append({
            "feas":feas,
            "tss":ts,
            "label":label_select
        })
    saveDataToJson(res,saveFilepath)
            