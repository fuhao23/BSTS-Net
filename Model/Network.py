import torch.nn as nn
import torch


class Net(nn.Module):
    def __init__(self) -> None:
        super(Net,self).__init__()
        self.relu=nn.ReLU()
        self.ln1=nn.Linear(128,64)    
        self.ln2=nn.Linear(64,32)  
        self.ln3=nn.Linear(32,16)  
        self.batchnorm1=nn.BatchNorm1d(64)
        self.batchnorm2=nn.BatchNorm1d(32)
        self.dropout=nn.Dropout(0.2)     
    def forward_once(self,x):
        x=self.ln1(x)
        x=self.batchnorm1(x)
        x=self.relu(x)
        x=self.dropout(x)
        x=self.ln2(x)
        x=self.batchnorm2(x)
        x=self.relu(x)
        x=self.dropout(x)
        x=self.ln3(x)
        x=torch.sigmoid(x)
        return x
    def forward(self,x1,x2,anchor):
        x1=self.forward_once(x1)
        x2=self.forward_once(x2)
        anchor=self.forward_once(anchor)
        return x1,x2,anchor