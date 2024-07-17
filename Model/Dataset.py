from typing import Any
import torch
from torch.utils.data import Dataset

from utils.FileUtils import readDataFromJson
class FlowDataset(Dataset):
    def __init__(self,featureFilename) -> None:
        super().__init__()
        feaData=readDataFromJson(featureFilename)
        self.data=list()
        for port,feadata in feaData.items():
            for line in feadata:
                line_fea=[
                    line["act"]["fea"],
                    line["neg"]["fea"],
                    line["anc"]["fea"],
                ]
                for i,item in enumerate(line_fea):
                    if len(item)<127:
                        line_fea[i]=item+[-1]*(127-len(item))
                    else:
                        line_fea[i]=item[:127]
                    line_fea[i].insert(0,int(port))
                self.data.append(line_fea)
        self.data=torch.Tensor(self.data)
    def __getitem__(self, index) -> Any:
        return self.data[index]
    def __len__(self):
        return len(self.data)