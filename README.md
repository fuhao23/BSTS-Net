# BSTS-Net
Code and models from the paper "A Fingerprint-Based Method for Malicious Traffic Detection"

# Dependencies
pip install -r requirements.txt

# Usage
Due to the large size of dataset, in order to demonstrate the effectiveness of the model, we provide intermediate features extrcted from the patator attack. You need to unzip testData and run it.\
`python detect.py`


# Zeek install
Please visit the [zeek](https://github.com/zeek/zeek) website and follow the [tutorial](https://docs.zeek.org/en/master/install.html#building-from-source) for installation. Note: Our script extracts rich application layer protocol information, so please install version 7.0 and above!
#### Log extraction
`zeek -Cr filename.pcap AllFeas.zeek`

# Label flow
Traffic logs need to be labeled, and we provide code for tagging the CICIDS2017 dataset : LabelDataset.py

# Train custom models
Firstly, you need to use zeek to extract the traffic features, and then train the model.
#### traffic fingerprints extract
Run function `classFlowAndSave`
#### assign fingerprints ID
Run function `assignIpIDAndSave`
#### Sample grouping based on fingerprints
Run function `clusterFlowById`
#### construct dataset for SSN
Run function `getDataPairByCluster`
#### Train SNN
Run function `train`
The below image shows the change of training loss with epoch.\
<img src="https://github.com/fuhao23/BSTS-Net/blob/main/loss.png" width="400px">
#### Use the model to calculate sample embeddings
Run function `predict`
Distributionson the partial validation sets:\
<img src="https://github.com/fuhao23/BSTS-Net/blob/main/data%20distribution.png" width="400px">
#### Malicious Traffic Detection
Run function `clusterIPByTpy` 
Performance on the validation set:\
![image](https://github.com/user-attachments/assets/966f1f97-dab3-4ecc-8422-6a290cd72d3e)





