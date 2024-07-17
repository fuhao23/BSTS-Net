# BSTS-Net
Code and models from the paper "A Fingerprint-Based Method for Malicious Traffic Detection"

### Dependencies
pip install -r requirements.txt

### Usage
`#` Due to the large size of dataset, in order to demonstrate the effectiveness of the model, we provide intermediate features extrcted from the patator attack. You need to unzip testData and run it.
python detect.py

### Train custom models
## Firstly, you need to use zeek to extract the traffic features, and then train the model.
# Zeek install
Please visit the zeek website[https://github.com/zeek/zeek] and follow the tutorial for installation. Note: Our script extracts rich application layer protocol information, so please install version 7.0 and above!
`#` Log extraction.
zeek -Cr filename.pcap AllFeas.zeek

# Label flow
Traffic logs need to be tagged, and we provide code for tagging the CICIDS2017 dataset : LabelDataset.py

# Model Trainning
`#` traffic fingerprints extract
Run function `classFlowAndSave`
`#` assign fingerprints ID
Run function `assignIpIDAndSave`
`#` Sample grouping based on fingerprints
Run function `clusterFlowById`
`#` construct dataset for SSN
Run function `getDataPairByCluster`
`#` Train SNN
Run function `train`
`#` Use the model to calculate sample embeddings
Run function `predict`
`#` Malicious Traffic Detection
Run function `clusterIPByTpy`
