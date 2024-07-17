import json
import yaml

def saveDataToJson(data, filepath):
    with open(filepath, "w", encoding="utf8") as f:
        json.dump(data, f, ensure_ascii=False)

def readDataFromJson(filepath):
    with open(filepath, "r", encoding="utf8") as f:
        data = json.load(f)
    return data  

def readConfig(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        file_content = f.read()
    content = yaml.load(file_content, yaml.FullLoader)
    return content