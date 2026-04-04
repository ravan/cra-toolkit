import yaml

def process_config(path):
    with open(path) as f:
        data = yaml.load(f)
    return data

def validate_config(data):
    return "key" in data
