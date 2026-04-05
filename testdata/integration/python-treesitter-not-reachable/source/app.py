import yaml

def process():
    data = yaml.safe_load("key: value")
    return data

if __name__ == "__main__":
    print(process())
