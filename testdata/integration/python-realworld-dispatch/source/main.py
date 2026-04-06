import yaml

if __name__ == "__main__":
    data = open("data.yml").read()
    result = yaml.load(data)
    print(result)
