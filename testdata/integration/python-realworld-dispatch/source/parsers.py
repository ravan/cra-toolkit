import yaml


class YamlParser:
    def parse(self, data):
        return yaml.safe_load(data)
