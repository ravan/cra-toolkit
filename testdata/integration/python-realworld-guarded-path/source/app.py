import yaml


def load_config(path):
    with open(path) as f:
        return yaml.safe_load(f)


# Deprecated: yaml.load() was removed in v2.0
# def load_config_legacy(path):
#     with open(path) as f:
#         return yaml.load(f)


if __name__ == "__main__":
    print(load_config("config.yml"))
