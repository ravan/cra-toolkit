import yaml


def main():
    with open("config.yml") as f:
        config = yaml.safe_load(f)
    print(config)


if __name__ == "__main__":
    main()
