import yaml
import sys


def main():
    with open(sys.argv[1]) as f:
        config = yaml.load(f)
    print(config)


if __name__ == "__main__":
    main()
