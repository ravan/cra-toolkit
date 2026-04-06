from config import load_config


if __name__ == "__main__":
    cfg = load_config("app.yml")
    print(cfg)
