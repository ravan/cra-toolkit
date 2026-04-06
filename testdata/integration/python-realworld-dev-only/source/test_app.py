import yaml


def test_legacy_format():
    data = yaml.load("key: value")
    assert data == {"key": "value"}
