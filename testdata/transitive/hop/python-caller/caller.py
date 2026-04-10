import urllib3

def outer_func():
    return urllib3.PoolManager()

def unrelated_func():
    return "hello"
