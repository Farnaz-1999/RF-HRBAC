import requests
import time
from dotenv import load_dotenv
import os

load_dotenv()
server_url=os.getenv("SERVER_URL")
methods={1:"get",2:"post"}

def FRBAC_test(relative_url,method,msg,params=None):
    global server_url
    match method:
        case "get":
            start = time.time()
            response = requests.get(url=server_url+relative_url+params)
            end = time.time()
            print(type(response))
            print(msg,":\n", response," msg: ",response.text,end - start," s\n\n")
        case "post":
            start = time.time()
            response = requests.post(url=server_url+relative_url,data=params)
            end = time.time()
            print(msg,":\n", response," msg: ",response.text,end - start," s\n\n")
