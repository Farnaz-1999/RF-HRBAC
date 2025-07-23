import requests
import time
from dotenv import load_dotenv
import os

load_dotenv()
server_address=os.getenv("SERVER_URL")

def FRBAC_api_test(api_address:str,method:str,msg:str,params:str=""):
    global server_address
    match method:
        case "get":
            start = time.time()
            response = requests.get(url=server_address+api_address+params)
            end = time.time()
            result=end - start
            print(msg,":\n", response," msg: ",response.text,result," s\n\n")
        case "post":
            start = time.time()
            response = requests.post(url=server_address+api_address,data=params)
            end = time.time()
            result=end - start
            print(msg,":\n", response," msg: ",response.text,result," s\n\n")
    return result

def FRBAC_performance_test(n_times:int,api_address:str,method:str,msg:str,params:str=""):
    result=0
    for i in range(n_times):
        result+=FRBAC_api_test(api_address,method,msg,params)
    print("avg time for ", n_times, "query in ", msg, "method is", result/n_times)