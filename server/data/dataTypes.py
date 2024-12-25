from pydantic import BaseModel

class relData(BaseModel):
    UserName:str
    targetUserName:str
    role:str
    passw:str
    relRole:str
    relUserName:str

class ACderive_Data(BaseModel):  
    UserName:str
    targetUserName:str
    role:str
    passw:str
    relRole:str
    relUserName:str
    dataType:str
    newPrivilege:int
    R4SR:list
    R4SW:list
    C4R:list
