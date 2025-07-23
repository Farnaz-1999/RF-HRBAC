from pydantic import BaseModel

class fetchData(BaseModel):
    UserName:str
    role:str
    passw:str

class fetchRelData(BaseModel):
    UserName:str
    role:str
    passw:str
    relUserName:str

class fetchOtherData(BaseModel):
    UserName:str
    role:str
    passw:str
    targetUserName:str
    targetRole:str
    dataType:str

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

class specificACderive_Data(BaseModel):  
    UserName:str
    targetUserName:str
    role:str
    passw:str
    esclatationRole:str
    esclatationUserName:str
    dataType:str
    newPrivilege:str#R-W -> R*-W*

class change_Data(BaseModel):  
    UserName:str
    targetUserName:str
    role:str
    passw:str
    targetRole:str
    dataType:str
    newData:str

class dataTypes_privileges():   
    template={
		"Insurance":{"organizationName":00000, "ExpirationTime":00000},
		"Telemetry":{
			"HealthTelemetry":{"pulsRate":00000,"bloodPressure":00000}, 
			"PersonalTelemetry":{"Location":{"x":00000,"y":00000} }
		},
		"PersonalInfo":{
			"BiometricInfo":{"BloodType":00000, "EyeColor":00000},
			"PersonalData":{"FirstName":00000 , "LastName": 00000, "age":00000, "IDNo":00000}
		},
		"HealthInfo":{
			"Past":{"precedure":00000, "recognition":00000, "prescription":00000},
			"curr":{"precedure":00000, "recognition":00000, "prescription":00000}
		}
	}

    simple_template={
		"Insurance":00000,
		"Telemetry":00000,
		"PersonalInfo":00000,
		"HealthInfo":00000
	}