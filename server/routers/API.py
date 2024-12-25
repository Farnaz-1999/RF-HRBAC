from fastapi import APIRouter
from DB_config.mdb import Mdb 
from serializers.Relations import serializeDictRelation, serializeListRelation
from serializers.Roles import serializeDictRoles, serializeListRoles
from middleWares.cryptography import encrypt_privileges, decrypt_privileges
from middleWares.roles_aranging import *
from middleWares.Algorithms import *
from data.dataTypes import *
import os

routes = APIRouter()

#test
@routes.get("/")
def default():
    return{"Welcome to FRBAC Model"}

#fetchOwnAC
@routes.get('/fetchOwnData/{UserName}/{role}/{passw}')
async def fetchOwnPrivileges(UserName,role,passw):
    mdb=Mdb()
    FRBAC_db=mdb.get_FRBAC_db()
    output="unexpected Err"
    user=FRBAC_db.Users.find_one({'user_name':UserName,'role_label':role,'password':passw})

    if user!=None:
        user_role=FRBAC_db.Roles.find_one({'id':user["role_id"],'name':role})
        key = os.getenv("KEY")
        privileges=decrypt_privileges(user_role["privileges"],key)
        output={'data':user["Data"],'role_privileges':privileges}
    else:
        output="No User found with this details"

    return output 

#fetchRelatedACs
@routes.get('/users/privileges/{UserName}/{role}/{passw}')
async def fetch_privileges(UserName,role,passw):
    mdb=Mdb()
    FRBAC_db=mdb.get_FRBAC_db()
    output="No User found with this details"
    user=FRBAC_db.Users.find_one({'user_name':UserName,'role_label':role,'password':passw})

    if user!=None:
        rels_privileges=[]
        if role=="self":
            relations=FRBAC_db.Relations.find({'user_id':user["user_id"]})
            if relations!=None:
                rels=serializeListRelation(relations)
                key = os.getenv("KEY")
                for rel in rels:                    
                    rel_privileges=FRBAC_db.Roles.find_one({"id":rel["relation_role_id"]})["privileges"]
                    rel_privileges=decrypt_privileges(rel_privileges,key)
                    rels_privileges.append({"rel_user_name":rel["related_user_name"],"privileges":rel_privileges})        
        else:
            relations=FRBAC_db.Relations.find({'related_user_id':user["user_id"]})
            if relations!=None:
                rels=serializeListRelation(relations)
                default_rel_privileges=FRBAC_db.Roles.find_one({"id":user["role_id"]})["privileges"]
                key = os.getenv("KEY")
                default_rel_privileges=decrypt_privileges(default_rel_privileges,key)
                for rel in rels:
                    if user["role_id"]==rel["relation_role_id"]:
                        rels_privileges.append({"rel_user_name":rel["user_name"],"privileges":default_rel_privileges})
                    else:
                        rel_privileges=FRBAC_db.Roles.find_one({"id":rel["relation_role_id"]})["privileges"]
                        rel_privileges=decrypt_privileges(rel_privileges,key)
                        rels_privileges.append({"rel_user_name":rel["user_name"],"privileges":rel_privileges})        
        return rels_privileges

    return output

#fetchControlRelACs
@routes.get('/rel/users/privileges/{UserName}/{role}/{passw}/{relUserName}')
async def fetch_relPrivileges_control(UserName,role,passw,relUserName):
    mdb=Mdb()
    FRBAC_db=mdb.get_FRBAC_db()
    output="No User found with this details"
    user=FRBAC_db.Users.find_one({'user_name':UserName,'role_label':role,'password':passw})
    if user!=None:
        output="Relation doesn't exist !!!"
        relation=FRBAC_db.Relations.find_one({'related_user_id':user["user_id"], "user_name":relUserName})
        if relation!=None:
            output="access denied"
            privileges=FRBAC_db.Roles.find_one({'id':relation["relation_role_id"]})["privileges"]
            key = os.getenv("KEY")
            privileges=decrypt_privileges(privileges,key)            
            if privileges["C4R"]!=[]: 
                relations=FRBAC_db.Relations.find({'user_name':relUserName})
                if relations!=None:
                    rels_privileges=[]       
                    rels=serializeListRelation(relations)
                    for rel in rels:  
                        rel_privileges=FRBAC_db.Roles.find_one({"id":rel["relation_role_id"]})["privileges"]
                        rel_privileges=decrypt_privileges(rel_privileges,key)                        
                        rels_privileges.append({"rel_user_name":rel["related_user_name"],"privileges":rel_privileges})
            
                return rels_privileges

    return output

#ACderive
@routes.post('/ACderive')
async def ACderive(items:ACderive_Data):
    mdb=Mdb()
    FRBAC_db=mdb.get_FRBAC_db()
    user=FRBAC_db.Users.find_one({'user_name':items.UserName,'role_label':items.role,'password':items.passw})
    output="No User found with this details"
    if user!=None:
        role=FRBAC_db.Roles.find_one({"id":user["role_id"]})   
        key = os.getenv("KEY")
        hchk(role["ancestors"][0],key)
        role=FRBAC_db.Roles.find_one({"id":user["role_id"]})   
        privileges=decrypt_privileges(role["privileges"],key)
        output="Privilege Denied"
        if privileges["C4R"] != []:
            C4Roles=privileges["C4R"]
            EsclatationRole=FRBAC_db.Roles.find_one({"name":items.relRole})
            relRoleParents=EsclatationRole["ancestors"]
            esclatation_role_privilege=EsclatationRole["privileges"]
            esclatation_role_privilege=decrypt_privileges(esclatation_role_privilege,key)

            if items.relRole in C4Roles or any(i in C4Roles for i in relRoleParents): 
                #chk access derive for special privileges                
                relRoleParent=FRBAC_db.Roles.find_one({"name":relRoleParents[0]})
                relRoleParentCildren=relRoleParent["children"]
                relRoleParentName=relRoleParent["name"]
                relRoleParentCildrenNO=len(relRoleParentCildren)
                relRoleParentPrivileges=decrypt_privileges(relRoleParent["privileges"],key)

                r4srParents=FRBAC_db.Roles.find({"name":{"$in":items.R4SR}})
                r4srParents=serializeListRoles(r4srParents)
                r4swParents=FRBAC_db.Roles.find({"name":{"$in":items.R4SW}})
                r4swParents=serializeListRoles(r4swParents)
                c4rParents=FRBAC_db.Roles.find({"name":{"$in":items.C4R}})
                c4rParents=serializeListRoles(c4rParents)

                output="Access Denied to derive special privileges"
                if (all((item in relRoleParentPrivileges["R4SR"]) or (any(iitem in relRoleParentPrivileges["R4SR"] for iitem in r4srParents[i]["ancestors"])) for i,item in enumerate(items.R4SR))) and (all((item in relRoleParentPrivileges["R4SW"]) or (any(iitem in relRoleParentPrivileges["R4SW"] for iitem in r4swParents[i]["ancestors"])) for i,item in enumerate(items.R4SW))) and (all((item in relRoleParentPrivileges["C4R"]) or (any(iitem in relRoleParentPrivileges["C4R"] for iitem in c4rParents[i]["ancestors"])) for i,item in enumerate(items.C4R))):
                    #chk access derive for data types                      
                    dataTypeParents=FRBAC_db.DataItems.find_one({"name":items.dataType})["ancestors"]              
                    dataTypeParents.append(items.dataType)

                    esclatation_role_privilege["C4R"]=items.C4R
                    esclatation_role_privilege["R4SR"]=items.R4SR
                    esclatation_role_privilege["R4SW"]=items.R4SW
                            
                    output="Access Denied"
                    if chk_requesterPrivilege_2_data(privileges["dataItems_privileges"],dataTypeParents[1:]):
                        if chk_dataDerivePrivilege_4_role(relRoleParentPrivileges["dataItems_privileges"],dataTypeParents[1:],items.newPrivilege):
                            change_dataTypes_privileges(esclatation_role_privilege["dataItems_privileges"],dataTypeParents[1:],items.newPrivilege)
                            esclatation_role_privilege_hashed=encrypt_privileges(esclatation_role_privilege,key)
                            newRoleID=0
                            for child,childHash in relRoleParentCildren.items():
                                if esclatation_role_privilege_hashed==childHash:
                                    newRoleID=int(child)
                                    break
                            if not(newRoleID):
                                name=relRoleParentName+"child"+str(relRoleParentCildrenNO)
                                newRoleID=FRBAC_db.Roles.count_documents({})
                                FRBAC_db.Roles.insert_one({"name": name,"id": newRoleID,"privileges": esclatation_role_privilege_hashed,"children": {},"ancestors": relRoleParents})
                                updateAncestorsChildren(relRoleParents,esclatation_role_privilege_hashed,newRoleID)

                            if items.targetUserName:
                                anyRel2Taget=FRBAC_db.Relations.find_one({"user_name":items.targetUserName,"related_user_name":items.UserName})
                                if anyRel2Taget!=None:
                                    FRBAC_db.Relations.update_one({"user_name":items.targetUserName,"related_user_name":items.relUserName},{ "$set": { "relation_role_id": newRoleID } })
                            else:
                                FRBAC_db.Relations.update_one({"user_name":items.UserName,"related_user_name":items.relUserName},{ "$set": { "relation_role_id": newRoleID } })
                            output="done"
                            hchk(relRoleParentName,key)

    return output

#AddRel
@routes.post('/add/rel/')
async def addRels(items:relData):
    mdb=Mdb()
    FRBAC_db=mdb.get_FRBAC_db()
    user=FRBAC_db.Users.find_one({'user_name':items.UserName,'role_label':items.role,'password':items.passw})
    output="No User found with this details"
    if user!=None:
        privileges=FRBAC_db.Roles.find_one({"id":user["role_id"]})["privileges"]
        key = os.getenv("KEY")
        privileges=decrypt_privileges(privileges,key)
        output="Privilege Denied"
        if privileges["C4R"] != []:
            C4Roles=privileges["C4R"]
            EsclatationRole=FRBAC_db.Roles.find_one({"name":items.relRole})
            relRoleParents=EsclatationRole["ancestors"]
            relRoleID=EsclatationRole["id"]

            if items.relRole in C4Roles or any(i in C4Roles for i in relRoleParents):                
                relUserId=FRBAC_db.Users.find_one({'user_name':items.relUserName})["user_id"]
                if items.targetUserName:
                    anyRel2Taget=FRBAC_db.Relations.find_one({"user_name":items.targetUserName,"related_user_name":items.UserName})
                    if anyRel2Taget!=None:
                        targetUserNameId=FRBAC_db.Users.find_one({'user_name':items.targetUserName})["user_id"]                   
                        FRBAC_db.Relations.insert_one({
                        "related_user_name": items.relUserName,
                        "user_name": items.targetUserName,
                        "relation_role_id": relRoleID,
                        "relation_role_label": items.relRole,
                        "related_user_id": relUserId,
                        "user_id": targetUserNameId
                    })
                    output="done"
                else:
                    FRBAC_db.Relations.insert_one({
                        "related_user_name": items.relUserName,
                        "user_name": items.UserName,
                        "relation_role_id": relRoleID,
                        "relation_role_label": items.relRole,
                        "related_user_id": relUserId,
                        "user_id": user["user_id"]
                    })
                    output="done"

    return output

#RevokeRel
@routes.post('/revoke/rel/')
async def revokeRels(items:relData):
    mdb=Mdb()
    FRBAC_db=mdb.get_FRBAC_db()
    user=FRBAC_db.Users.find_one({'user_name':items.UserName,'role_label':items.role,'password':items.passw})
    output="No User found with this details"
    if user!=None:
        privileges=FRBAC_db.Roles.find_one({"id":user["role_id"]})["privileges"]
        key = os.getenv("KEY")
        privileges=decrypt_privileges(privileges,key)
        output="Privilege Denied"
        if privileges["C4R"] != []:
            C4Roles=privileges["C4R"]
            EsclatationRole=FRBAC_db.Roles.find_one({"name":items.relRole})
            relRoleParents=EsclatationRole["ancestors"]
            
            if items.relRole in C4Roles or any(i in C4Roles for i in relRoleParents):                
                if items.targetUserName:
                    anyRel2Taget=FRBAC_db.Relations.find_one({"user_name":items.targetUserName,"related_user_name":items.UserName})
                    if anyRel2Taget!=None:
                        FRBAC_db.Relations.delete_one({
                            "related_user_name": items.relUserName,
                            "user_name": items.targetUserName,
                        })
                else:
                    FRBAC_db.Relations.delete_one({
                        "related_user_name": items.relUserName,
                        "user_name": items.UserName,
                    })
                output="done"

    return output
