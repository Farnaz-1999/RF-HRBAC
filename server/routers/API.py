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
    return{"Welcome to FRHRBAC Model"}

#fetchOwnAC
@routes.post('/fetchOwnData/')
async def fetchOwnPrivileges(items:fetchData):
    mdb=Mdb()
    FRHRBAC_db=mdb.get_FRHRBAC_db()
    output="unexpected Err"
    user=FRHRBAC_db.Users.find_one({'user_name':items.UserName,'role_label':items.role,'password':items.passw})

    if user!=None:
        user_role=FRHRBAC_db.Roles.find_one({'id':user["role_id"],'name':items.role})
        key = os.getenv("KEY")
        privileges=decrypt_privileges(user_role["privileges"],key)
        output={'data':user["Data"],'role_privileges':privileges}
    else:
        output="No User found with this details"

    return output 

#fetchRelatedACs
@routes.post('/users/privileges/')
async def fetch_privileges(items:fetchData):
    mdb=Mdb()
    FRHRBAC_db=mdb.get_FRHRBAC_db()
    output="No User found with this details"
    user=FRHRBAC_db.Users.find_one({'user_name':items.UserName,'role_label':items.role,'password':items.passw})

    if user!=None:
        rels_privileges=[]
        if items.role=="self":
            relations=FRHRBAC_db.Relations.find({'user_id':user["user_id"]})
            if relations!=None:
                rels=serializeListRelation(relations)
                key = os.getenv("KEY")
                for rel in rels:                    
                    rel_privileges=FRHRBAC_db.Roles.find_one({"id":rel["relation_role_id"]})["privileges"]
                    rel_privileges=decrypt_privileges(rel_privileges,key)
                    rels_privileges.append({"rel_user_name":rel["related_user_name"],"privileges":rel_privileges})        
        else:
            relations=FRHRBAC_db.Relations.find({'related_user_id':user["user_id"]})
            if relations!=None:
                rels=serializeListRelation(relations)
                default_rel_privileges=FRHRBAC_db.Roles.find_one({"id":user["role_id"]})["privileges"]
                key = os.getenv("KEY")
                default_rel_privileges=decrypt_privileges(default_rel_privileges,key)
                for rel in rels:
                    if user["role_id"]==rel["relation_role_id"]:
                        rels_privileges.append({"rel_user_name":rel["user_name"],"privileges":default_rel_privileges})
                    else:
                        rel_privileges=FRHRBAC_db.Roles.find_one({"id":rel["relation_role_id"]})["privileges"]
                        rel_privileges=decrypt_privileges(rel_privileges,key)
                        rels_privileges.append({"rel_user_name":rel["user_name"],"privileges":rel_privileges})        
        return rels_privileges

    return output

#fetchControlRelACs
@routes.post('/rel/users/privileges/')
async def fetch_relPrivileges_control(items:fetchRelData):
    mdb=Mdb()
    FRHRBAC_db=mdb.get_FRHRBAC_db()
    output="No User found with this details"
    user=FRHRBAC_db.Users.find_one({'user_name':items.UserName,'role_label':items.role,'password':items.passw})
    if user!=None:
        output="Relation doesn't exist !!!"
        relation=FRHRBAC_db.Relations.find_one({'related_user_id':user["user_id"], "user_name":items.relUserName})
        if relation!=None:
            output="access denied"
            privileges=FRHRBAC_db.Roles.find_one({'id':relation["relation_role_id"]})["privileges"]
            key = os.getenv("KEY")
            privileges=decrypt_privileges(privileges,key)            
            if privileges["C4R"]!=[]: 
                relations=FRHRBAC_db.Relations.find({'user_name':items.relUserName})
                if relations!=None:
                    rels_privileges=[]       
                    rels=serializeListRelation(relations)
                    for rel in rels:  
                        rel_privileges=FRHRBAC_db.Roles.find_one({"id":rel["relation_role_id"]})["privileges"]
                        rel_privileges=decrypt_privileges(rel_privileges,key)                        
                        rels_privileges.append({"rel_user_name":rel["related_user_name"],"privileges":rel_privileges})
            
                return rels_privileges

    return output

#fetchOthersData
@routes.post('/fetchOthersData/')
async def fetchOthersData(items:fetchOtherData):
    mdb=Mdb()
    FRHRBAC_db=mdb.get_FRHRBAC_db()
    user=FRHRBAC_db.Users.find_one({'user_name':items.UserName,'role_label':items.role,'password':items.passw})
    output="No User found with this details"
    if user!=None:
        role=FRHRBAC_db.Roles.find_one({"id":user["role_id"]})   
        key = os.getenv("KEY")
        hchk(role["ancestors"][0],key)
        role=FRHRBAC_db.Roles.find_one({"id":user["role_id"]})   
        privileges=decrypt_privileges(role["privileges"],key)
       
        #chk access derive for data types                      
        dataTypeParents=FRHRBAC_db.DataItems.find_one({"name":items.dataType})["ancestors"]              
        dataTypeParents.append(items.dataType)
                
        output="Access Denied"
        if chk_requesterPrivilege_2_data_2_read(privileges["dataItems_privileges"],dataTypeParents[1:]):
            #chk relations among users
            anyRel2Target=FRHRBAC_db.Relations.find_one({"user_name":items.targetUserName,"related_user_name":items.UserName})
            output="No Relations"
            if anyRel2Target!=None:
                targetUser=FRHRBAC_db.Users.find_one({'user_name':items.targetUserName,'role_label':items.targetRole})
                if targetUser!=None:
                    output=read_targetRole_specific_dataItem(targetUser["Data"],dataTypeParents[1:])
                else:
                    output="No target User found with this details"

    return output

#editOthersData
@routes.post('/editOthersData/')
async def editOthersData(items:change_Data):
    mdb=Mdb()
    FRHRBAC_db=mdb.get_FRHRBAC_db()
    user=FRHRBAC_db.Users.find_one({'user_name':items.UserName,'role_label':items.role,'password':items.passw})
    output="No User found with this details"
    if user!=None:
        role=FRHRBAC_db.Roles.find_one({"id":user["role_id"]})   
        key = os.getenv("KEY")
        hchk(role["ancestors"][0],key)

        anyRel2Target=FRHRBAC_db.Relations.find_one({"user_name":items.targetUserName,"related_user_name":items.UserName})

        output="No Relations"
        if anyRel2Target!=None:
            role=FRHRBAC_db.Roles.find_one({"id":anyRel2Target["relation_role_id"]})
            privileges=decrypt_privileges(role["privileges"],key)
        
            #chk access derive for data types                      
            dataTypeParents=FRHRBAC_db.DataItems.find_one({"name":items.dataType})["ancestors"]              
            dataTypeParents.append(items.dataType)
            output="Access Denied"
            if chk_requesterPrivilege_2_data_2_write(privileges["dataItems_privileges"],dataTypeParents[1:]):
                #chk relations among users
                targetUser=FRHRBAC_db.Users.find_one({'user_name':items.targetUserName,'role_label':items.targetRole})
                if targetUser!=None:
                    output=edit_targetRole_specific_dataItem(targetUser["Data"],dataTypeParents[1:],items.newData)
                    FRHRBAC_db.Users.update_one({'user_name':items.targetUserName,'role_label':items.targetRole}, { "$set": {"Data":output}})
                else:
                    output="No target User found with this details"

    return output

#ACderive
@routes.post('/ACderive/')
async def ACderive(items:ACderive_Data):
    mdb=Mdb()
    FRHRBAC_db=mdb.get_FRHRBAC_db()
    user=FRHRBAC_db.Users.find_one({'user_name':items.UserName,'role_label':items.role,'password':items.passw})
    output="No User found with this details"
    if user!=None:
        role=FRHRBAC_db.Roles.find_one({"id":user["role_id"]})   
        key = os.getenv("KEY")
        hchk(role["ancestors"][0],key)

        if items.targetUserName:
            user_relation=FRHRBAC_db.Relations.find_one({"user_name":items.targetUserName,"related_user_name":items.UserName})
        elif items.role=="self":
            user_relation=FRHRBAC_db.Relations.find_one({"user_name":items.UserName,"related_user_name":items.UserName})
        else:
            user_relation=FRHRBAC_db.Relations.find_one({"user_name":items.relUserName,"related_user_name":items.UserName})

        role=FRHRBAC_db.Roles.find_one({"id":user_relation["relation_role_id"]})   
        privileges=decrypt_privileges(role["privileges"],key)
        output="Privilege Denied"

        if privileges["C4R"] != []:
            C4Roles=privileges["C4R"]
            EsclatationRole=FRHRBAC_db.Roles.find_one({"name":items.relRole})
            relRoleParents=EsclatationRole["ancestors"]
            esclatation_role_privilege=EsclatationRole["privileges"]
            esclatation_role_privilege=decrypt_privileges(esclatation_role_privilege,key)
            if items.relRole in C4Roles or any(i in C4Roles for i in relRoleParents): 
                #chk access derive for special privileges                
                relRoleParent=FRHRBAC_db.Roles.find_one({"name":relRoleParents[0]})
                relRoleParentCildren=relRoleParent["children"]
                relRoleParentName=relRoleParent["name"]
                relRoleParentCildrenNO=len(relRoleParentCildren)
                relRoleParentPrivileges=decrypt_privileges(relRoleParent["privileges"],key)
                
                r4srParents=FRHRBAC_db.Roles.find({"name":{"$in":items.R4SR}})
                r4srParents=serializeListRoles(r4srParents)
                r4swParents=FRHRBAC_db.Roles.find({"name":{"$in":items.R4SW}})
                r4swParents=serializeListRoles(r4swParents)
                c4rParents=FRHRBAC_db.Roles.find({"name":{"$in":items.C4R}})
                c4rParents=serializeListRoles(c4rParents)

                output="Access Denied to derive special privileges"
                if (all((item in relRoleParentPrivileges["R4SR"]) or (any(iitem in relRoleParentPrivileges["R4SR"] for iitem in r4srParents[i]["ancestors"])) for i,item in enumerate(items.R4SR))) and (all((item in relRoleParentPrivileges["R4SW"]) or (any(iitem in relRoleParentPrivileges["R4SW"] for iitem in r4swParents[i]["ancestors"])) for i,item in enumerate(items.R4SW))) and (all((item in relRoleParentPrivileges["C4R"]) or (any(iitem in relRoleParentPrivileges["C4R"] for iitem in c4rParents[i]["ancestors"])) for i,item in enumerate(items.C4R))):
                    #chk access derive for data types                      
                    dataTypeParents=FRHRBAC_db.DataItems.find_one({"name":items.dataType})["ancestors"]              
                    dataTypeParents.append(items.dataType)

                    esclatation_role_privilege["C4R"]=items.C4R
                    esclatation_role_privilege["R4SR"]=items.R4SR
                    esclatation_role_privilege["R4SW"]=items.R4SW
                            
                    output="Access Denied"
                    if chk_requesterPrivilege_2_data_2_change(privileges["dataItems_privileges"],dataTypeParents[1:]):
                        #to chk least privilege of related role  
                        if items.targetUserName:
                            relation=FRHRBAC_db.Relations.find_one({"user_name":items.targetUserName,"related_user_name":items.relUserName})
                        else:
                            relation=FRHRBAC_db.Relations.find_one({"user_name":items.UserName,"related_user_name":items.relUserName})
                        labeledRelRole=FRHRBAC_db.Roles.find_one({"name":relation["relation_role_label"]})
                        labeledRelRolePrivileges=decrypt_privileges(labeledRelRole["privileges"],key)
                        isParent=role["name"] in relRoleParents
                        if chk_dataDerivePrivilege_4_role(relRoleParentPrivileges["dataItems_privileges"],labeledRelRolePrivileges["dataItems_privileges"],dataTypeParents[1:],items.newPrivilege,isParent):
                            change_dataTypes_privileges(esclatation_role_privilege["dataItems_privileges"],dataTypeParents[1:],items.newPrivilege)
                            esclatation_role_privilege_hashed=encrypt_privileges(esclatation_role_privilege,key)
                            newRoleID=0
                            for child,childHash in relRoleParentCildren.items():
                                if esclatation_role_privilege_hashed==childHash:
                                    newRoleID=int(child)
                                    break
                            if not(newRoleID):
                                name=relRoleParentName+"child"+str(relRoleParentCildrenNO)
                                newRoleID=FRHRBAC_db.Roles.count_documents({})
                                FRHRBAC_db.Roles.insert_one({"name": name,"id": newRoleID,"privileges": esclatation_role_privilege_hashed,"children": {},"ancestors": relRoleParents})
                                updateAncestorsChildren(relRoleParents,esclatation_role_privilege_hashed,newRoleID)

                            if items.targetUserName:
                                anyRel2Taget=FRHRBAC_db.Relations.find_one({"user_name":items.targetUserName,"related_user_name":items.UserName})
                                if anyRel2Taget!=None:
                                    FRHRBAC_db.Relations.update_one({"user_name":items.targetUserName,"related_user_name":items.relUserName},{ "$set": { "relation_role_id": newRoleID } })
                            else:
                                FRHRBAC_db.Relations.update_one({"user_name":items.UserName,"related_user_name":items.relUserName},{ "$set": { "relation_role_id": newRoleID } })
                           
                            output="done"
                            hchk(relRoleParentName,key)

    return output

#specific ACderive for R*, W*
@routes.post('/specificACderive/')
async def specific_ACderive(items:specificACderive_Data):
    mdb=Mdb()
    FRHRBAC_db=mdb.get_FRHRBAC_db()
    user=FRHRBAC_db.Users.find_one({'user_name':items.UserName,'role_label':items.role,'password':items.passw})
    output="No User found with this details"
    if user!=None:
        role=FRHRBAC_db.Roles.find_one({"id":user["role_id"]})
        key = os.getenv("KEY")
        hchk(role["ancestors"][0],key)
        role=FRHRBAC_db.Roles.find_one({"id":user["role_id"]})   
        privileges=decrypt_privileges(role["privileges"],key)

        esclatationRole=FRHRBAC_db.Roles.find_one({"name":items.esclatationRole})
        esclatationRoleParents=esclatationRole["ancestors"]

        #chk access derive for special privileges                
        esclatationRoleParent=FRHRBAC_db.Roles.find_one({"name":esclatationRoleParents[0]})
        esclatationRoleParentCildren=esclatationRoleParent["children"]
        esclatationRoleParentName=esclatationRoleParent["name"]
        esclatationRoleParentCildrenNO=len(esclatationRoleParentCildren)
        esclatationRoleParentPrivileges=decrypt_privileges(esclatationRoleParent["privileges"],key)

        #chk access derive for data types                      
        dataTypeParents=FRHRBAC_db.DataItems.find_one({"name":items.dataType})["ancestors"]              
        dataTypeParents.append(items.dataType)
                
        output="Access Denied"
        requester_min_privilege=0
        newPrivilege=0
        if items.newPrivilege=="R":
            requester_min_privilege=10011#R*
            newPrivilege=10001
        else:
            requester_min_privilege=11100#W*
            newPrivilege=10100

        if chk_requesterPrivilege_2_data_2_change(privileges["dataItems_privileges"],dataTypeParents[1:],requester_min_privilege):
            if chk_specificDataDerivePrivilege_4_role(esclatationRoleParentPrivileges["dataItems_privileges"],dataTypeParents[1:],newPrivilege):
                newPermissions=dataTypes_privileges.template
                rebuild_dataTypes_privileges(dataTypeParents[1:],newPermissions,newPrivilege)
                #set all to null
                esclatation_role_privilege={"dataItems_privileges":newPermissions}
                esclatation_role_privilege["C4R"]=[]
                esclatation_role_privilege["R4SR"]=[]
                esclatation_role_privilege["R4SW"]=[]

                esclatation_role_privilege_hashed=encrypt_privileges(esclatation_role_privilege,key)
                newRoleID=0
                for child,childHash in esclatationRoleParentCildren.items():
                    if esclatation_role_privilege_hashed==childHash:
                        newRoleID=int(child)
                        break

                esclatationUser=FRHRBAC_db.Users.find_one({'user_name':items.esclatationUserName})
                targetUser=FRHRBAC_db.Users.find_one({'user_name':items.targetUserName})

                if not(newRoleID):
                    name=esclatationRoleParentName+"child"+str(esclatationRoleParentCildrenNO)
                    newRoleID=FRHRBAC_db.Roles.count_documents({})
                    FRHRBAC_db.Roles.insert_one({"name": name,"id": newRoleID,"privileges": esclatation_role_privilege_hashed,"children": {},"ancestors": esclatationRoleParents})
                    updateAncestorsChildren(esclatationRoleParents,esclatation_role_privilege_hashed,newRoleID)

                    #add rel among target and esclation role
                    FRHRBAC_db.Relations.insert_one({"related_user_name": items.esclatationUserName, "related_user_id":esclatationUser["user_id"], "relation_role_id": newRoleID, "relation_role_label":name, "user_name": items.targetUserName, "user_id":targetUser["user_id"] })
                else:
                    labeledRole=FRHRBAC_db.Roles.find_one({"id":newRoleID})
                    name=labeledRole["name"]
                    FRHRBAC_db.Relations.insert_one({"related_user_name": items.esclatationUserName, "related_user_id":esclatationUser["user_id"], "relation_role_id":newRoleID , "relation_role_label":name, "user_name": items.targetUserName, "user_id":targetUser["user_id"] })
                print("Gand:\n",esclatation_role_privilege)
                output="done"
                hchk(esclatationRoleParentName,key)

    return output

#AddRel
@routes.post('/add/rel/')
async def addRels(items:relData):
    mdb=Mdb()
    FRHRBAC_db=mdb.get_FRHRBAC_db()
    user=FRHRBAC_db.Users.find_one({'user_name':items.UserName,'role_label':items.role,'password':items.passw})
    output="No User found with this details"
    if user!=None:
        privileges=FRHRBAC_db.Roles.find_one({"id":user["role_id"]})["privileges"]
        key = os.getenv("KEY")
        privileges=decrypt_privileges(privileges,key)
        output="Privilege Denied"
        if privileges["C4R"] != []:
            C4Roles=privileges["C4R"]
            EsclatationRole=FRHRBAC_db.Roles.find_one({"name":items.relRole})
            relRoleParents=EsclatationRole["ancestors"]
            relRoleID=EsclatationRole["id"]

            if items.relRole in C4Roles or any(i in C4Roles for i in relRoleParents):                
                relUserId=FRHRBAC_db.Users.find_one({'user_name':items.relUserName})["user_id"]
                if items.targetUserName:
                    anyRel2Taget=FRHRBAC_db.Relations.find_one({"user_name":items.targetUserName,"related_user_name":items.UserName})
                    if anyRel2Taget!=None:
                        targetUserNameId=FRHRBAC_db.Users.find_one({'user_name':items.targetUserName})["user_id"]                   
                        FRHRBAC_db.Relations.insert_one({
                        "related_user_name": items.relUserName,
                        "user_name": items.targetUserName,
                        "relation_role_id": relRoleID,
                        "relation_role_label": items.relRole,
                        "related_user_id": relUserId,
                        "user_id": targetUserNameId
                    })
                    output="done"
                else:
                    FRHRBAC_db.Relations.insert_one({
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
    FRHRBAC_db=mdb.get_FRHRBAC_db()
    user=FRHRBAC_db.Users.find_one({'user_name':items.UserName,'role_label':items.role,'password':items.passw})
    output="No User found with this details"
    if user!=None:
        privileges=FRHRBAC_db.Roles.find_one({"id":user["role_id"]})["privileges"]
        key = os.getenv("KEY")
        privileges=decrypt_privileges(privileges,key)
        output="Privilege Denied"
        if privileges["C4R"] != []:
            C4Roles=privileges["C4R"]
            EsclatationRole=FRHRBAC_db.Roles.find_one({"name":items.relRole})
            relRoleParents=EsclatationRole["ancestors"]
            
            if items.relRole in C4Roles or any(i in C4Roles for i in relRoleParents):                
                if items.targetUserName:
                    anyRel2Taget=FRHRBAC_db.Relations.find_one({"user_name":items.targetUserName,"related_user_name":items.UserName})
                    if anyRel2Taget!=None:
                        FRHRBAC_db.Relations.delete_one({
                            "related_user_name": items.relUserName,
                            "user_name": items.targetUserName,
                        })
                else:
                    FRHRBAC_db.Relations.delete_one({
                        "related_user_name": items.relUserName,
                        "user_name": items.UserName,
                    })
                output="done"

    return output
