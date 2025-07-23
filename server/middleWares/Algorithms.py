from DB_config.mdb import Mdb 
from middleWares.cryptography import encrypt_privileges, decrypt_privileges, keyGenerator
from serializers.Roles import serializeDictRoles, serializeListRoles
from middleWares.roles_aranging import *
import os

def chk_parentalPrivilege_4_child(childDT_privileges,parentDT_privileges):
    for cDT_privilege in childDT_privileges.values():
        if type(cDT_privilege)==int:
            if cDT_privilege>parentDT_privileges:
                return False
        else:
            return chk_parentalPrivilege_4_child(cDT_privilege,parentDT_privileges)
    return True

def chk_parentalPrivilege_4_parent(childDT_privileges,parentDT_privileges):
    for pDT_privilege in parentDT_privileges.values():
        if type(pDT_privilege)==int:
            if childDT_privileges>pDT_privilege:
                return False
        else:
            return chk_parentalPrivilege_4_parent(childDT_privileges,pDT_privilege)
    return True

def chk_parentPrivilege(childDT_privileges,parentDT_privileges):
    for dt,pDT_privilege in parentDT_privileges.items():
        if type(pDT_privilege)==int:
            if type(childDT_privileges[dt])==int:
                if childDT_privileges[dt]>pDT_privilege:
                    return False
            else:
                if not(chk_parentalPrivilege_4_child(childDT_privileges[dt],pDT_privilege)):
                    return False
        else:
            if type(childDT_privileges[dt])==int:
                if not(chk_parentalPrivilege_4_parent(pDT_privilege,childDT_privileges[dt])):
                    return False
            else:
                if not(chk_parentPrivilege(childDT_privileges[dt],pDT_privilege)):
                    return False
    return True

def chkParentalSpecialPrivileges(parent_privilege,child_privilege):
    mdb=Mdb()
    FRBAC_db=mdb.get_FRBAC_db()
    r4srParents=FRBAC_db.Roles.find({"name":{"$in":child_privilege["R4SR"]}})
    r4srParents=serializeListRoles(r4srParents)
    r4swParents=FRBAC_db.Roles.find({"name":{"$in":child_privilege["R4SW"]}})
    r4swParents=serializeListRoles(r4swParents)
    c4rParents=FRBAC_db.Roles.find({"name":{"$in":child_privilege["C4R"]}})
    c4rParents=serializeListRoles(c4rParents)

    if (all((item in parent_privilege["R4SR"]) or (any(iitem in parent_privilege["R4SR"] for iitem in r4srParents[i]["ancestors"])) for i,item in enumerate(child_privilege["R4SR"]))) and (all((item in parent_privilege["R4SW"]) or (any(iitem in parent_privilege["R4SW"] for iitem in r4swParents[i]["ancestors"])) for i,item in enumerate(child_privilege["R4SW"]))) and (all((item in parent_privilege["C4R"]) or (any(iitem in parent_privilege["C4R"] for iitem in c4rParents[i]["ancestors"])) for i,item in enumerate(child_privilege["C4R"]))):
        return True
    
    return False

def repairFromParent(roleName,ancestors):
    mdb=Mdb()
    FRBAC_db=mdb.get_FRBAC_db()
    role=FRBAC_db.Roles.find_one({"name":roleName})        
    try:
        ancestorRole=FRBAC_db.Roles.find_one({"name":ancestors[0]})
        key = os.getenv("KEY")
        privileges=decrypt_privileges(ancestorRole["privileges"],key)
        role_privilege=ancestorRole["children"][str(role["id"])]
        role_privilege=decrypt_privileges(role_privilege,key)
        newKey=keyGenerator()
        role_privilege=encrypt_privileges(role_privilege,newKey)
        FRBAC_db.Roles.update_one({"name":roleName},{"$set":{"privileges":role_privilege}})
    except:
        if len(ancestors)>1:
            repairFromParent(ancestors[0],ancestors[1:])
            ancestorRole=FRBAC_db.Roles.find_one({"name":ancestors[0]})
            key = os.getenv("KEY")
            privileges=decrypt_privileges(ancestorRole["privileges"],key)
            role_privilege=ancestorRole["children"][str(role["id"])]
            role_privilege=decrypt_privileges(role_privilege,key)
            newKey=keyGenerator()
            role_privilege=encrypt_privileges(role_privilege,newKey)
            FRBAC_db.Roles.update_one({"name":roleName},{"$set":{"privileges":role_privilege}})
        else:
            #it's not repairable from parent try two other solutions !!!
            #fetch from backup root and update
            ancestorRole=FRBAC_db.Roles.find_one({"name":"rootBackup"})
            key = os.getenv("KEY")
            privileges=decrypt_privileges(ancestorRole["privileges"],key)
            role_privilege=ancestorRole["children"][str(role["id"])]
            role_privilege=decrypt_privileges(role_privilege,key)
            newKey=keyGenerator()
            role_privilege=encrypt_privileges(role_privilege,newKey)
            FRBAC_db.Roles.update_one({"name":roleName},{"$set":{"privileges":role_privilege}})

def sub_hchk(role,children_privilege,privileges,FRBAC_db,key):
    sw=0
    for childID,child_privilege in role["children"].items():   
        if(type(child_privilege)==dict):
            role=FRBAC_db.Roles.find_one({"id":int(childID)})
            privileges=decrypt_privileges(role["privileges"],key)
            sub_hchk(role,children_privilege,privileges,FRBAC_db,key)
        elif not(child_privilege in children_privilege.values()) and chkParentalSpecialPrivileges(privileges,decrypt_privileges(child_privilege,key)) and chk_parentPrivilege(decrypt_privileges(child_privilege,key)["dataItems_privileges"],privileges["dataItems_privileges"]):      
            childRole=FRBAC_db.Roles.find_one({"id":int(childID)})            
            children_privilege.update({childID:hchk(childRole["name"],key)})
        else:
            sw=1
            FRBAC_db.Roles.delete_one({"id":int(childID)})
    return sw

def hchk(roleName,key):
    mdb=Mdb()
    FRBAC_db=mdb.get_FRBAC_db()
    children_privilege={}
    role=FRBAC_db.Roles.find_one({"name":roleName})
    try:
        privileges=decrypt_privileges(role["privileges"],key)
    except:    
        repairFromParent(role["name"],role["ancestors"])
        role=FRBAC_db.Roles.find_one({"name":roleName})
        privileges=decrypt_privileges(role["privileges"],key)

    sw=sub_hchk(role,children_privilege,privileges,FRBAC_db,key)

    if sw:
        newKey=keyGenerator()
        newRolePrivilege=encrypt_privileges(privileges,newKey)
        FRBAC_db.Roles.update_one({"id":role["id"]},{"$set":{"children":children_privilege,"privileges":newRolePrivilege}})
        updateAncestorsChildren(role["ancestors"],children_privilege,role["id"])
    return role["privileges"]
