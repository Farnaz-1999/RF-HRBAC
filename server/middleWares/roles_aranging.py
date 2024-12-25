from DB_config.mdb import Mdb 

def rebuild_dataTypes_privileges(dataTypeParents,esclatation_role_privilege,newPrivilege):
    mdb=Mdb()
    FRBAC_db=mdb.get_FRBAC_db()
    newDT_privileges={}
    children=FRBAC_db.DataItems.find_one({"name":dataTypeParents[0]})
    for child in children:
        newDT_privileges.update({child:esclatation_role_privilege})
    if len(dataTypeParents)==2:
        newDT_privileges.update({dataTypeParents[1]:newPrivilege})
    else:
        newDT_privileges.update({dataTypeParents[1]:rebuild_dataTypes_privileges(dataTypeParents[1:],esclatation_role_privilege,newPrivilege)})
    return newDT_privileges

def change_dataTypes_privileges(esclatation_role_privilege,dataTypeParents,newPrivilege):
    if type(esclatation_role_privilege[dataTypeParents[0]])==int:
        if len(dataTypeParents)==1:
            esclatation_role_privilege[dataTypeParents[0]]=newPrivilege
        elif esclatation_role_privilege[dataTypeParents[0]]!=newPrivilege:
            esclatation_role_privilege[dataTypeParents[0]]=rebuild_dataTypes_privileges(dataTypeParents,esclatation_role_privilege[dataTypeParents[0]],newPrivilege)
    else:
        return change_dataTypes_privileges(esclatation_role_privilege[dataTypeParents[0]],dataTypeParents[1:],newPrivilege)

def chk_requesterPrivilege_2_data(privileges,dataTypeParents):
    if type(privileges[dataTypeParents[0]])==int:
        if privileges[dataTypeParents[0]]>=20000:
            return True
        else:
            return False
    else:
        return chk_requesterPrivilege_2_data(privileges[dataTypeParents[0]],dataTypeParents[1:])

def chk_dataDerivePrivilege_4_role(relRoleParentPrivileges,dataTypeParents,newPrivilege):
    if type(relRoleParentPrivileges[dataTypeParents[0]])==int:
        if relRoleParentPrivileges[dataTypeParents[0]]>=newPrivilege:
            return True
        else:
            return False
    else:
        return chk_dataDerivePrivilege_4_role(relRoleParentPrivileges[dataTypeParents[0]],dataTypeParents[1:],newPrivilege)

def updateAncestorsChildren(relRoleParents,esclatation_role_privilegeHashed,EsclatationRoleID):
    mdb=Mdb()
    FRBAC_db=mdb.get_FRBAC_db()
    parentRole=FRBAC_db.Roles.find_one({"name":relRoleParents[0]})
    parentRole["children"].update({str(EsclatationRoleID):esclatation_role_privilegeHashed})
    FRBAC_db.Roles.update_one({"name":relRoleParents[0]}, {"$set": {"children":parentRole["children"]}})
    if len(relRoleParents)>1:
        updateAncestorsChildren(relRoleParents[1:],parentRole["children"],parentRole["id"])
