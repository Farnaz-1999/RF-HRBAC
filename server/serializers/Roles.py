def serializeDictRoles(item) -> dict:
    return{            
            "name": item["name"],
            "id": item['id'],
            "privileges": item['privileges'],
            "children": item["children"],
            "ancestors": item["ancestors"],
    }

def serializeListRoles(entity) -> list:
    return [serializeDictRoles(item) for item in entity]
