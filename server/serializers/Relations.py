def serializeDictRelation(item) -> dict:
    return{            
            "related_user_name": item["related_user_name"],
            "user_name": item['user_name'],
            "relation_role_id": item['relation_role_id'],
            "relation_role_label": item["relation_role_label"],
            "related_user_id": item["related_user_id"],
            "user_id": item["user_id"]
    }

def serializeListRelation(entity) -> list:
    return [serializeDictRelation(item) for item in entity]
