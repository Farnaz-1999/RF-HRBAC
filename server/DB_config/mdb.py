from pymongo import MongoClient
import os
from dotenv import load_dotenv

class Mdb:
    def __init__(self):
        self.__connect()

    def __connect(self):
        load_dotenv()
        self.__mongodb_connection= MongoClient(os.getenv("MONGO_URL"))

    def get_FRBAC_db(self):
        FRBAC_Mdb=self.__mongodb_connection.FRBAC_db
        return FRBAC_Mdb

    def __disconnect(self):
        self.__mongodb_connection.close()

    def __del__(self):
        self.__disconnect()