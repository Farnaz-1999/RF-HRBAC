from pymongo import MongoClient
import os
from dotenv import load_dotenv

class Mdb:
    def __init__(self):
        self.__connect()

    def __connect(self):
        load_dotenv()
        self.__mongodb_connection= MongoClient(os.getenv("MONGO_URL"))

    def get_FRHRBAC_db(self):
        FRHRBAC_Mdb=self.__mongodb_connection.FRHRBAC_db
        return FRHRBAC_Mdb

    def __disconnect(self):
        self.__mongodb_connection.close()

    def __del__(self):
        self.__disconnect()