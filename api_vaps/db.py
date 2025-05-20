
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from dotenv import load_dotenv
import os

load_dotenv()

uri = os.getenv("MONGO_URI")
database_name = os.getenv("DATABASE_NAME")
collection_name = os.getenv("COLLECTION_NAME")

# Create a new client and connect to the server
client = MongoClient(uri, server_api=ServerApi('1'))

# Create the database and collection
db = client[database_name]

# Obtener la coleccion
colection = db[collection_name]


# Send a ping to confirm a successful connection
# try:
#     client.admin.command('ping')
#     print("Pinged your deployment. You successfully connected to MongoDB!")
# except Exception as e:
#     print(e)

# Buscar por cwe_id
def buscar_por_cwe(cwe_id):
    resultado = colection.find_one({"cwe_id": cwe_id})
    return resultado
