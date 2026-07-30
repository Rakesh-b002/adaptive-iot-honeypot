"""MongoDB connection helper."""

from functools import lru_cache
from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.database import Database
from honeypot_ml.config import settings


@lru_cache(maxsize=1)
def get_client() -> MongoClient:
    return MongoClient(settings.mongo_uri, serverSelectionTimeoutMS=5000)


def get_database() -> Database:
    return get_client()[settings.mongo_db]


def get_collection(name: str) -> Collection:
    return get_database()[name]


def ping() -> bool:
    get_client().admin.command("ping")
    return True
