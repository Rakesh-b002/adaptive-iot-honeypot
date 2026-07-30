"""Central configuration — reads from .env file."""

import os
from dataclasses import dataclass
from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class Settings:
    mongo_uri: str = os.getenv("MONGO_URI", "mongodb://localhost:27017")
    mongo_db: str = os.getenv("MONGO_DB", "cowrie")
    embedding_model: str = os.getenv("EMBEDDING_MODEL", "all-MiniLM-L6-v2")
    pca_components: int = int(os.getenv("PCA_COMPONENTS", "40"))
    isolation_forest_contamination: float = float(
        os.getenv("ISOLATION_FOREST_CONTAMINATION", "0.05")
    )


settings = Settings()
