"""Minimal RAG vector-store wiring that mirrors the audit leak shape:

a live database credential embedded on the SAME source line as AI-relevant
code (the vector-DB connection used for retrieval-augmented generation).
"""

import openai
import sqlalchemy

# The connection string carries a real-looking password (with an embedded '@')
# on the same line the scanner picks up as an "SQL database client" evidence hit.
engine = sqlalchemy.create_engine("postgresql://vectoradmin:Sup3r@Secret@vectordb.internal:5432/embeddings")

# A second same-line leak shape: bare keyword assignment next to model config.
DB_PASSWORD = "Pl4inTextVectorDbPass"


def embed_and_store(text: str):
    vector = openai.embeddings.create(model="text-embedding-3-small", input=text)
    with engine.connect() as conn:
        conn.execute(sqlalchemy.text("INSERT INTO embeddings (v) VALUES (:v)"), {"v": vector})
