import anthropic
import chromadb

ALLOWED_SOURCES = {"internal-docs", "verified-kb"}

client = anthropic.Anthropic()
chroma_client = chromadb.Client()
collection = chroma_client.get_or_create_collection("docs")


def verify_source(doc) -> bool:
    return doc.metadata.get("source") in ALLOWED_SOURCES


def answer(query: str) -> str:
    results = collection.similarity_search(query, k=4)
    trusted = [r for r in results if verify_source(r)]
    context = "\n".join(r.page_content for r in trusted)
    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=500,
        messages=[{"role": "user", "content": context}],
    )
    return response.content[0].text
