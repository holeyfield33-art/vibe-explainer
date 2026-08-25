import anthropic
import chromadb

client = anthropic.Anthropic()
chroma_client = chromadb.Client()
collection = chroma_client.get_or_create_collection("docs")


def answer(query: str) -> str:
    results = collection.similarity_search(query, k=4)
    context = "\n".join(r.page_content for r in results)
    prompt_template = f"Answer using only this context:\n{context}\n\nQuestion: {query}"
    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=500,
        messages=[{"role": "user", "content": prompt_template}],
    )
    return response.content[0].text
