"""Synthetic review input; never execute or install this example."""
import os
from anthropic import Anthropic
from langchain_chroma import Chroma

client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
store = Chroma(collection_name="approved_documents")


def answer(question):
    documents = store.similarity_search(question)
    prompt_template = f"Use the retrieved context: {documents}. Question: {question}"
    response = client.messages.create(
        model="example-model", max_tokens=100,
        messages=[{"role": "user", "content": prompt_template}],
    )
    return response.content
