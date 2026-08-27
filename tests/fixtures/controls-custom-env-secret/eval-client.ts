// Minimal version of the aegis-provenance llm-eval.ts:679 shape: a custom-
// named credential env var (not one of the fixed provider names) supplied
// via process.env, used to call a model endpoint.
const apiKey = process.env.AEGIS_EVAL_API_KEY?.trim();

export async function callModel(prompt: string) {
  const response = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: { Authorization: `Bearer ${apiKey}` },
    body: JSON.stringify({ messages: [{ role: 'user', content: prompt }] }),
  });
  return response.json();
}
