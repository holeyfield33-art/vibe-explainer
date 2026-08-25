// Real-world TS idiom: call OpenAI via raw fetch, not the SDK.
export class OpenAIProvider {
  private apiKey: string
  private model: string
  constructor() {
    this.apiKey = process.env.AI_API_KEY || ''
    this.model = process.env.AI_MODEL || 'gpt-3.5-turbo'
  }
  async complete(prompt: string) {
    const response = await fetch(`https://api.openai.com/v1/chat/completions`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${this.apiKey}` },
      body: JSON.stringify({
        model: this.model,
        messages: [{ role: 'user', content: prompt }],
      }),
    })
    return response.json()
  }
}
