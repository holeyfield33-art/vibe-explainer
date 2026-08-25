import unittest
from pathlib import Path

from vibe_explainer.ai_discovery import discover_ai
from vibe_explainer.attack_surface import BUCKETS, build_attack_surface

FIXTURES = Path(__file__).resolve().parent / "fixtures"


class TestAttackSurfaceBucketing(unittest.TestCase):
    def test_chatbot_buckets(self):
        discovery = discover_ai(FIXTURES / "basic-chatbot")
        surface = build_attack_surface(discovery)
        by_bucket = surface.by_bucket()

        model_names = {i.name for i in by_bucket["model"]}
        self.assertIn("OpenAI", model_names)
        self.assertIn("Chat/completions call", model_names)

        input_names = {i.name for i in by_bucket["inputs"]}
        self.assertIn("System prompt variable", input_names)

        storage_names = {i.name for i in by_bucket["storage"]}
        self.assertIn("Model API key env var", storage_names)

    def test_rag_app_populates_retrieval_bucket(self):
        discovery = discover_ai(FIXTURES / "rag-app")
        surface = build_attack_surface(discovery)
        by_bucket = surface.by_bucket()
        self.assertGreater(len(by_bucket["retrieval"]), 0)

    def test_mcp_and_agent_tools_populate_tools_bucket(self):
        discovery = discover_ai(FIXTURES / "mcp-server")
        surface = build_attack_surface(discovery)
        by_bucket = surface.by_bucket()
        self.assertGreater(len(by_bucket["tools"]), 0)

        discovery2 = discover_ai(FIXTURES / "agent-with-tools")
        surface2 = build_attack_surface(discovery2)
        by_bucket2 = surface2.by_bucket()
        self.assertGreater(len(by_bucket2["tools"]), 0)

    def test_webhook_routes_to_inputs_other_integrations_route_to_tools(self):
        discovery = discover_ai(FIXTURES / "external-api-app")
        surface = build_attack_surface(discovery)
        by_bucket = surface.by_bucket()
        input_names = {i.name for i in by_bucket["inputs"]}
        tool_names = {i.name for i in by_bucket["tools"]}
        self.assertIn("Webhook handler", input_names)
        self.assertIn("HTTP client call", tool_names)

    def test_every_item_has_a_relevance_note(self):
        discovery = discover_ai(FIXTURES / "hardcoded-credential")
        surface = build_attack_surface(discovery)
        self.assertGreater(len(surface.items), 0)
        for item in surface.items:
            self.assertTrue(item.security_relevance)

    def test_all_buckets_present_in_to_dict_even_when_empty(self):
        discovery = discover_ai(FIXTURES / "basic-chatbot")
        surface = build_attack_surface(discovery)
        d = surface.to_dict()
        self.assertEqual(set(d["buckets"].keys()), set(BUCKETS))
        self.assertEqual(set(d["summary"].keys()), set(BUCKETS))
        # outputs bucket is an intentional gap in this phase (see attack_surface.py docstring)
        self.assertEqual(d["summary"]["outputs"], 0)


    def test_items_trace_back_to_source_finding_id(self):
        discovery = discover_ai(FIXTURES / "basic-chatbot")
        surface = build_attack_surface(discovery)
        finding_ids = {f.id for f in discovery.findings}
        for item in surface.items:
            self.assertTrue(item.finding_id)
            self.assertIn(item.finding_id, finding_ids)

    def test_dataflow_not_attached_by_default(self):
        discovery = discover_ai(FIXTURES / "basic-chatbot")
        surface = build_attack_surface(discovery)
        self.assertIsNone(surface.dataflow)
        self.assertNotIn("dataflow", surface.to_dict())

    def test_dataflow_attached_when_requested(self):
        discovery = discover_ai(FIXTURES / "basic-chatbot")
        surface = build_attack_surface(discovery, include_dataflow=True)
        self.assertIsNotNone(surface.dataflow)
        d = surface.to_dict()
        self.assertIn("dataflow", d)
        self.assertIn("edges", d["dataflow"])
        # existing bucket behavior is unchanged when dataflow is attached
        self.assertEqual(set(d["buckets"].keys()), set(BUCKETS))


if __name__ == "__main__":
    unittest.main()
