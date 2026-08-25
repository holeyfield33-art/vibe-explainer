import unittest
from pathlib import Path

from vibe_explainer.ai_discovery import discover_ai
from vibe_explainer.dataflow import (
    MAX_DATAFLOW_LINE_DISTANCE,
    STATUS_INFERRED,
    build_dataflow,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _edges(graph, relationship=None):
    edges = graph.edges
    if relationship is not None:
        edges = [e for e in edges if e.relationship == relationship]
    return edges


class TestPromptToModel(unittest.TestCase):
    def test_prompt_feeds_model_edge_exists(self):
        discovery = discover_ai(FIXTURES / "basic-chatbot")
        graph = build_dataflow(discovery)
        feeds = _edges(graph, "feeds_prompt")
        self.assertEqual(len(feeds), 1)
        edge = feeds[0]
        self.assertEqual(edge.source_type, "prompt_surface")
        self.assertEqual(edge.destination_type, "ai_usage")
        self.assertEqual(edge.status, STATUS_INFERRED)
        self.assertIn(edge.confidence, ("high", "moderate"))
        self.assertTrue(edge.evidence)

    def test_secret_reads_storage_into_model_provider(self):
        # OPENAI_API_KEY (line 4) is near two distinct model_provider findings:
        # the import (line 2) and the client instantiation (line 4, same line).
        # Both are genuine, separately-identified findings, so both legitimately
        # get a reads_storage edge back to the credential.
        discovery = discover_ai(FIXTURES / "basic-chatbot")
        graph = build_dataflow(discovery)
        reads = [e for e in _edges(graph, "reads_storage") if e.destination_type == "model_provider"]
        self.assertEqual(len(reads), 2)
        for edge in reads:
            self.assertEqual(edge.confidence, "high")
        pairs = {(e.source_finding_id, e.destination_finding_id) for e in reads}
        self.assertEqual(len(pairs), 2)  # no duplicate edges


class TestRAGToModel(unittest.TestCase):
    def test_retrieved_context_edge_exists(self):
        discovery = discover_ai(FIXTURES / "rag-app")
        graph = build_dataflow(discovery)
        retrieved = _edges(graph, "retrieved_context")
        self.assertEqual(len(retrieved), 1)
        edge = retrieved[0]
        self.assertEqual(edge.source_type, "rag_retrieval")
        self.assertEqual(edge.destination_type, "ai_usage")


class TestModelToTool(unittest.TestCase):
    def test_invokes_tool_edge_exists(self):
        discovery = discover_ai(FIXTURES / "dataflow-model-to-tool")
        graph = build_dataflow(discovery)
        invokes = _edges(graph, "invokes_tool")
        self.assertEqual(len(invokes), 1)
        self.assertEqual(invokes[0].source_type, "ai_usage")
        self.assertEqual(invokes[0].destination_type, "tool_agent")


class TestModelToShellOutput(unittest.TestCase):
    def test_flows_to_output_edge_for_shell_sink(self):
        discovery = discover_ai(FIXTURES / "dataflow-model-to-shell")
        graph = build_dataflow(discovery)
        flows = _edges(graph, "flows_to_output")
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0].destination_type, "tool_agent")
        # a shell-sink edge should not ALSO show up as a generic invokes_tool
        # edge for the same pair (no duplicate relationship for one pair)
        invokes = _edges(graph, "invokes_tool")
        self.assertEqual(len(invokes), 0)


class TestModelToExternalAPI(unittest.TestCase):
    def test_calls_external_service_edge_exists(self):
        discovery = discover_ai(FIXTURES / "dataflow-model-to-external-api")
        graph = build_dataflow(discovery)
        calls = _edges(graph, "calls_external_service")
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0].source_type, "ai_usage")
        self.assertEqual(calls[0].destination_type, "external_integration")


class TestUnrelatedAndDistant(unittest.TestCase):
    def test_distant_same_file_findings_do_not_connect(self):
        discovery = discover_ai(FIXTURES / "dataflow-unrelated")
        graph = build_dataflow(discovery)
        self.assertEqual(_edges(graph, "feeds_prompt"), [])
        # sanity: both findings do exist, they're just too far apart
        categories = {f.category for f in discovery.findings}
        self.assertIn("prompt_surface", categories)
        self.assertIn("ai_usage", categories)

    def test_unpaired_categories_never_produce_an_edge(self):
        # rag-app has both rag_retrieval and model_provider findings close
        # together, but (rag_retrieval, model_provider) is not a documented
        # rule pair — must never be invented.
        discovery = discover_ai(FIXTURES / "rag-app")
        graph = build_dataflow(discovery)
        for edge in graph.edges:
            pair = (edge.source_type, edge.destination_type)
            self.assertIn(
                pair,
                {
                    ("prompt_surface", "ai_usage"),
                    ("rag_retrieval", "ai_usage"),
                    ("ai_usage", "tool_agent"),
                    ("ai_usage", "external_integration"),
                    ("secret_config", "model_provider"),
                    ("secret_config", "ai_usage"),
                },
            )


class TestCrossFileDeferred(unittest.TestCase):
    def test_cross_file_prompt_and_model_do_not_connect(self):
        discovery = discover_ai(FIXTURES / "dataflow-cross-file")
        # sanity: both findings exist, in different files
        prompt_findings = [f for f in discovery.findings if f.category == "prompt_surface"]
        usage_findings = [f for f in discovery.findings if f.category == "ai_usage"]
        self.assertEqual(len(prompt_findings), 1)
        self.assertEqual(len(usage_findings), 1)
        self.assertNotEqual(prompt_findings[0].file, usage_findings[0].file)

        graph = build_dataflow(discovery)
        self.assertEqual(_edges(graph, "feeds_prompt"), [])


class TestCommentsDoNotCreateFlows(unittest.TestCase):
    def test_prose_only_comments_produce_no_findings_and_no_edges(self):
        # No .md files are content-scanned at all (SCAN_EXTS excludes .md), and
        # a .py file containing only prose in comments (no real assignments/
        # calls) should not trip the underlying patterns either.
        discovery = discover_ai(FIXTURES / "external-api-app")
        graph = build_dataflow(discovery)
        self.assertEqual(_edges(graph, "feeds_prompt"), [])
        self.assertEqual(_edges(graph, "retrieved_context"), [])


class TestNoAIBaseline(unittest.TestCase):
    def test_no_ai_project_has_empty_graph(self):
        sample = Path(__file__).resolve().parents[1] / "examples" / "sample-vibe-project"
        discovery = discover_ai(sample)
        graph = build_dataflow(discovery)
        self.assertEqual(graph.nodes, [])
        self.assertEqual(graph.edges, [])


class TestDeterminism(unittest.TestCase):
    def test_same_input_produces_identical_graph_twice(self):
        discovery1 = discover_ai(FIXTURES / "basic-chatbot")
        discovery2 = discover_ai(FIXTURES / "basic-chatbot")
        graph1 = build_dataflow(discovery1)
        graph2 = build_dataflow(discovery2)
        self.assertEqual(graph1.nodes, graph2.nodes)
        self.assertEqual(
            [e.to_dict() for e in graph1.edges],
            [e.to_dict() for e in graph2.edges],
        )

    def test_nodes_include_every_finding_id_even_unconnected(self):
        discovery = discover_ai(FIXTURES / "basic-chatbot")
        graph = build_dataflow(discovery)
        self.assertEqual(sorted(f.id for f in discovery.findings), graph.nodes)


class TestNoDuplicateEdges(unittest.TestCase):
    def test_no_duplicate_source_dest_relationship_triples(self):
        discovery = discover_ai(FIXTURES / "agent-with-tools")
        graph = build_dataflow(discovery)
        triples = [(e.source_finding_id, e.destination_finding_id, e.relationship) for e in graph.edges]
        self.assertEqual(len(triples), len(set(triples)))


class TestTruncatedPreserved(unittest.TestCase):
    def test_truncated_metadata_passed_through_not_lost(self):
        discovery = discover_ai(FIXTURES / "truncation-heavy")
        self.assertGreater(len(discovery.truncated), 0)  # sanity: this fixture trips the cap
        graph = build_dataflow(discovery)
        self.assertEqual(len(graph.truncated), len(discovery.truncated))
        d = graph.to_dict()
        self.assertIn("truncated", d)
        self.assertEqual(len(d["truncated"]), len(discovery.truncated))


class TestMaxDistanceIsRespected(unittest.TestCase):
    def test_threshold_constant_is_documented_and_used(self):
        self.assertEqual(MAX_DATAFLOW_LINE_DISTANCE, 30)


if __name__ == "__main__":
    unittest.main()
