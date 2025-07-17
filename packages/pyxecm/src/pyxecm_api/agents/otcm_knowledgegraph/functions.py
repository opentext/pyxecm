"""Function to build a knowledge graph from the OTCS object."""

import logging
import time
from datetime import UTC, datetime

from pyxecm_customizer.knowledge_graph import KnowledgeGraph

from pyxecm_api.common.functions import get_otcs_object

logger = logging.getLogger("pyxecm_api.agent.otcm_knowledge_graph")

KNOWLEDGEGRAPH_OBJECT: KnowledgeGraph = None
KNOWLEDGEGRAPH_ONTOLOGY = {
    ("Vendor", "Material", "child"): ["offers", "supplies", "provides"],
    ("Vendor", "Purchase Order", "child"): ["supplies", "provides"],
    ("Vendor", "Purchase Contract", "child"): ["signs", "owns"],
    ("Material", "Vendor", "parent"): ["is supplied by"],
    ("Purchase Order", "Material", "child"): ["includes", "is part of"],
    ("Customer", "Sales Order", "child"): ["has ordered"],
    ("Customer", "Sales Contract", "child"): ["signs", "owns"],
    ("Sales Order", "Customer", "parent"): ["belongs to", "is initiated by"],
    ("Sales Order", "Material", "child"): ["includes", "consists of"],
    ("Sales Order", "Delivery", "child"): ["triggers", "is followed by"],
    ("Sales Order", "Production Order", "child"): ["triggers", "is followed by"],
    ("Sales Contract", "Material", "child"): ["includes", "consists of"],
    ("Production Order", "Material", "child"): ["includes", "consists of"],
    ("Production Order", "Delivery", "child"): ["triggers", "is followed by"],
    ("Production Order", "Goods Movement", "child"): ["triggers", "is followed by"],
    ("Delivery", "Goods Movement", "child"): ["triggers", "is followed by"],
    ("Delivery", "Material", "child"): ["triggers", "is followed by"],
}


def build_graph() -> None:
    """Build the knowledgeGraph. And keep it updated every hour."""

    def build() -> None:
        knowledge_graph = KnowledgeGraph(otcs_object=get_otcs_object(), ontology=KNOWLEDGEGRAPH_ONTOLOGY)

        start_time = datetime.now(UTC)
        result = knowledge_graph.build_graph(
            workspace_type_exclusions=None,
            workspace_type_inclusions=[
                "Vendor",
                "Purchase Contract",
                "Purchase Order",
                "Material",
                "Customer",
                "Sales Order",
                "Sales Contract",
                "Delivery",
                "Goods Movement",
            ],
            workers=20,
            filter_at_traversal=True,  # also filter for workspace types if following relationships
            relationship_types=["child"],  # only go from parent to child
            strategy="BFS",
            metadata=False,
        )
        end_time = datetime.now(UTC)
        logger.info(
            "Knowledge Graph completed in %s. Processed %d workspace nodes and traversed %d workspace relationships.",
            str(end_time - start_time),
            result["processed"],
            result["traversed"],
        )

        global KNOWLEDGEGRAPH_OBJECT  # noqa: PLW0603
        KNOWLEDGEGRAPH_OBJECT = knowledge_graph

    while True:
        logger.info("Building knowledge graph...")
        build()
        logger.info("Knowledge graph build complete. Waiting for 1 hour before rebuilding...")
        time.sleep(3600)


###


def get_knowledgegraph_object() -> KnowledgeGraph:
    """Get the OTCA object."""

    return KNOWLEDGEGRAPH_OBJECT
