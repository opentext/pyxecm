"""Knowledge Graph Module to implement a class to build and maintain and knowledge graph.

The knowledge graph consists of the OTCS workspaces and their relationships.
"""

__author__ = "Dr. Marc Diefenbruch"
__copyright__ = "Copyright (C) 2024-2025, OpenText"
__credits__ = ["Kai-Philip Gatzweiler"]
__maintainer__ = "Dr. Marc Diefenbruch"
__email__ = "mdiefenb@opentext.com"

import logging
from collections import deque

from pyxecm import OTCS
from pyxecm.helper import Data
from pyxecm.helper.otel_config import tracer

APP_NAME = "pyxecm"
MODULE_NAME = APP_NAME + ".customizer.knowledge_graph"
OTEL_TRACING_ATTRIBUTES = {"class": "knowledge_graph"}

default_logger = logging.getLogger(MODULE_NAME)


class KnowledgeGraph:
    """Used to build and maintain a Knowledge Graph for the OTCS workspaces."""

    logger: logging.Logger = default_logger

    WORKSPACE_ID_FIELD = "id"
    WORKSPACE_NAME_FIELD = "name"
    WORKSPACE_TYPE_FIELD = "wnf_wksp_type_id"

    def __init__(self, otcs_object: OTCS, ontology: dict[tuple[str, str, str], list[str]] | None = None) -> None:
        """Initialize the Knowledge Graph.

        Args:
            otcs_object (OTCS):
                An instance of the OTCS class providing access to workspace data.
            ontology (dict[tuple[str, str, str], list[str]]):
                A dictionary mapping (source_type, target_type, rel_type) tuples
                to a list of semantic relationship names. source_type and target_type
                are workspace type names from OTCS. rel_type is either "parent" or "child".
                It abstracts the graph structure at the type level.

        Example:
            ontology = {
                ("Vendor", "Material", "child"): ["offers", "supplies", "provides"],
                ("Vendor", "Purchase Order", "child"): ["receives", "fulfills"],
                ("Vendor", "Purchase Contract", "child"): ["signs", "owns"],
                ("Material", "Vendor", "parent"): ["is supplied by", "is offered by"],
                ("Purchase Order", "Material", "child"): ["includes", "consists of"],
                ("Customer", "Sales Order", "child"): ["orders", "issues", "sends"],
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

        """

        # The OTCS object to traverse the workspaces and workspace relationships:
        self._otcs = otcs_object

        # The ontology abstracts the graph structure at the type level:
        self._ontology: dict[tuple[str, str, str], list[str]] = ontology if ontology else {}
        self._type_graph = self.build_type_graph()
        self._type_graph_inverted = self.invert_type_graph(self._type_graph)

        # This include the pandas data frames for the node and edge INSTANCES:
        self._nodes = Data()  # columns=["id", "name", "type"])
        self._edges = Data()  # (columns=["source", "target", "relationship"])

        # Create a simple dictionary with all workspace types to easily
        # lookup the workspace type name (value) by the workspace type ID (key):
        workspace_types = self._otcs.get_workspace_types()
        self.workspace_types = {
            wt["data"]["properties"]["wksp_type_id"]: wt["data"]["properties"]["wksp_type_name"]
            for wt in workspace_types["results"]
        }

    # end method definition

    def get_nodes(self) -> Data:
        """Return the graph nodes as a Data object.

        Returns:
            Data:
                Data object with embedded Pandas data frame for the nodes of the Knowledge Graph.

        """

        return self._nodes

    # end method definition

    def get_edges(self) -> Data:
        """Return the graph edges as a Data object.

        Returns:
            Data:
                Data object with embedded Pandas data frame for the edges of the Knowledge Graph.

        """

        return self._edges

    # end method definition

    def get_otcs_object(self) -> OTCS:
        """Return the OTCS object.

        Returns:
            OTCS:
                OTCS object.

        """

        return self._otcs

    # end method definition

    def get_ontology(self) -> dict[tuple[str, str, str], list[str]] | None:
        """Return the graph ontology.

        Returns:
            dict[tuple[str, str, str], list[str]] | None:
                Defined ontology for the knowledge graph.

        """

        return self._ontology

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="build_type_graph")
    def build_type_graph(self, directions: list | None = None) -> dict[str, set[str]]:
        """Construct a directed type-level graph from the ontology.

        This uses the ontology's (source_type, target_type, direction) keys to build
        a forward graph of type relationships, avoiding duplicates.

        Args:
            directions (list | None, optional):
                Which directions the edges should be traversed: "child", "parent", or both.
                Default is ["child"].

        Returns:
            dict[str, set[str]]:
                A dictionary mapping each entity type to a list of connected types
                based on child/parent ontology relationships.

        Example:
            Input:
                {
                    ("Vendor", "Material", "child"): ["supplies"],
                    ("Material", "Vendor", "parent"): ["is supplied by"]
                }
            Output:
                {
                    "Vendor": {"Material"},
                    "Material": {"Vendor"}
                }

        """

        type_graph = {}

        if directions is None:
            directions = ["child"]

        # To avoid duplicate entries, we use a set during graph construction to
        # ensure each target type appears only once per source type.
        # Then convert it back to a list at the end.
        for source_type, target_type, direction in self._ontology:
            # Determine the forward (parent-chld) direction
            if direction == "child" and "child" in directions:
                from_type, to_type = source_type, target_type
                # Add forward edge
                type_graph.setdefault(from_type, set()).add(to_type)
            elif direction == "parent" and "parent" in directions:
                from_type, to_type = target_type, source_type
                # Add reverse edge to allow backward traversal
                type_graph.setdefault(to_type, set()).add(from_type)
            else:
                continue  # ignore unknown directions

        return type_graph

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="invert_type_graph")
    def invert_type_graph(self, type_graph: dict) -> dict[str, set[str]]:
        """Invert the provided type graph, meaning invert the relationships (edges) in the graph.

        Args:
            type_graph (dict):
                Existing type graph that should be inverted.

        Returns:
            dict[str, set[str]]:
                A new inverted type graph.

        """

        type_graph_inverted = {}

        for start_type, target_types in type_graph.items():
            for target_type in target_types:
                if target_type not in type_graph_inverted:
                    type_graph_inverted[target_type] = set()
                type_graph_inverted[target_type].add(start_type)

        return type_graph_inverted

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="build_type_pathes")
    def build_type_pathes(
        self,
        source_type: str,
        target_type: str,
        direction: str = "child",
    ) -> list[list[str]]:
        """Find all possible paths (acyclic) from start to target type.

        Args:
            source_type:
                The source type (e.g., 'Material').
            target_type:
                The target type (e.g., 'Customer').
            direction (str, optional):
                Either "child" (source_id to target_id) or "parent" (target_id to source_id).
                "child" is the default.

        Returns:
            list[list[str]]:
                List of paths (each a list of types), all acyclic.

        """

        if source_type == target_type:
            return [[source_type]]

        # Do we want parent -> child or child -> parent?
        type_graph = self._type_graph if direction == "child" else self._type_graph_inverted

        all_pathes = []
        stack = [(source_type, [source_type])]  # (current_type, path_so_far)

        while stack:
            current, path = stack.pop()

            for neighbor in type_graph.get(current, []):
                if neighbor in path:
                    continue  # avoid cycles
                new_path = path + [neighbor]
                if neighbor == target_type:
                    all_pathes.append(new_path)
                else:
                    stack.append((neighbor, new_path))

        return all_pathes

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="build_graph")
    def build_graph(
        self,
        workspace_type_exclusions: str | list | None = None,
        workspace_type_inclusions: str | list | None = None,
        filter_at_traversal: bool = False,
        relationship_types: list | None = None,
        metadata: bool = False,
        workers: int = 3,
        strategy: str = "BFS",
        max_depth: int | None = None,
        timeout: float = 60.0,
    ) -> dict:
        """Build the knowledge graph by traversing all workspaces and their relationships.

        Args:
            workspace_type_exclusions (str | list | None, optional):
                List of workspace types to exclude. Can be a single workspace type
                or a list of workspace types. None = inactive.
            workspace_type_inclusions (str | list | None, optional):
                List of workspace types to include. Can be a single workspace type
                or a list of workspace types. None = inactive.
            filter_at_traversal (bool, optional):
                If False (default) the inclusion and exclusion filters are only tested for the
                queue initialization not the traversal via workspace relationships.
                If True the inclusion and exclusion filters are also tested
                during the traversal of workspace relationships.
            relationship_types (list | None, optional):
                The default that will be established if None is provided is ["child", "parent"].
            metadata (bool, optional):
                If True, metadata for the workspace nodes will be included.
            workers (int, optional):
                The number of parallel working threads. Defaults to 3.
            strategy (str, optional):
                Either "DFS" for Depth First Search, or "BFS" for Breadth First Search.
                "BFS" is the default.
            max_depth (int | None, optional):
                The maximum traversal depth. Defaults to None = unlimited.
            timeout (float, optional):
                Wait time for the queue to have items. This is also the time it
                takes at the end to detect the workers are done. So expect delay
                if you raise it high!

        Returns:
            dict:
                The number of traversed and processed workspaces.

        """

        @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="build_node")
        def build_node(workspace_node: dict, metadata: bool = False, **kwargs: dict) -> tuple[bool, bool]:
            """Add a node to the Knowledge Graph by inserting into the nodes data frame.

            This method will be called back from the OTCS traverse_workspaces_parallel()
            for each traversed workspace node.

            Args:
                workspace_node (dict):
                    The workspace node.
                kwargs (dict):
                    Optional additional parameters.
                metadata (bool, optional):
                    If True, metadata for the workspace nodes will be included.

            Returns:
                bool:
                    Whether or not the operation was successful.
                bool:
                    Whether or not we require further traversal.

            """

            workspace_id = self._otcs.get_result_value(response=workspace_node, key=self.WORKSPACE_ID_FIELD)
            workspace_name = self._otcs.get_result_value(response=workspace_node, key=self.WORKSPACE_NAME_FIELD)
            workspace_type = self.workspace_types[
                self._otcs.get_result_value(response=workspace_node, key=self.WORKSPACE_TYPE_FIELD)
            ]
            data = {
                "id": workspace_id,
                "name": workspace_name,
                "type": workspace_type,
                **kwargs,  # ← allows adding more attributes from caller
            }
            if metadata:
                response = self._otcs.get_workspace(node_id=workspace_id, fields="categories", metadata=True)
                if response:
                    data["attributes"] = self._otcs.extract_category_data(node=response)
            with self._nodes.lock():
                self._nodes.append(data)
            return (True, True)

        @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="build_edge")
        def build_edge(
            workspace_node_from: dict, workspace_node_to: dict, rel_type: str = "child", **kwargs: dict | None
        ) -> tuple[bool, bool]:
            """Add an edge to the Knowledge Graph by inserting into the edges data frame.

            This method will be called back from the OTCS traverse_workspaces_parallel()
            for each traversed workspace relationship (edge).

            Args:
                workspace_node_from (dict):
                    The source workspace node.
                workspace_node_to (dict):
                    The target workspace node.
                rel_type (str, optional):
                    The relationship type ("child" or "parent").
                kwargs (dict, optional):
                    Optional additional parameters.

            Returns:
                bool:
                    Whether or not the operation was successful.
                bool:
                    Whether or not we require further traversal.

            """

            workspace_source_id = self._otcs.get_result_value(response=workspace_node_from, key=self.WORKSPACE_ID_FIELD)
            workspace_target_id = self._otcs.get_result_value(response=workspace_node_to, key=self.WORKSPACE_ID_FIELD)
            workspace_source_type = self._otcs.get_result_value(
                response=workspace_node_from, key=self.WORKSPACE_TYPE_FIELD
            )
            workspace_target_type = self._otcs.get_result_value(
                response=workspace_node_to, key=self.WORKSPACE_TYPE_FIELD
            )
            with self._edges.lock():
                self._edges.append(
                    {
                        "source_type": workspace_source_type,
                        "source_id": workspace_source_id,
                        "target_type": workspace_target_type,
                        "target_id": workspace_target_id,
                        "relationship_type": rel_type,
                        "relationship_semantics": self.get_semantic_labels(
                            source_type=self.workspace_types.get(workspace_source_type, workspace_source_type),
                            target_type=self.workspace_types.get(workspace_target_type, workspace_target_type),
                            rel_type=rel_type,
                        ),
                        **kwargs,  # ← allows adding more attributes from caller
                    }
                )
            return (True, True)

        #
        # Start the actual traversal algorithm in OTCS:
        #
        result = self._otcs.traverse_workspaces_parallel(
            workspace_type_exclusions=workspace_type_exclusions,
            workspace_type_inclusions=workspace_type_inclusions,
            filter_at_traversal=filter_at_traversal,
            node_executables=[build_node],
            relationship_executables=[build_edge],
            relationship_types=relationship_types,
            workers=workers,
            strategy=strategy,
            max_depth=max_depth,
            timeout=timeout,
            metadata=metadata,
        )

        return result

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="get_semantic_labels")
    def get_semantic_labels(self, source_type: str, target_type: str, rel_type: str) -> list:
        """Resolve semantic labels from the ontology.

        Args:
            source_type:
                Type of the source workspace.
            target_type:
                Type of the target workspace.
            rel_type:
                Raw relationship type. Either "parent" or "child".

        Returns:
            list:
                A list of semantic labels for the relationship.

        """

        key = (source_type, target_type, rel_type)

        # As fallback option we just return a 1-item list with the technical relationship name.
        return self._ontology.get(key, [rel_type])

    # end method definition

    @tracer.start_as_current_span(attributes=OTEL_TRACING_ATTRIBUTES, name="graph_query")
    def graph_query(
        self,
        source_type: str,
        source_value: str | int,
        target_type: str,
        target_value: str | int | None = None,
        max_hops: int | None = None,
        direction: str = "child",
        intermediate_types: list[str] | None = None,
        strict_intermediate_types: bool = False,
        ordered_intermediate_types: bool = False,
    ) -> set[tuple[str, int]]:
        """Find target entities by using the Knowledge Graph.

        Given a source entity (like Material:M-789), find target entities (like Customer)
        by traversing the graph in BFS manner.

        Args:
            source_type (str):
                Type of the starting node (e.g. "Material").
            source_value (str | int):
                The ID or name of the source node (e.g. "M-789").
            target_type (str):
                Desired result type (e.g. "Customer").
            target_value (str | int | None, optional):
                The value or name of the source node (e.g. "M-789").
            max_hops (int | None, optional):
                Limit on graph traversal depth. If None (default) there's no limit.
            direction (str, optional):
                Either "child" (source_id to target_id) or "parent" (target_id to source_id).
                "child" is the default.
            intermediate_types (list[str] | None, optional):
                Types that must be traversed.
            strict_intermediate_types (bool, optional):
                Only allow source + intermediate + target types in path.
            ordered_intermediate_types (bool, optional):
                Enforce order of intermediate types.

        Returns:
            set:
                Set of (name, id) tuples for matching nodes, e.g. {("Customer A", 123)}

        """

        # Keep the linter happy:
        _ = source_type, source_value

        # Get the nodes and edges of the Knowledge Graph:
        nodes_df = self.get_nodes().get_data_frame()
        edges_df = self.get_edges().get_data_frame()

        #
        # 1. Find the starting node
        #
        source_node = nodes_df[
            (nodes_df["type"] == source_type)
            & (nodes_df["name"].astype(str).str.contains(str(source_value), case=False, na=False, regex=False))
        ]
        if source_node.empty:
            return set()
        start_id = source_node.iloc[0]["id"]

        #
        # 2. Prepare the data structures for the BFS traversal:
        #
        visited = set()
        queue = deque([(start_id, 0, [])])  # (node_id, depth, path_types)
        results = set()
        # Cache of build_type_pathes results
        type_path_cache = {}

        #
        # 3. BFS from start_id to target_type:
        #
        while queue:
            # Get the next node from the traversal queue
            # (also updates the current depth and list of traversed types on the current path):
            current_id, current_depth, path_types = queue.popleft()

            # Check if the maximum depth is exceeded:
            if max_hops is not None and current_depth > max_hops:
                self.logger.info("Traversal has exceeded the given %d max hops!", max_hops)
                continue  # the while loop

            # Get the Knowledge Graph node row for the current ID:
            node_row = nodes_df[nodes_df["id"] == current_id]
            if node_row.empty:
                self.logger.error("Cannot find graph node with ID -> %d. This should never happen!", current_id)
                continue  # the while loop

            current_type = node_row.iloc[0]["type"]
            current_name = node_row.iloc[0]["name"]

            # Check if this node has been traversed before. If yes, skip.
            if current_id in visited:
                self.logger.debug(
                    "Node -> '%s' (%d) of type -> '%s' has been visited before!%s",
                    current_name,
                    current_id,
                    current_type,
                    " But we have requirements for intermediate types that need to be checked."
                    if intermediate_types
                    else " We don't need to further traverse from here.",
                )
                # If we don't have intermediate types then one path to a node is
                # sufficient and we can stop traversal here (otherwise we still
                # stop traversal but want to check if current node matches all requirements):
                if not intermediate_types:
                    continue  # the while loop

            # Simplified restriction: skip if current type is not allowed
            if (
                strict_intermediate_types
                and intermediate_types
                and current_type not in [source_type] + intermediate_types + [target_type]
            ):
                self.logger.debug(
                    "The current node type -> '%s' is not allowed for this query. Stop further traversals for this node.",
                    current_type,
                )
                continue  # the while loop

            # Update path types for tracking
            path_types = path_types + [current_type]

            # Check if current node matches target_type:
            if current_type == target_type:
                # Check intermediate type constraints:
                if intermediate_types:
                    if ordered_intermediate_types:
                        # Ordered check
                        index = 0
                        for t in path_types:
                            if t == intermediate_types[index]:
                                index += 1
                                if index == len(intermediate_types):
                                    break
                        if index != len(intermediate_types):
                            self.logger.debug(
                                "Target node -> '%s' (%d) has the right type -> '%s' but path -> %s has not traversed intermediate types -> %s in the right ordering",
                                current_name,
                                current_id,
                                target_type,
                                path_types,
                                intermediate_types,
                            )
                            continue  # Ordered constraint not fulfilled
                    elif not all(t in path_types for t in intermediate_types):
                        self.logger.debug(
                            "Target node -> '%s' (%d) has the right type -> '%s' but path -> %s has not traversed intermediate types -> %s",
                            current_name,
                            current_id,
                            target_type,
                            path_types,
                            intermediate_types,
                        )
                        continue  # the while loop because unordered constraint not fulfilled
                # end if intermediate_types:

                # This is the actual check for the target instance value:
                if (
                    target_value is not None
                    and target_value != current_name  # exact match
                    and target_value.lower() not in current_name.lower()  # partial match (substring)
                ):
                    self.logger.debug(
                        "Target node -> '%s' (%d) has the right type -> '%s' but not matching name or attributes (%s)",
                        current_name,
                        current_id,
                        target_type,
                        target_value,
                    )
                    continue

                results.add((current_name, current_id))
                self.logger.debug(
                    "Found node -> '%s' (%d) of desired target type -> '%s'%s%s",
                    current_name,
                    current_id,
                    target_type,
                    " and name or attributes -> {}".format(target_value) if target_value else "",
                    " via path -> {}.".format(path_types) if path_types else "",
                )
            # end if current_type == target_type:

            # We need to check this once more because if intermediate_types are specified
            # we need to continue until here...
            if current_id in visited:
                continue
            visited.add(current_id)

            # Get allowed neighbor types using cached paths
            if (current_type, target_type) not in type_path_cache:
                pathes = self.build_type_pathes(source_type=current_type, target_type=target_type, direction=direction)
                type_path_cache[(current_type, target_type)] = pathes
            else:
                pathes = type_path_cache[(current_type, target_type)]

            # Get allowed neighbor types from the type graph (pruning)
            neighbor_types = (
                set(self._type_graph.get(current_type, []))
                if direction == "child"
                else set(self._type_graph_inverted.get(current_type, []))
            )
            # Reduce that list to neighor types that are on a path to the target type:
            allowed_types = {
                allowed_type for allowed_type in neighbor_types if any(allowed_type in path for path in pathes)
            }

            removed_types = neighbor_types - allowed_types  # this is a set difference!
            if removed_types:
                self.logger.debug(
                    "Remove traverse options -> %s for type node -> '%s' as they are not leading towards target type -> '%s'. Remaining types to travers -> %s. Initial neighbor types -> %s",
                    str(removed_types),
                    current_type,
                    target_type,
                    str(allowed_types),
                    str(neighbor_types),
                )

            # Determine all neighbors (= list of target IDs derived from the edges).
            # The expression 'edges_df["source_id"] == current_id' creates a Boolean mask —
            # a Series of True or False values — indicating which rows of the edges_df DataFrame
            # have a source_id equal to the current_id.
            # The double brackets ([['target_id']]) are important to return a DataFrame (a 2D table)
            # and not just a series (column).
            if direction == "child":
                neighbors = edges_df[edges_df["source_id"] == current_id][["target_id"]]
                neighbor_ids = neighbors["target_id"].tolist()
            else:  # direction = "parent" - here we switch source and target:
                neighbors = edges_df[edges_df["target_id"] == current_id][["source_id"]]
                neighbor_ids = neighbors["source_id"].tolist()

            if neighbors.empty:
                continue

            # Get neighbor nodes with their types
            neighbor_rows = nodes_df[nodes_df["id"].isin(neighbor_ids)][["id", "type"]]

            # Filter neighbors by allowed types
            filtered_neighbors = [
                nid
                for nid in neighbor_rows.itertuples(index=False)
                if nid.type in allowed_types and nid.id not in visited
            ]

            # Travers edges from current node to neighbors:
            for neighbor in filtered_neighbors:
                queue.append((neighbor.id, current_depth + 1, path_types))
        # end while queue

        return results

    # end method definition
