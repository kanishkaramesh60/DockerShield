from __future__ import annotations

import streamlit as st
from streamlit_agraph import Config, Edge, Node, agraph


def render_attack_graph(paths: list[dict]) -> None:
    """Render an interactive attack-path graph."""

    if not paths:
        st.info("No attack paths available for visualization.")
        return

    st.subheader("Interactive Attack-Path Graph")

    path_options = {
        f"{path.get('path_id')} — {path.get('title')}": path
        for path in paths
    }

    selected_label = st.selectbox(
        "Select an attack path",
        list(path_options.keys()),
    )

    path = path_options[selected_label]

    nodes: list[Node] = []
    edges: list[Edge] = []

    path_id = path.get("path_id", "PATH")
    severity = path.get("severity", "HIGH")

    # Attack path node
    nodes.append(
        Node(
            id=path_id,
            label=path_id,
            size=30,
            shape="diamond",
        )
    )

    # Finding nodes
    matched_rules = path.get("matched_rules", [])

    for rule_id in matched_rules:
        nodes.append(
            Node(
                id=rule_id,
                label=rule_id,
                size=25,
                shape="box",
            )
        )

        edges.append(
            Edge(
                source=rule_id,
                target=path_id,
            )
        )

    # Impact node
    impact_id = f"{path_id}-IMPACT"

    nodes.append(
        Node(
            id=impact_id,
            label="Potential Security Impact",
            size=30,
            shape="ellipse",
        )
    )

    edges.append(
        Edge(
            source=path_id,
            target=impact_id,
        )
    )

    config = Config(
        width="100%",
        height=550,
        directed=True,
        physics=True,
        hierarchical=False,
        nodeHighlightBehavior=True,
        highlightColor="#F7A7A6",
        collapsible=False,
    )

    st.caption(
        f"Severity: {severity} | "
        f"Matched rules: {len(matched_rules)}"
    )

    agraph(
        nodes=nodes,
        edges=edges,
        config=config,
    )