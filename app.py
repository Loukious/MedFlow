from __future__ import annotations

from glob import glob
from pathlib import Path

import streamlit as st

from medflow_graph.memory import GraphStore, ingest_campaign_report
from medflow_ti.agents import AGENTS, answer_question
from medflow_ti.config import load_settings
from medflow_ti.embeddings import embedding_device
from medflow_ti.vector_store import COLLECTIONS, client, query


COLLECTION_GROUPS = {
    "All Knowledge Bases": list(COLLECTIONS),
    "Red Team Knowledge": ["redteam_db", "attack_db", "actor_db"],
    "Threat Intelligence Knowledge": ["attack_db", "actor_db", "detection_db", "redteam_db"],
    "ATT&CK Techniques": ["attack_db"],
    "Red Team Procedures": ["redteam_db"],
    "Actors, Malware, Tools": ["actor_db"],
    "Detection & Mitigation": ["detection_db"],
}


st.set_page_config(page_title="MedFlow Threat Intelligence", layout="wide")
st.title("MedFlow Threat Intelligence")

settings = load_settings()
with st.sidebar:
    st.caption(f"Embedding device: {embedding_device()}")
    mode = st.radio("Mode", ["Ask Agent", "Search Knowledge Base", "Graph Memory"])
    agent_labels = {
        "redteam": "Red Team Agent",
        "threat_intel": "Threat Intelligence Agent",
    }
    if mode == "Ask Agent":
        selected_label = st.selectbox("Agent", [agent_labels[name] for name in sorted(AGENTS)])
        agent = {label: name for name, label in agent_labels.items()}[selected_label]
        provider_label = st.selectbox("LLM Provider", ["Llama 3.1 8B", "Qwen 3 32B"])
        provider = "qwen" if provider_label.startswith("Qwen") else "llama"
    elif mode == "Search Knowledge Base":
        selected_group = st.selectbox("Knowledge Base", list(COLLECTION_GROUPS))
        show_full_text = st.checkbox("Show full result text", value=False)
    else:
        graph_path = st.text_input("Graph Memory Path", value="data/graph/medflow_graph.json")
        graph_show_context = st.checkbox("Show graph context", value=True)
    n_results = st.slider("Retrieved sources", 3, 12, 8)
    if st.button("Refresh DB Status"):
        st.session_state["status"] = True
    db = client(settings.chroma_dir)
    for collection in db.list_collections():
        st.metric(collection.name, collection.count())

default_query = "What SIEM rules detect MFA fatigue attacks against hospital portals?"
if mode == "Graph Memory":
    default_query = "packet capture exposure web route capability validation"
question = st.text_area("Question" if mode == "Ask Agent" else "Search Query", value=default_query, height=110)

button_label = "Ask" if mode == "Ask Agent" else "Search"
if st.button(button_label, type="primary") and question.strip():
    if mode == "Search Knowledge Base":
        collections = COLLECTION_GROUPS[selected_group]
        with st.spinner("Searching vector knowledge bases..."):
            hits = query(settings.chroma_dir, collections, question.strip(), settings.embedding_model, n_results=n_results)
        rows = []
        for rank, hit in enumerate(hits, 1):
            meta = hit.get("metadata") or {}
            distance = hit.get("distance")
            score = hit.get("score")
            if score is None and distance is not None:
                score = 1 / (1 + float(distance))
            rows.append(
                {
                    "Rank": rank,
                    "Score": None if score is None else round(float(score), 3),
                    "Collection": hit["collection"],
                    "MITRE ID": meta.get("mitre_id", ""),
                    "Name": meta.get("name", ""),
                    "URL": meta.get("url", ""),
                }
            )
        st.dataframe(rows, use_container_width=True, hide_index=True)
        for rank, hit in enumerate(hits, 1):
            meta = hit.get("metadata") or {}
            title = " ".join(x for x in [meta.get("mitre_id", ""), meta.get("name", "")] if x).strip()
            with st.expander(f"{rank}. {hit['collection']} · {title or hit['id']}"):
                if meta.get("url"):
                    st.markdown(meta["url"])
                st.markdown(hit["document"] if show_full_text else hit["document"][:1600])
        st.stop()

    if mode == "Graph Memory":
        store = GraphStore.load(Path(graph_path))
        hits = store.search(question.strip(), limit=n_results)
        st.subheader("Graph Summary")
        st.dataframe([store.summary()], use_container_width=True, hide_index=True)
        rows = [
            {
                "Rank": rank,
                "Score": hit["score"],
                "Type": hit["type"],
                "Name": hit["name"],
                "Sources": ", ".join(hit.get("source_ids") or []),
            }
            for rank, hit in enumerate(hits, 1)
        ]
        st.subheader("Search Results")
        st.dataframe(rows, use_container_width=True, hide_index=True)
        for rank, hit in enumerate(hits, 1):
            with st.expander(f"{rank}. {hit['type']} · {hit['name']}"):
                st.json(hit.get("attributes") or {})
                if graph_show_context:
                    st.markdown(hit.get("context") or "")
        st.stop()

    with st.spinner(f"Retrieving ATT&CK evidence and asking {provider_label}..."):
        result = answer_question(settings, agent, question.strip(), n_results=n_results, provider=provider)
    st.markdown(result.answer)
    with st.expander("Sources"):
        for hit in result.sources:
            meta = hit.get("metadata") or {}
            st.markdown(
                f"**{hit['collection']}** · `{meta.get('mitre_id', '')}` · "
                f"{meta.get('name', '')} · {meta.get('url', '')}"
            )
            st.caption(hit["document"][:1200])

if mode == "Graph Memory":
    st.divider()
    st.subheader("Ingest Campaign Reports")
    pattern = st.text_input("Report glob", value="reports/redteam_campaign/*.json")
    run_dream = st.checkbox("Run dedup cleanup after ingest", value=True)
    if st.button("Ingest Reports"):
        store = GraphStore.load(Path(graph_path))
        totals = {"created": 0, "merged": 0, "review": 0, "edges": 0}
        matched = [Path(item) for item in glob(pattern)]
        for report in matched:
            stats = ingest_campaign_report(store, report)
            for key, value in stats.items():
                totals[key] = totals.get(key, 0) + value
        dedup = store.dream_dedup() if run_dream else {"merged": 0, "reviews_added": 0}
        store.save()
        st.success(f"Ingested {len(matched)} report(s).")
        st.json({"ingest": totals, "dedup": dedup, "summary": store.summary()})
