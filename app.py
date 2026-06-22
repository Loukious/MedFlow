from __future__ import annotations

import streamlit as st

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
    mode = st.radio("Mode", ["Ask Agent", "Search Knowledge Base"])
    agent_labels = {
        "redteam": "Red Team Agent",
        "threat_intel": "Threat Intelligence Agent",
    }
    if mode == "Ask Agent":
        selected_label = st.selectbox("Agent", [agent_labels[name] for name in sorted(AGENTS)])
        agent = {label: name for name, label in agent_labels.items()}[selected_label]
        provider_label = st.selectbox("LLM Provider", ["Llama 3.1 8B", "Qwen 3 32B"])
        provider = "qwen" if provider_label.startswith("Qwen") else "llama"
    else:
        selected_group = st.selectbox("Knowledge Base", list(COLLECTION_GROUPS))
        show_full_text = st.checkbox("Show full result text", value=False)
    n_results = st.slider("Retrieved sources", 3, 12, 8)
    if st.button("Refresh DB Status"):
        st.session_state["status"] = True
    db = client(settings.chroma_dir)
    for collection in db.list_collections():
        st.metric(collection.name, collection.count())

question = st.text_area(
    "Question" if mode == "Ask Agent" else "Search Query",
    value="What SIEM rules detect MFA fatigue attacks against hospital portals?",
    height=110,
)

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
