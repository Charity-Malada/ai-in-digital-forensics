import json
import pandas as pd
import plotly.graph_objects as go
import streamlit as st
from scoring import WEIGHT_PRESETS, compute_total_score, validate_tool_spec

st.set_page_config(page_title="Technical Performance Evaluation Framework", layout="wide")
st.title("Technical Performance Evaluation Framework")
st.caption("Input layer -> Evaluation engine -> Output layer")


with st.expander("About this tool: what is being measured?", expanded=True):
    st.markdown("""
**Purpose.** This tool compares network intrusion detection systems (NIDS), which are tools that spot cyberattacks on a network.
It is part of an Honours research project at the University of the Western Cape.
 
**How it works.** Each tool gets 0 to 25 points on four measures, giving a total out of 100.
Use the sidebar to change how much each measure matters to you.
 
| Measure | What it means | How it is measured |
|---|---|---|
| Accuracy | How well the tool tells attacks from normal traffic | F1-score = 2 x (precision x recall) / (precision + recall) |
| FPR | Share of harmless traffic wrongly flagged as an attack | False positive rate = FP / (FP + TN) |
| Overhead | How heavy the tool is to run | Inference latency: milliseconds to classify 1,000 flows (Snort: 1,000 packets) |
| Coverage | How many attack types the tool detects (out of 4) | Attack categories detected with at least 80% recall |
 
**Tools compared** (tested on the CSE-CIC-IDS2018 dataset):
- **LSTM-based NIDS**: a Long Short-Term Memory neural network
- **CNN-based NIDS**: a Convolutional Neural Network
- **Hybrid SVM-DL NIDS**: deep-learning features classified by a Support Vector Machine
- **Snort**: a widely used rule-based (signature) NIDS, version 2.9.20, community rules
 
*The score bands are the author's own design, and each result comes from a single run, so treat the ranking as indicative.*
""")

# T9: a missing, unreadable or malformed specification file is reported, not a crash
try:
    with open("tools_data.json") as f:
        tools = json.load(f)
except FileNotFoundError:
    st.error("tools_data.json was not found.")
    st.stop()
except json.JSONDecodeError as e:
    st.error(f"tools_data.json is not valid JSON: {e}")
    st.stop()

if not isinstance(tools, list):
    st.error("tools_data.json must contain a list of tool specifications.")
    st.stop()

with st.expander("Tool specifications (edit tools_data.json to update)"):
    st.json(tools)

st.sidebar.header("Weighting scheme")
preset_name = st.sidebar.radio("Preset", list(WEIGHT_PRESETS.keys()) + ["Custom"])

if preset_name == "Custom":
    st.sidebar.write("Adjust weights (auto-normalised to sum to 1.0):")
    w_acc = st.sidebar.slider("Accuracy", 0.0, 1.0, 0.25, 0.05)
    w_fpr = st.sidebar.slider("FPR", 0.0, 1.0, 0.25, 0.05)
    w_ovh = st.sidebar.slider("Overhead", 0.0, 1.0, 0.25, 0.05)
    w_cov = st.sidebar.slider("Coverage", 0.0, 1.0, 0.25, 0.05)
    total_w = max(w_acc + w_fpr + w_ovh + w_cov, 0.0001)
    weights = {
        "accuracy": w_acc / total_w,
        "fpr": w_fpr / total_w,
        "overhead": w_ovh / total_w,
        "coverage": w_cov / total_w,
    }
else:
    weights = WEIGHT_PRESETS[preset_name]

results = []
for tool in tools:
    # T9: invalid or incomplete specifications are rejected with a message
    errs = validate_tool_spec(tool)
    if errs:
        label = tool.get("name", "Unnamed tool") if isinstance(tool, dict) else "Invalid entry"
        st.error(f"{label} rejected: {'; '.join(errs)}")
        continue
    r = compute_total_score(tool, weights)
    results.append({"Tool": tool["name"], "Total score": r["total"], **r["sub_scores"]})

if not results:
    st.warning("No valid tools to score. Check tools_data.json.")
    st.stop()

df = pd.DataFrame(results).sort_values("Total score", ascending=False).reset_index(drop=True)
df.index = df.index + 1

st.subheader("Ranking")
st.dataframe(
    df.style.format({
        "Total score": "{:.1f}",
        "accuracy": "{:.1f}",
        "fpr": "{:.1f}",
        "overhead": "{:.1f}",
        "coverage": "{:.1f}",
    }),
    use_container_width=True,
)

st.subheader("Spider graph")
categories = ["accuracy", "fpr", "overhead", "coverage"]
labels = ["Accuracy", "FPR", "Overhead", "Coverage"]

fig = go.Figure()

# Iterate df rows (rebuilt each run with current weights)
# and plot WEIGHTED values so spokes visually reflect weight changes
for _, row in df.iterrows():
    weighted_r = [row[c] * (weights[c] / 0.25) for c in categories]
    fig.add_trace(
        go.Scatterpolar(
            r=weighted_r,
            theta=labels,
            fill="toself",
            name=row["Tool"],
        )
    )

fig.update_layout(
    polar=dict(radialaxis=dict(visible=True, range=[0, 50])),
    showlegend=True,
    margin=dict(t=20, b=20),
)
st.plotly_chart(fig, use_container_width=True)
st.caption(f"Weighting used: { {k: round(v, 2) for k, v in weights.items()} }")
