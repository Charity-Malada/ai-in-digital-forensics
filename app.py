import json

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from scoring import WEIGHT_PRESETS, compute_total_score

st.set_page_config(page_title="AI Forensic Tool Evaluation Framework", layout="wide")
st.title("AI Forensic Tool Evaluation Framework")
st.caption("Term 3 prototype - Input layer -> Evaluation engine -> Output layer")

# --- Input layer -------------------------------------------------------
with open("tools_data.json") as f:
    tools = json.load(f)

with st.expander("Tool specifications (edit tools_data.json to update)"):
    st.json(tools)

# --- Weighting control (T4 sensitivity analysis) ------------------------
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

# --- Evaluation engine ---------------------------------------------------
results = []
for tool in tools:
    r = compute_total_score(tool, weights)
    results.append({"Tool": tool["name"], "Total score": r["total"], **r["sub_scores"]})

df = pd.DataFrame(results).sort_values("Total score", ascending=False).reset_index(drop=True)
df.index = df.index + 1  # 1-based rank

# --- Output layer ---------------------------------------------------
st.subheader("Ranking")
st.dataframe(
    df.style.format({"Total score": "{:.1f}", "accuracy": "{:.1f}", "fpr": "{:.1f}", "overhead": "{:.1f}", "coverage": "{:.1f}"}),
    use_container_width=True,
)

st.subheader("Spider graph")
categories = ["accuracy", "fpr", "overhead", "coverage"]
labels = ["Accuracy", "FPR", "Overhead", "Coverage"]

fig = go.Figure()
for row in results:
    fig.add_trace(
        go.Scatterpolar(
            r=[row[c] for c in categories],
            theta=labels,
            fill="toself",
            name=row["Tool"],
        )
    )
fig.update_layout(
    polar=dict(radialaxis=dict(visible=True, range=[0, 25])),
    showlegend=True,
    margin=dict(t=20, b=20),
)
st.plotly_chart(fig, use_container_width=True)

st.caption(f"Weighting used: {weights}")
