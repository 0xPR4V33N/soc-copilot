from __future__ import annotations

import json
import os
from pathlib import Path

import pandas as pd
import streamlit as st

from soc_copilot.config import load_settings
from soc_copilot.evaluation import evaluate_results, load_labels
from soc_copilot.feedback import event_fingerprint, feedback_index, upsert_feedback
from soc_copilot.mitre.mapper import load_mitre_techniques, map_to_mitre, mitre_url
from soc_copilot.parse.sysmon_event import parse_sysmon_message
from soc_copilot.triage.pipeline import parse_triage_record

st.set_page_config(page_title="AI SOC Copilot", layout="wide")
st.title("AI-Powered SOC Copilot — Local Triage Engine")

settings = load_settings()


def resolve_triaged_path(use_demo: bool) -> Path:
    if use_demo:
        demo_triaged = settings.root / "data" / "samples" / "triaged.json"
        if demo_triaged.exists():
            return demo_triaged
    return settings.events_processed


@st.cache_data
def load_data(file_path: str, file_mtime: float):
    path = Path(file_path)
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    mitre_db = load_mitre_techniques(str(settings.mitre_index))

    rows = []
    for event_index, item in enumerate(data):
        triage = parse_triage_record(item.get("triage", {}))
        parsed_event = parse_sysmon_message(item["event"])
        confidence = triage.get("confidence")
        confidence_percent = (
            float(confidence) * 100 if isinstance(confidence, (int, float)) else None
        )

        mitre_label = triage.get("mitre") or map_to_mitre(
            triage.get("technique_guess", ""), mitre_db
        )

        rows.append(
            {
                "Severity": triage.get("severity", "unknown").upper(),
                "AI Severity": triage.get("severity", "unknown").upper(),
                "Event Type": parsed_event.event_type,
                "MITRE Technique": mitre_label,
                "MITRE URL": mitre_url(mitre_label),
                "Technique Guess": triage.get("technique_guess", ""),
                "Summary": triage.get("summary", ""),
                "Process": parsed_event.image,
                "Parent Process": parsed_event.parent_image,
                "Destination": (
                    f"{parsed_event.destination_hostname or parsed_event.destination_ip}:"
                    f"{parsed_event.destination_port}"
                    if parsed_event.destination_port
                    else ""
                ),
                "Registry Target": parsed_event.target_object,
                "User": parsed_event.user,
                "Time": parsed_event.utc_time or item["event"].get("TimeCreated", ""),
                "Source": triage.get("source", "unknown"),
                "Confidence": confidence_percent,
                "Rules": ", ".join(triage.get("rule_ids", [])),
                "Feedback": "",
                "_event_key": event_fingerprint(item["event"]),
                "_event_index": event_index,
            }
        )
    return pd.DataFrame(rows), data


with st.sidebar:
    st.header("Data source")
    use_demo = st.toggle(
        "Demo mode",
        value=not settings.events_processed.exists(),
        help="Use sanitized sample data (no Sysmon or LLM required).",
    )
    triaged_path = resolve_triaged_path(use_demo)
    st.caption(f"Loading: `{triaged_path.relative_to(settings.root)}`")

if not triaged_path.exists():
    st.warning(
        "No triage data found. Run the pipeline first:\n\n"
        "`python scripts/run_pipeline.py --demo-static` (no model needed)\n\n"
        "`python scripts/run_pipeline.py` (live Sysmon + LLM)"
    )
    st.stop()

mtime = os.path.getmtime(triaged_path)
df, raw_data = load_data(str(triaged_path), mtime)

analyst_feedback = feedback_index(settings.analyst_feedback)
for row_index, row in df.iterrows():
    feedback = analyst_feedback.get(row["_event_key"])
    if feedback:
        df.at[row_index, "Severity"] = feedback["analyst_severity"].upper()
        df.at[row_index, "Feedback"] = feedback["disposition"].replace("_", " ").title()

severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
df["_sort"] = df["Severity"].map(severity_order).fillna(99)
df = df.sort_values("_sort").drop(columns="_sort")

col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("Total Events", len(df))
col2.metric("High/Critical", len(df[df["Severity"].isin(["HIGH", "CRITICAL"])]))
col3.metric("Mapped to MITRE", len(df[df["MITRE Technique"] != "Unmapped"]))
col4.metric("Low/Benign", len(df[df["Severity"] == "LOW"]))
col5.metric("Rule Decisions", len(df[df["Source"] == "rule"]))

if use_demo and settings.sample_labels.exists():
    evaluation = evaluate_results(raw_data, load_labels(settings.sample_labels))
    with st.expander("Labeled sample evaluation", expanded=True):
        eval1, eval2, eval3, eval4, eval5 = st.columns(5)
        eval1.metric("Labeled Events", evaluation["evaluated"])
        eval2.metric("Severity Accuracy", f"{evaluation['severity_accuracy']:.0%}")
        eval3.metric("Precision", f"{evaluation['precision']:.0%}")
        eval4.metric("Recall", f"{evaluation['recall']:.0%}")
        eval5.metric("F1", f"{evaluation['f1']:.0%}")
        st.caption(
            "Precision, recall, and F1 treat HIGH/CRITICAL as suspicious. "
            "Metrics use AI/rule verdicts before analyst overrides."
        )

st.subheader("Triage Results")

filter_col1, filter_col2, filter_col3, filter_col4 = st.columns(4)
with filter_col1:
    severity_filter = st.multiselect(
        "Severity",
        options=sorted(df["Severity"].unique()),
        default=sorted(df["Severity"].unique()),
    )
with filter_col2:
    source_filter = st.multiselect(
        "Decision source",
        options=sorted(df["Source"].unique()),
        default=sorted(df["Source"].unique()),
    )
with filter_col3:
    event_type_filter = st.multiselect(
        "Event type",
        options=sorted(df["Event Type"].unique()),
        default=sorted(df["Event Type"].unique()),
    )
with filter_col4:
    process_query = st.text_input("Process search", placeholder="powershell.exe")

filtered_df = df[
    df["Severity"].isin(severity_filter)
    & df["Source"].isin(source_filter)
    & df["Event Type"].isin(event_type_filter)
]
if process_query:
    filtered_df = filtered_df[
        filtered_df["Process"].str.contains(process_query, case=False, na=False)
    ]

def color_severity(val):
    colors = {
        "CRITICAL": "background-color: #ff4b4b",
        "HIGH": "background-color: #ff8c42",
        "MEDIUM": "background-color: #ffd93d",
        "LOW": "background-color: #6bcf7f",
    }
    return colors.get(val, "")


display_df = filtered_df.drop(columns=["_event_index", "_event_key"])
st.dataframe(
    display_df.style.map(color_severity, subset=["Severity"]),
    column_config={
        "MITRE URL": st.column_config.LinkColumn(
            "MITRE ATT&CK",
            help="Open the official MITRE ATT&CK technique page",
            display_text="Open technique",
        ),
        "Confidence": st.column_config.NumberColumn(format="%.0f%%"),
    },
    width="stretch",
    height=350,
)

st.subheader("Analyst Event Detail")
for _, row in filtered_df.iterrows():
    event_index = int(row["_event_index"])
    item = raw_data[event_index]
    triage = parse_triage_record(item.get("triage", {}))
    event_key = row["_event_key"]
    existing_feedback = analyst_feedback.get(event_key, {})
    with st.expander(
        f"Event #{event_index + 1} — {row['Severity']} — {row['Process']}"
    ):
        st.write(f"**Decision source:** {row['Source']}")
        st.write(f"**Summary:** {row['Summary']}")
        if triage.get("indicators"):
            st.write("**Indicators:**")
            for indicator in triage["indicators"]:
                st.write(f"- {indicator}")
        if isinstance(row["MITRE URL"], str) and row["MITRE URL"]:
            st.link_button(
                f"Open {row['MITRE Technique']} in MITRE ATT&CK",
                row["MITRE URL"],
            )
        st.write("**Analyst disposition**")
        severity_options = ["low", "medium", "high", "critical"]
        current_severity = existing_feedback.get(
            "analyst_severity", triage.get("severity", "low")
        )
        disposition_options = ["needs_review", "confirmed", "false_positive"]
        current_disposition = existing_feedback.get("disposition", "needs_review")
        with st.form(f"feedback-{event_key}"):
            analyst_severity = st.selectbox(
                "Analyst severity",
                severity_options,
                index=severity_options.index(current_severity)
                if current_severity in severity_options
                else 0,
            )
            disposition = st.selectbox(
                "Disposition",
                disposition_options,
                index=disposition_options.index(current_disposition),
                format_func=lambda value: value.replace("_", " ").title(),
            )
            notes = st.text_area(
                "Analyst notes",
                value=existing_feedback.get("notes", ""),
                placeholder="Document why the alert was confirmed or overridden.",
            )
            if st.form_submit_button("Save analyst decision"):
                upsert_feedback(
                    settings.analyst_feedback,
                    item["event"],
                    original_severity=triage.get("severity", "unknown"),
                    analyst_severity=analyst_severity,
                    disposition=disposition,
                    notes=notes,
                )
                st.success("Analyst decision saved.")
                st.rerun()
        st.json(item)
