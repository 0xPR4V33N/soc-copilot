# AI SOC Copilot Portfolio Summary

## Dataset Snapshot
- Total events: 8
- MITRE mapped events: 6 (75%)
- Severity distribution: {'low': 3, 'critical': 1, 'high': 3, 'medium': 1}
- Decision source distribution: {'sample': 2, 'rule': 6}

## Labeled Evaluation
- Labeled events: 8
- Severity accuracy: 100%
- Precision: 100%
- Recall: 100%
- F1: 100%

## Analyst Feedback
- Reviewed events: 1
- Severity overrides: 0 (0%)
- Dispositions: {'confirmed': 1}

## Model Benchmark
- sample-baseline: accuracy 100%, F1 100%, runtime 0.00s

## Portfolio Talking Points
- Hybrid triage (rules first, LLM fallback) reduces noisy model decisions.
- Analyst-in-the-loop feedback records false positives and severity corrections.
- Quantitative metrics (accuracy, precision, recall, F1) track quality over time.
