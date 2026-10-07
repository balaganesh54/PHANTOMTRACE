# SIH Presentation
PHANTOMTRACE turns a suspicious email into an explainable investigation. The analyst starts with the original `.eml`, preserves evidence, extracts indicators, evaluates authentication, correlates infrastructure, maps supported evidence to MITRE ATT&CK, calculates a transparent score and generates a forensic report.

Demo script: login → dashboard → new investigation → upload `samples/phishing.eml` → show risk factors → authentication → IOCs/URLs/domains → SMTP path → graph → MITRE observed/potential → timeline → report.

Why it is reliable for judging: local deterministic analysis works without API keys; synthetic cases are explicitly labeled DEMO; unknown intelligence is never invented.
