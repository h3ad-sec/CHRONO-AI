# CHRONO-AI

**Incident Timeline Builder — Part of [H3AD-AI](https://h3ad-sec.github.io/H3AD-AI/)**

CHRONO-AI constructs structured incident timelines from unordered analyst notes, alert data, or raw log excerpts. Paste the raw observations and get a chronologically ordered event sequence with ATT&CK technique tagging, significance ratings, and detection notes per event.

## Features

- Supports four AI providers: Anthropic (Claude), OpenAI (GPT), Google Gemini, Groq
- Reconstructs chronological order from unordered input
- Tags each event with ATT&CK technique and tactic
- Significance rating per event (Critical / High / Medium / Low)
- Detection notes — what should have been visible in logs or EDR
- Identifies timeline gaps and missing visibility windows
- Clean event list format ready for incident reports
- Export as plain text

## Output Format

Each timeline event includes:
- Timestamp (absolute or relative, as inferred from input)
- Event description
- ATT&CK technique tag
- Significance rating
- Detection note (what telemetry should have caught this)

## How to Use

1. Add your API key via the settings icon
2. Paste raw incident data: log lines, alert descriptions, analyst notes, IOC timestamps
3. Click BUILD TIMELINE
4. Review the ordered event sequence and export

## Live Tool

[h3ad-sec.github.io/CHRONO-AI](https://h3ad-sec.github.io/CHRONO-AI/)

## Part of H3AD-SEC

CHRONO-AI is a sub-tool under [H3AD-AI](https://h3ad-sec.github.io/H3AD-AI/), the AI-assisted analysis hub of the [H3AD-SEC](https://h3ad-sec.github.io) platform.
