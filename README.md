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
- Fully responsive — works on mobile, tablet, and desktop

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

## H3AD-SEC Platform Modules

| Module | Tools |
|--------|-------|
| [H3AD-X](https://h3ad-sec.github.io/H3AD-X/) | X-VERDIKT, PARSE-X, DNSCOPE, MAILSCOPE |
| [H3AD-AI](https://h3ad-sec.github.io/H3AD-AI/) | INSIGHT-AI, QUERYCRAFT-AI, FPLENS-AI, ATTMAP-AI, CHRONO-AI, MALBRIEF-AI, PROMPTVAULT |
| [H3AD-DETECT](https://h3ad-sec.github.io/H3AD-DETECT/) | TRACERULES |
| [H3AD-HUNT](https://h3ad-sec.github.io/H3AD-HUNT/) | HYPOS, PIVEX, TRACEPULSE |
| [H3AD-OPS](https://h3ad-sec.github.io/H3AD-OPS/) | QUICKTRACE, SHIFTLOG, PHISHOPS |
| [H3AD-DF](https://h3ad-sec.github.io/H3AD-DF/) | REGSCOPE, MALBRIEF-AI |
| [H3AD-IR](https://h3ad-sec.github.io/H3AD-IR/) | PHISHBOOK |
| [H3AD-LEARN](https://h3ad-sec.github.io/H3AD-LEARN/) | Threat Hunting (9 ch), LOLBAS (8 ch) |
