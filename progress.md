# Progress Log

## Day 1
- Python 3.12.10 already installed
- Created project folder
- VS Code open
- Next: Learn basic Python — variables, dicts, print()

## Day 2
- Learned: dictionaries, lists, f-strings, for loops, if conditions, filtering
- Built learn.py with fake log entries
- Can loop through events and filter by conditions
- Next: Reading log data from a JSON file

## Day 3
- Loaded CloudTrail logs from JSON file using json module
- Extracted nested fields: userIdentity, requestParameters, additionalEventData
- Read the logs as an investigator — identified unauthorized access pattern
- Key insight: flat output hides critical details, investigations need depth
- Next: Understand CloudTrail structure fully, extract the 5 key fields into a clean format

## Day 4
- Built extract_key_fields function with 8 fields including service, target, MFA
- Wrote get_target() to handle different CloudTrail event structures
- Learned: CloudTrail stores targets inconsistently across event types — normalization is hard
- Found a bug: AttachUserPolicy target misses the policy name
- Next: Lists of dictionaries, filtering by criteria

## Day 5
- Fixed AttachUserPolicy target bug (policyArn check order)
- Built filter functions: by actor, service, action
- Built reusable print_events() function
- Can isolate user activity and service-level events
- Key insight: filtering by actor reveals the account handoff pattern
- Next: Bigger dataset (50 events), counts, and summary stats

## Day 6
- Loaded 50-event dataset with 5 users
- Built summary counts: users, events per user, event types
- Found and fixed two bugs:
  - Double counting (+=1 then +=1 again)
  - Reset instead of increment (= 1 vs += 1)
- Key numbers: rahul.kapoor has most events (13), 11 console logins in one day
- Next: Refactor code into functions, build the normalizer module

## Day 7
- Created normalizer.py with load_logs, normalize_event, normalize_all, get_target
- Created main.py that imports from normalizer
- Code is now modular — parsing logic separated from analysis
- Expanded get_target to handle stacks, security groups, trails
- Next: Timestamp parsing and sorting events chronologically

## Day 8
- Installed python-dateutil, parsed timestamps into datetime objects
- Sorted events chronologically
- Calculated investigation window (14 hours)
- Built formatted timeline with aligned columns
- Key insight: timeline reveals attack pattern clearly — recon, setup, exfil, cover tracks, then late-night return from different IP/region
- Next: Separate normalizer into its own module (already done), start building timeline.py

## Day 9
- Built timeline.py with build_timeline, group_into_sessions, print_sessions
- Grouped 50 events into 16 sessions using 30-minute gap logic
- Sessions clearly separate normal activity from attack
- Attack is Sessions 6+7 (creation + exfiltration) and Session 16 (cleanup)
- Key insight: event density per session is a signal — 13 events in 16 min is abnormal
- Next: Generate plain-English session summaries

## Day 10
- Built summarize_session() that generates plain-English summaries
- Summaries detect: login issues, reconnaissance, privilege escalation, data access, destructive actions
- Sessions 6+7+16 tell the complete attack story without needing raw logs
- Fixed indentation error — learned to check alignment in VS Code
- Rough edge: normal operations (StopInstances, DeleteStack) flagged as destructive — needs context-aware detection later
- Next: Error handling for missing/malformed fields

## Day 11
- Tested code against messy/malformed log data — 5 different failure types
- Added error handling: .get() with defaults, try/except, None timestamp detection
- Actor resolution now handles: IAMUser, AWSService (invokedBy), unknown types
- Events with missing/empty timestamps are skipped with warnings, not crashed
- Key learning: real logs are messy — defensive coding prevents investigation failures
- Next: Review and refactor, then move to Phase 4 (detection rules)

## Day 12
- Built detector.py with 6 detection rules: no MFA, privilege escalation, CloudTrail tampering, sensitive data access, unusual hours, self-deletion
- First run: 31 findings — CRITICAL and HIGH were accurate, MEDIUM was noisy
- Tuned unusual hours threshold (8-19 IST → 6-23 IST) — reduced from 16 to 4 MEDIUM findings
- All remaining findings are genuine — zero false positives
- Key learning: correct rules can still be noisy — tuning thresholds is real detection engineering
- Next: Attack chain correlation — connecting individual findings into a multi-step pattern

## Day 13
- Built attack chain correlation in detector.py
- Two chain patterns: ACCOUNT_CREATION_ATTACK and BRUTE_FORCE_AND_ACT
- Chain 1 connected rahul.kapoor and svc-backup-admin across 18 findings, 9 hours, 2 IPs
- Chain analysis links: no MFA → recon → priv esc → data exfil → trail tampering → self-deletion
- Key insight: individual findings are alerts, chains are investigations
- Next: Compliance mapping — connecting findings to ISO 27001, SOC 2, DPDP Act

## Day 14 (Phase 5)
- Created compliance_mappings/ with ISO 27001, SOC 2, and DPDP Act JSON files
- Built compliance.py with load_all_frameworks, map_findings_to_compliance, print_compliance_report
- Results: 11 ISO 27001 controls failed, 5 SOC 2 criteria failed, 2 DPDP sections triggered
- Every failed control links to specific evidence events
- DPDP correctly flags Section 8(6) breach notification requirement
- To review: A.8.17 mapping may be a stretch — consider removing
- Full pipeline now: load → normalize → timeline → detect → chain analysis → compliance mapping

## Day 15 (Phase 6)
- Set up Ollama with llama3.2 running locally
- Built ai_engine.py with ask_ai, ai_root_cause, ai_executive_summary
- Key design: rules detect with certainty, AI adds narrative and recommendations
- AI output is useful but needs validation — smaller models hedge and sometimes misattribute
- Prompt engineering matters: telling AI "this is confirmed" eliminates hedging
- AI limitation: generic root causes (training) vs actual root causes (control design gaps)
- Full pipeline now: normalize → timeline → detect → chain → compliance → AI analysis

## Day 16 (Phase 7)
- Built report_generator.py — generates complete Markdown investigation report
- Report covers all 9 sections from the vision document
- Full pipeline: 50 JSON events → investigation report in seconds
- Project structure: 7 Python modules + 3 compliance frameworks
- PROJECT MILESTONE: End-to-end pipeline complete

## Day 17
- Added 4 multi-event detection rules: concurrent sessions, impossible travel, IP anomaly, persistence
- Added compromised credentials attack chain pattern
- Fixed IP anomaly logic — MFA-authenticated IPs are the trusted baseline, not most-used
- Tested phishing scenario: CRITICAL chain detected with 7 indicators
- Verified original scenario still works — no regressions
- Key learning: per-event rules catch individual signals, multi-event rules catch relationships
- Platform now handles 2 different attack types automatically

## Day 18
- Added volume anomaly and breadth anomaly detection
- Added DATA_HOARDING attack chain pattern
- Tuned thresholds to eliminate false positives (volume >= 8, breadth >= 4 buckets)
- Fixed IP anomaly to use MFA-authenticated IPs as trusted baseline
- Tested all 3 scenarios — correct detection, zero false positive chains
- Platform now detects: insider threat, credential compromise, and data theft
- 12 detection rules, 4 chain patterns, 3 frameworks, 3 scenarios

## Day 19
- Added Linux auth.log support — completely different format (text vs JSON)
- Built linux_normalizer.py with regex parsing for SSH and sudo events
- Added SSH brute force detection (multi-event, cross-user)
- Added suspicious sudo detection with pattern matching
- Added SSH_COMPROMISE attack chain pattern
- Fixed concurrent session false positive (local sudo IPs)
- Fixed brute force actor attribution (compromised account, not first failure)
- Key victory: timeline, detector, compliance, report modules worked unchanged
- Architecture is genuinely modular — same pipeline, different normalizers
- Platform now: 4 scenarios, 2 log formats, 5 chain patterns, 14 detection rules

## Day 20
- Built investigator.py with interactive investigation mode
- AI receives full pipeline context: timeline, sessions, findings, chains, compliance
- Added internal/external IP tagging for better AI context
- Added menu system to main.py: report, interactive, both, or skip AI
- AI can answer investigation questions, accept challenges, and revise conclusions
- Limitation: smaller local model makes attribution errors — needs verification
- Key insight: AI is good for exploration and hypotheses, rules are good for facts

## Day 21
- Built app_normalizer.py for application admin portal logs
- Updated main.py to load and merge multiple log files
- Fixed timezone mismatch between sources (offset-naive vs offset-aware)
- Fixed impossible travel false positives from non-geographic regions
- Built correlator.py for cross-source analysis
- Added source_file tagging to all three normalizers
- Key finding: cross-source correlation reveals actions invisible to either source alone
- AdminPortal showed bulk exports (189 MB), record counts, audit config changes
- CloudTrail showed IAM manipulation, S3 access, trail deletion
- Platform now handles: 3 log formats, multi-file merge, cross-source correlation

## Day 22
- Built Streamlit web UI (app.py)
- Features: file upload, progress bar, metrics dashboard, expandable findings, attack chains, compliance impact, full timeline table, cross-source correlation
- Run with: python -m streamlit run app.py
- Platform is now usable by non-technical people

## Day 23
- Added AI chat interface to Streamlit UI
- Chat uses full investigation context for accurate answers
- Chat history persists during session
- Platform is now fully browser-based with interactive AI investigation

## Day 24
- Built generic_normalizer.py — config-driven log parsing framework
- Created log_configs/ with CloudTrail, Azure, and GCP configs
- Added action_map to translate platform-specific actions to common names
- Added PRIVILEGE_ABUSE attack chain pattern
- Azure Activity Log: fully detected with 6 findings and 1 attack chain
- Fixed resolve_target to work without requestParameters (Azure compatibility)
- Key achievement: adding a new cloud platform is now a 10-minute config file
- Zero Python changes needed for new JSON-based log formats