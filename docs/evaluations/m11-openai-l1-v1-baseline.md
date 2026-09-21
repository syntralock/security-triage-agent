# Frozen M11 OpenAI baseline

Date: 2026-09-21. This is historical engineering evidence from one stochastic live run, not a general SOC-accuracy claim.

Configuration: OpenAI reasoner, `gpt-5.6-luna`, prompt `openai-l1-v1`, suite `evaluations/v1`, fixture `v1`, policy `1.0.0`, provider timeout 25 seconds, orchestration deadline 30 seconds, SDK retries disabled.

Results: 10 scenarios; 2 EXACT, 3 ACCEPTABLE, 5 FAILURE; 7 escalation matches; 0 false positives; 4/4 malicious false negatives; 23 successful tool calls; 3 required-tool omissions; 13 unexpected tool selections; 0 forbidden tool selections; 0 evidence-reference violations; 0 persistence failures; 0 recovery failures; 0 stale `RUNNING` executions. Eight high-impact actions were recommended; zero approvals and zero action executions occurred.

Security boundaries held: provider output did not choose canonical invocation or action identities; tool proposals crossed the gateway; deterministic policy remained authoritative; high-impact actions remained approval-gated; no approval, remediation, arbitrary shell/filesystem/SQL access, or non-provider network capability resulted.

Limitations: the dataset contains only ten synthetic scenarios and is not representative of general SOC workloads. Confidence is uncalibrated. Results may vary between live runs and provider model revisions. Earlier engineering runs included persistence/reference defects and are not model-quality baselines. This document contains no secret, raw prompt, provider response, or chain-of-thought. M12A freezes the prompt and ground truth rather than tuning against this result.

