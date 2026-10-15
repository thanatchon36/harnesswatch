#!/bin/bash
# Full canary-bench sequence used for the paper (resumable: completed runs are skipped).
set -u
cd "$(dirname "$0")/.."
SC="--scenario control --scenario readme --scenario instructions --scenario code_comment --scenario tool_output"
OUT=bench/results/2026-10-15
uv run harnesswatch bench run --out $OUT --raw bench/.work/raw -n 5 --parallel 2 --timeout 240 --model qwen3:4b-instruct $SC
uv run harnesswatch bench run --out $OUT --raw bench/.work/raw -n 3 --parallel 2 --timeout 240 --model llama3.1:8b $SC
echo ALL_DONE
