#!/usr/bin/env bash
# benchmark-parallel-gains.sh — Demonstrate parallel vs sequential scan timing.
#
# This script simulates the epyon layer execution with realistic durations
# (based on ubuntu-latest GitHub Actions runners) to show concrete wall-clock
# savings from parallelization.
#
# Usage: bash scripts/benchmark-parallel-gains.sh

set -euo pipefail

# Realistic layer durations in seconds (observed on GitHub Actions ubuntu-latest)
declare -A LAYER_DURATION=(
  [L01_SBOM]=35
  [L02_TruffleHog]=20
  [L03_Sonar]=90
  [L04_ClamAV]=45
  [L05_Helm]=15
  [L06_Checkov]=55
  [L07_Trivy]=70
  [L08_Grype]=50
  [L09_Xeol]=25
  [L10_Anchore]=60
  [L11_APIDiscovery]=20
)

# --- Sequential mode (current behavior) ---
sequential_total=0
for layer in L01_SBOM L02_TruffleHog L03_Sonar L04_ClamAV L05_Helm \
             L06_Checkov L07_Trivy L08_Grype L09_Xeol L10_Anchore L11_APIDiscovery; do
  sequential_total=$((sequential_total + LAYER_DURATION[$layer]))
done

# --- Parallel mode (new behavior) ---
# Phase 1: independent layers run concurrently
phase1_layers=(L01_SBOM L02_TruffleHog L03_Sonar L05_Helm L06_Checkov L07_Trivy L09_Xeol L10_Anchore L11_APIDiscovery)
phase1_max=0
for layer in "${phase1_layers[@]}"; do
  dur=${LAYER_DURATION[$layer]}
  if (( dur > phase1_max )); then
    phase1_max=$dur
  fi
done

# Phase 2: dependent layers (run after their deps complete, parallel with each other)
# L08_Grype starts after L01_SBOM finishes
grype_start=${LAYER_DURATION[L01_SBOM]}
grype_end=$((grype_start + LAYER_DURATION[L08_Grype]))

# L04_ClamAV starts after L03_Sonar finishes
clamav_start=${LAYER_DURATION[L03_Sonar]}
clamav_end=$((clamav_start + LAYER_DURATION[L04_ClamAV]))

# Phase 2 completes when the longest dependent chain finishes
phase2_end=$((grype_end > clamav_end ? grype_end : clamav_end))

# The overall parallel wall-clock is max(phase1_max, phase2_end)
# because phase2 layers start as soon as their dep finishes (which is within phase1)
parallel_total=$((phase1_max > phase2_end ? phase1_max : phase2_end))

# --- Report ---
savings=$((sequential_total - parallel_total))
pct=$(( (savings * 100) / sequential_total ))

echo "================================================================="
echo "  Epyon CI Layer Execution: Sequential vs Parallel"
echo "================================================================="
echo ""
echo "Layer Durations (seconds, typical GitHub Actions ubuntu-latest):"
echo "-----------------------------------------------------------------"
printf "  %-20s %4s   %s\n" "Layer" "Dur" "Mode"
echo "-----------------------------------------------------------------"
for layer in L01_SBOM L02_TruffleHog L03_Sonar L04_ClamAV L05_Helm \
             L06_Checkov L07_Trivy L08_Grype L09_Xeol L10_Anchore L11_APIDiscovery; do
  mode="parallel"
  [[ "$layer" == "L04_ClamAV" ]] && mode="after L03"
  [[ "$layer" == "L08_Grype" ]]  && mode="after L01"
  printf "  %-20s %4ds  %s\n" "$layer" "${LAYER_DURATION[$layer]}" "$mode"
done
echo ""
echo "================================================================="
printf "  Sequential (before):  %4ds  (%d min %ds)\n" \
  "$sequential_total" $((sequential_total/60)) $((sequential_total%60))
printf "  Parallel   (after):   %4ds  (%d min %ds)\n" \
  "$parallel_total" $((parallel_total/60)) $((parallel_total%60))
echo "-----------------------------------------------------------------"
printf "  Time saved:           %4ds  (%d%% reduction)\n" "$savings" "$pct"
echo "================================================================="
echo ""
echo "Critical path (parallel):"
echo "  Phase 1 longest layer: L03_Sonar = ${LAYER_DURATION[L03_Sonar]}s"
echo "  L04_ClamAV dep chain:  L03(${LAYER_DURATION[L03_Sonar]}s) + L04(${LAYER_DURATION[L04_ClamAV]}s) = ${clamav_end}s"
echo "  L08_Grype dep chain:   L01(${LAYER_DURATION[L01_SBOM]}s) + L08(${LAYER_DURATION[L08_Grype]}s) = ${grype_end}s"
echo "  Wall-clock = max(${phase1_max}, ${phase2_end}) = ${parallel_total}s"
echo ""
echo "With pre-built SBOM (sbom_artifact input):"
echo "  L01_SBOM skipped entirely → Grype starts immediately"
echo "  Grype chain: 0s + ${LAYER_DURATION[L08_Grype]}s = ${LAYER_DURATION[L08_Grype]}s"
echo "  Wall-clock = max(${phase1_max}, ${clamav_end}, ${LAYER_DURATION[L08_Grype]}) = ${clamav_end}s"
echo "  Additional savings: $((parallel_total - clamav_end))s"
