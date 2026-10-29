"""Ghost Data Still Exists — AI-Powered Deletion Audit Agent.

Main CLI entry point for the deletion audit system.
"""

import argparse
import csv
import json
import os
import sys
import time

# Ensure package directory is on path
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from loaders import (
    load_deletion_requests,
    load_user_identities,
    load_user_audit_log,
    load_system_activity,
    load_deletion_rules,
)
from identity import IdentityResolver
from evidence_index import EvidenceIndex
from correlator import EvidenceCorrelator
from policy_engine import PolicyEngine


def run_pipeline(dataset_dir: str, requests_file: str, output_file: str):
    """Run the complete end-to-end deletion audit pipeline."""
    start_time = time.time()
    print("=" * 70)
    print("  HACKERRANK ORCHESTRATE: GHOST DATA STILL EXISTS")
    print("  AI-Powered Deletion Audit Agent")
    print("=" * 70)

    # 1. Load datasets
    print("\n[1/5] Loading datasets...")
    requests = load_deletion_requests(requests_file)
    identities = load_user_identities(os.path.join(dataset_dir, "user_identities.csv"))
    audit_log = load_user_audit_log(os.path.join(dataset_dir, "user_audit_log.csv"))
    rules = load_deletion_rules(os.path.join(dataset_dir, "deletion_rules.csv"))
    activity = load_system_activity(os.path.join(dataset_dir, "system_activity.csv"))

    print(f"  * Evaluation Requests:  {len(requests)}")
    print(f"  * Identity Snapshots:   {len(identities)}")
    print(f"  * User Audit Events:    {len(audit_log)}")
    print(f"  * Deletion Rules:       {len(rules)}")
    print(f"  * Operational Activity: {len(activity)}")

    # 2. Historical Identity Resolver
    print("\n[2/5] Initializing Historical Identity Resolver...")
    resolver = IdentityResolver(identities, audit_log)
    print("  * Built temporal timelines for all users across cutoff windows.")

    # 3. Evidence Index
    print("\n[3/5] Indexing and parsing evidence files...")
    evidence_index = EvidenceIndex(dataset_dir)
    diag = evidence_index.get_diagnostic_report()
    print(f"  * Indexed files:        {diag['total_files']} files ({diag['counts_by_status'].get('PARSED_SUCCESSFULLY', 0)} fully parsed)")
    print(f"  * Extracted facts:      {diag['total_extracted_facts']} structured facts")

    # 4. Correlator & Policy Engine
    print("\n[4/5] Initializing Evidence Correlator and Policy Engine...")
    correlator = EvidenceCorrelator(evidence_index, activity)
    engine = PolicyEngine(rules)

    # 5. Evaluate all requests
    print(f"\n[5/5] Auditing {len(requests)} cases against deletion rules and ground-truth evidence...")
    # Sort requests by case_id ascending as strictly required by contract
    requests.sort(key=lambda r: r.case_id)

    output_rows = []
    status_counts = {"COMPLETE": 0, "INCOMPLETE": 0, "NOT_APPLICABLE": 0}

    for i, req in enumerate(requests, start=1):
        resolved_id = resolver.find_user_by_email_at(req.email, req.audit_at)
        ctx = correlator.correlate_case(req.case_id, req.email, req.audit_at, resolved_id)
        row = engine.evaluate_case(req.case_id, req.request_text, req.audit_at, ctx)
        output_rows.append(row)
        status_counts[row.deletion_status] += 1
        if i % 100 == 0 or i == len(requests):
            print(f"  * Evaluated {i}/{len(requests)} cases...")

    # Write output CSV
    os.makedirs(os.path.dirname(os.path.abspath(output_file)), exist_ok=True)
    with open(output_file, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["case_id", "deletion_status", "steps_json"])
        for row in output_rows:
            writer.writerow([row.case_id, row.deletion_status, row.steps_json])

    elapsed = time.time() - start_time
    print("\n" + "=" * 70)
    print(f"AUDIT RUN COMPLETE: {len(output_rows)} cases written to {output_file}")
    print(f"Execution time:     {elapsed:.2f} seconds ({elapsed/len(output_rows)*1000:.1f} ms/case)")
    print(f"Status breakdown:   COMPLETE={status_counts['COMPLETE']} | INCOMPLETE={status_counts['INCOMPLETE']} | NOT_APPLICABLE={status_counts['NOT_APPLICABLE']}")
    print("=" * 70)


def evaluate_samples(dataset_dir: str):
    """Evaluate against the public sample dataset."""
    sample_req_path = os.path.join(dataset_dir, "sample_deletion_requests.csv")
    sample_gt_path = os.path.join(dataset_dir, "sample_output.csv")

    requests = load_deletion_requests(sample_req_path)
    identities = load_user_identities(os.path.join(dataset_dir, "user_identities.csv"))
    audit_log = load_user_audit_log(os.path.join(dataset_dir, "user_audit_log.csv"))
    rules = load_deletion_rules(os.path.join(dataset_dir, "deletion_rules.csv"))
    activity = load_system_activity(os.path.join(dataset_dir, "system_activity.csv"))

    resolver = IdentityResolver(identities, audit_log)
    evidence_index = EvidenceIndex(dataset_dir)
    correlator = EvidenceCorrelator(evidence_index, activity)
    engine = PolicyEngine(rules)

    ground_truth = {}
    with open(sample_gt_path, "r", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            ground_truth[row["case_id"]] = (row["deletion_status"], json.loads(row["steps_json"]))

    correct_status = 0
    total = len(requests)
    print("\nEvaluating against public sample (32 cases):")
    for req in requests:
        resolved_id = resolver.find_user_by_email_at(req.email, req.audit_at)
        ctx = correlator.correlate_case(req.case_id, req.email, req.audit_at, resolved_id)
        out = engine.evaluate_case(req.case_id, req.request_text, req.audit_at, ctx)
        gt_status, gt_steps = ground_truth[req.case_id]
        match = "MATCH" if out.deletion_status == gt_status else "MISMATCH"
        if match == "MATCH":
            correct_status += 1
        print(f"  {req.case_id}: Pred={out.deletion_status:<10} GT={gt_status:<10} [{match}]")

    print(f"\nSample Deletion Status Accuracy: {correct_status}/{total} ({correct_status/total*100:.1f}%)")


def main():
    parser = argparse.ArgumentParser(description="Ghost Data Still Exists — AI Deletion Audit Agent")
    parser.add_argument("--dataset-dir", default=None, help="Path to dataset directory")
    parser.add_argument("--requests", default=None, help="Path to deletion requests CSV")
    parser.add_argument("--output", default=None, help="Path to output CSV destination")
    parser.add_argument("--evaluate-samples", action="store_true", help="Evaluate against public samples")

    args = parser.parse_args()

    repo_root = os.path.dirname(current_dir)
    dataset_dir = args.dataset_dir or os.path.join(repo_root, "dataset")

    if args.evaluate_samples:
        evaluate_samples(dataset_dir)
        return

    requests_file = args.requests or os.path.join(dataset_dir, "deletion_requests.csv")
    output_file = args.output or os.path.join(repo_root, "output.csv")

    run_pipeline(dataset_dir, requests_file, output_file)


if __name__ == "__main__":
    main()
