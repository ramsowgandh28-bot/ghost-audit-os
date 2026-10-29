import os, csv, sys, re

sys.stdout.reconfigure(encoding='utf-8')
repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
dataset_dir = os.path.join(repo_root, 'dataset')
req_path = os.path.join(dataset_dir, 'deletion_requests.csv')

with open(req_path, 'r', encoding='utf-8') as f:
    rows = list(csv.DictReader(f))

# Let's check non-deletion indicators across all rows:
# - asking to leave/keep/not close/not delete/continue using
# - asking only for export/download/copy without deletion
# - asking only for correction/rectification/update/change without deletion
# - asking only for unsubscribe/opt-out/promotional/marketing
# - asking for login/password help

non_del_cases = []
for r in rows:
    txt = r['request_text']
    lower = txt.lower()
    
    # Check if there are explicit negative indicators (e.g. "not asking for deletion", "do not close", "keep the account", "continue using", "not a request to erase")
    explicit_neg = any(p in lower for p in [
        'not asking for deletion', 'do not close', 'don\'t close', 'keep the account',
        'continue using', 'not a request to erase', 'leave my profile', 'leave the account',
        'without removing', 'marketing lists only'
    ])
    
    if explicit_neg:
        non_del_cases.append((r['case_id'], txt))

print(f"Explicit non-deletion requests count: {len(non_del_cases)}")
for cid, txt in non_del_cases:
    print(f"[{cid}] {txt}")
