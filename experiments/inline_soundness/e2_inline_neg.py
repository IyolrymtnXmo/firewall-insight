"""E2b what-if: v4.40 inline handling + per-dimension Kleene negation (in memory only)."""
import json, sys
sys.path.insert(0, '.')
import app.traffic_v440 as T
import e2_neg
e2_neg.T = T
T.trace_layer_candidates = e2_neg.patched
import e2_inline as I
out = {}
for frac in (0.1, 0.2, 0.3):
    out[str(frac)] = I.run(T.trace_access_tree, opaque_frac=frac)
    print(json.dumps(out[str(frac)]))
json.dump(out, open('e2_inline_v440_kleene_neg.json', 'w'), indent=1)
