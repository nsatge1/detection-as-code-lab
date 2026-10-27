## New or changed detection

- **Rule:** `detections/...`
- **ATT&CK technique(s):**
- **Log source:**

## Checklist

- [ ] Test events added in `tests/events/<rule>.json` (at least one `should_match` and one `should_not_match`)
- [ ] `make all` passes locally
- [ ] False positives are described in the rule
- [ ] Coverage report regenerated (`make coverage`)