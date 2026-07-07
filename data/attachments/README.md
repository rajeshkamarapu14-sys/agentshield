# Test attachments (synthetic)

Real files on disk that `read_attachment` reads. All content is **synthetic** and
exists to exercise the firewall:

| File | What it demonstrates |
|---|---|
| `receipt.txt` | Benign attachment — passes clean. |
| `invoice_dispute.txt` | **Poisoned**: hidden instruction (system-prompt leak + unauthorized refund) → firewall blocks. |
| `server_logs.txt` | **Poisoned**: embedded fake API key → firewall redacts/sanitizes. |

No real secrets, no real customer data.
