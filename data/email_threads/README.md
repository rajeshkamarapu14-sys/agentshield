# Test email threads (synthetic)

Real files on disk that `read_email_thread` reads. All content is **synthetic**.
Email thread history is one of the five prompt-injection sources — a malicious
instruction can be buried in a prior message.

| File | What it demonstrates |
|---|---|
| `order_followup.txt` | Benign thread — passes clean. |
| `refund_thread_poisoned.txt` | **Poisoned**: a hidden instruction to exfiltrate customer data → firewall blocks. |

No real customers, no real email addresses in use.
