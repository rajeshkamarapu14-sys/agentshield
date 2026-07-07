"""pytest configuration.

Force the test suite to run DETERMINISTICALLY, independent of any local `.env`.
Tests must be hermetic — fast, reproducible, and never dependent on the network,
a Gemini key, or free-tier quota. We disable the optional LLM paths here BEFORE
`config` is imported; python-dotenv's load_dotenv() uses override=False, so it
won't clobber these, keeping the firewall on pure deterministic rules under test.
"""

import os

os.environ["AGENTSHIELD_USE_LLM_JUDGE"] = "false"
os.environ["AGENTSHIELD_USE_LLM_DETECTOR"] = "false"
