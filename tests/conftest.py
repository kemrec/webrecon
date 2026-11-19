import os
import sys

# Allow `import webrecon` / `import servicescan` when pytest runs from the repo
# root without an editable install (keeps CI a single `pip install -r` step).
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
