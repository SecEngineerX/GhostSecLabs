**Brute-force detector (v2)** 
 — This project contains a sliding-window brute-force detector (`Automation-Tools/Python-Scripts/bruteforce_detector_v2.py`) and a log generator (`Automation-Tools/Python-Scripts/generate_auth.py`) used for local testing. 
   The detector parses syslog-style auth entries and raises alerts when an IP exceeds a configurable attempt threshold within a specified time window. 
   The generator creates realistic, synthetic auth logs to reproduce attack bursts during development. 
       
    Note: generated logs are not stored in the repo; run the generator locally to produce test data.

## Brute-force detector (v2)

**Brute-force detector (v2)** — This project contains a sliding-window brute-force detector (`Automation-Tools/Python-Scripts/bruteforce_detector_v2.py`) and a log generator (`Automation-Tools/Python-Scripts/generate_auth.py`) used for local testing. The detector parses syslog-style auth entries and raises alerts when an IP exceeds a configurable attempt threshold within a specified time window. The generator creates realistic, synthetic auth logs to reproduce attack bursts during development. Note: generated logs are not stored in the repo; run the generator locally to produce test data.
