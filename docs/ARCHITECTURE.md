# AegisAV architecture

```text
                         +-------------------------------+
                         |     AegisAV Intel Server      |
                         |  FastAPI + SQLite             |
                         |                               |
                         |  MalwareBazaar hash lookup    |
                         |  rolling threat ingestion     |
                         |  optional URLhaus feed        |
                         |  optional ClamAV static scan  |
                         +---------------+---------------+
                                         ^
                              HTTPS/HTTP | hash lookup
                              + optional | private upload
                                         v
+--------------------------------------------------------------------+
|                    Windows C++ Endpoint                             |
|                                                                    |
| Signature DB -> SHA256 -> Static Heuristics -> Cloud Reputation    |
|      |            |              |                  |               |
|      |            |              |                  +-> server      |
|      |            |              +-> PowerShell/PE/entropy          |
|      |            +-> BCrypt                                           |
|      +-> rolling local hashes                                      |
|                                                                    |
| File watcher -------+                                              |
| Process monitor ----+--> Scanner --> verdict --> log/quarantine    |
| CLI/GUI ------------+                                              |
| Windows service ----+                                              |
+--------------------------------------------------------------------+
```

## Trust boundaries

The endpoint never executes a file to determine whether it is malicious. The server never executes uploads either. If ClamAV is installed, it is invoked as a scanner only.

The threat-intel server is a separate trust boundary. Hash-only lookup is the default. Uploading unknown files is opt-in.

## Why there is no kernel driver in v1

A production filesystem minifilter must be engineered, fuzzed, signed, and distributed under Microsoft's driver-signing requirements. A broken minifilter can crash or brick Windows. AegisAV v1 therefore stays in user mode while the scanning logic is developed and tested.
