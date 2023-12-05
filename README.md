# SEC Code Descriptions for PS scripts
| Security Code | Description |
|:-------------:|:-----------:|
| `SEC0` | SEARCH/FILTER descriptions on Active Directory based on SEC codes |
| `SEC1` | TAGS inactive Computer accounts | 
| `SEC2` | DISABLE user/computer accounts (including external contractors, service accounts) |
| `SEC3` | MOVES user/computer accounts to corresponding disabled OU/status with cautionary checks |
| `SEC4` | CREDENTIAL LEAK! Disables user account and tags description for follow-up procedures |
| `SEC5` | Just-In-Time Access for user/service accounts |
| `SEC6` | Soft-delete user/computer object for 30days |
| `SEC7` | Check for password expirations for user/computer objects |
| `SEC8` | |
| `SEC9` | |
| `SEC10` | |
| `SEC11` | Reads SMB/TLS/Hashes from Registry Editor |
| `SEC12` | Reads RDP logon sessions that occurred recently on a server |
| `SEC13` | Checks service account credentials, ensuring bad login thresholds (1) and account lockout checking |
| `SEC14` | Checks enabled computers without LAPS and inactivity (60 days). Run script in phases (description, pings, disables) |
