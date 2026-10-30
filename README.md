# Nmap NSE Script Enhancements: HTTP and FTP

**Author:** Gokul R  
**Project type:** Student proposal for review  

This repository separates official Nmap reference scripts from original,
observation-only student proposals. It is not an official Nmap repository and
none of the enhanced scripts have been accepted by the Nmap project.

## Repository layout

```text
http/
  base/http-headers.nse
  enhanced/http-security-observation.nse
ftp/
  base/banner.nse
  enhanced/ftp-greeting-observation.nse
```

## HTTP module

| File | Purpose |
| --- | --- |
| `http/base/http-headers.nse` | Official Nmap reference script. It requests a resource and displays returned headers. |
| `http/enhanced/http-security-observation.nse` | Student proposal that returns a structured, observation-only summary of selected headers, cookie presence, CORS, and HTTPS-aware HSTS status. |

Official source: https://github.com/nmap/nmap/blob/master/scripts/http-headers.nse

## FTP module

| File | Purpose |
| --- | --- |
| `ftp/base/banner.nse` | Official Nmap reference script for initial TCP banner collection. |
| `ftp/enhanced/ftp-greeting-observation.nse` | Student proposal that safely collects and sanitizes one unauthenticated FTP/FTPS greeting. It does not authenticate or send FTP commands. |

Official source: https://github.com/nmap/nmap/blob/master/scripts/banner.nse

## Local validation

Both enhanced scripts completed a basic Nmap load check with Nmap 7.99 on
localhost. This validates parsing and loading only; it is not an upstream Nmap
review or acceptance decision.

## Responsible use

Run the scripts only against services that you own or have explicit permission
to assess. Any future upstream submission must follow Nmap maintainer feedback
and testing requirements.
