# Testing notes

## Completed check

The enhanced scripts were loaded by Nmap 7.99 using a localhost scan. This
confirms that Nmap can parse and load the scripts.

```text
nmap --script ./ftp/enhanced/ftp-greeting-observation.nse -p 1 127.0.0.1
nmap --script ./http/enhanced/http-security-observation.nse -p 1 127.0.0.1
```

## HTTP modern-policy observation check

Test the HTTP script only against a web service that you own or are authorised
to assess:

```text
nmap -p 80,443 --script ./http/enhanced/http-security-observation.nse <test-host>
```

For a specific path, provide the path argument. To force a GET request when a
test service handles HEAD differently, set `useget` to `true`:

```text
nmap -p 443 --script ./http/enhanced/http-security-observation.nse \
  --script-args http-security-observation.path=/,http-security-observation.useget=true \
  <test-host>
```

Use the fixture in `tests/fixtures/modern-policy-headers.txt` as the expected
header set for a controlled test service. A successful result should report
the modern-policy headers as `present` and retain the observation-only wording.
Missing headers are reported as `not observed`; they are not vulnerability
findings.

## HTTP evidence checklist

- Save one authorised HTTP result and one authorised HTTPS result.
- Confirm that a server accepting HEAD reports `request: HEAD`.
- Confirm that `useget=true` reports `request: GET`.
- Confirm that no credentials, forms, crawling, or `Origin` header are used.
- Do not publish private hostnames, tokens, cookies, or sensitive header values.

## FTP capability-observation check

Before presenting the FTP script as ready for upstream review, test it only on
an FTP service that you own or are authorised to assess:

```text
nmap -p 21 --script ./ftp/enhanced/ftp-greeting-observation.nse <test-host>
```

Verify that the result records the initial `220` greeting, makes one `FEAT`
request, and lists only capabilities returned in a `211` response. Repeat this
check with a server that does not support `FEAT`; the script should report no
advertised capabilities and should not fail the scan.

## Implicit FTPS check

For an authorised implicit-FTPS service, test port 990:

```text
nmap -p 990 --script ./ftp/enhanced/ftp-greeting-observation.nse <test-host>
```

Confirm that the greeting and `FEAT` response are collected over TLS. Save the
sanitised Nmap output as test evidence; do not publish credentials, private
hostnames, or sensitive banners.

## Review checklist

- The script does not authenticate, enumerate files, or modify server state.
- The `FEAT` request is documented in the script description and output.
- Output is bounded and control characters are sanitised.
- Test output is collected for FTP, a server without `FEAT`, and implicit FTPS.
- A proposed Nmap pull request explains how this capability inventory differs
  from the existing general-purpose `banner.nse` script.
- A proposed HTTP pull request explains that the script focuses on modern
  browser-isolation, permissions, reporting, and policy-reporting headers.
