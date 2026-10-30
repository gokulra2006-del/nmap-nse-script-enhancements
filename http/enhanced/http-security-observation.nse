local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Collects a structured, observation-only inventory of modern browser-isolation,
permissions, reporting, and policy-reporting response headers. It is intended
to complement the existing broad HTTP security-header checks by making the
newer policy families easy to compare across authorised web services.

The script first attempts HEAD and falls back to GET only when HEAD is not
usable. It does not authenticate, crawl, submit forms, send an Origin header,
or treat missing headers as confirmed vulnerabilities.
]]

---
-- @arg http-security-observation.path Path to request. Default: /
-- @arg http-security-observation.useget Force GET instead of HEAD. Accepted values:
-- true or 1.
-- @usage
-- nmap -p 80,443 --script http-security-observation <target>
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | http-security-observation:
-- |   request: HEAD
-- |   permissions-policy: present
-- |   cross-origin-opener-policy: not observed
-- |   cross-origin-embedder-policy: present
-- |_  observation: header presence only; no vulnerability conclusion

author = "Gokul R"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.http

local function header_presence(headers, name)
  if headers and headers[name] then
    return "present"
  end
  return "not observed"
end

action = function(host, port)
  local path = stdnse.get_script_args(SCRIPT_NAME .. ".path") or "/"
  local useget = stdnse.get_script_args(SCRIPT_NAME .. ".useget")
  useget = useget == "true" or useget == "1"
  local request_type = "HEAD"
  local status, response

  if not useget then
    status, response = http.can_use_head(host, port, nil, path)
  end

  if not status then
    response = http.get(host, port, path)
    request_type = "GET"
  end

  if not (response and response.status) then
    return stdnse.format_output(false, "HTTP request failed")
  end

  local headers = response.header or {}
  local output = stdnse.output_table()
  output.request = request_type
  output.status = tostring(response.status)
  output["permissions-policy"] = header_presence(headers, "permissions-policy")
  output["cross-origin-opener-policy"] = header_presence(headers, "cross-origin-opener-policy")
  output["cross-origin-embedder-policy"] = header_presence(headers, "cross-origin-embedder-policy")
  output["cross-origin-resource-policy"] = header_presence(headers, "cross-origin-resource-policy")
  output["content-security-policy-report-only"] =
    header_presence(headers, "content-security-policy-report-only")
  output["reporting-endpoints"] = header_presence(headers, "reporting-endpoints")
  output["network-error-logging"] = header_presence(headers, "nel")
  output["clear-site-data"] = header_presence(headers, "clear-site-data")
  output.observation = "header presence only; no vulnerability conclusion"

  return output
end
