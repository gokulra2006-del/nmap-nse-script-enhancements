local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Collects a structured, observation-only summary of selected HTTP response
headers. The script first attempts a HEAD request and falls back to GET only
when the service does not support HEAD. It does not authenticate, crawl, submit
forms, or report missing headers as confirmed vulnerabilities.
]]

---
-- @args http-security-observation.path Path to request. Default: /
-- @args http-security-observation.useget Force GET instead of HEAD.
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | http-security-observation:
-- |   request: HEAD
-- |   content-security-policy: present
-- |   strict-transport-security: not assessed (HTTPS required)
-- |_  access-control-allow-origin: not observed

author = "Gokul R (student proposal)"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.http

local function header_value(headers, name)
  if headers and headers[name] then
    return tostring(headers[name])
  end
  return "not observed"
end

local function header_presence(headers, name)
  if headers and headers[name] then
    return "present"
  end
  return "not observed"
end

action = function(host, port)
  local path = stdnse.get_script_args(SCRIPT_NAME .. ".path") or "/"
  local useget = stdnse.get_script_args(SCRIPT_NAME .. ".useget")
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
  output.server = header_value(headers, "server")
  output["content-type"] = header_value(headers, "content-type")
  output["content-security-policy"] = header_presence(headers, "content-security-policy")
  output["x-content-type-options"] = header_presence(headers, "x-content-type-options")
  output["x-frame-options"] = header_presence(headers, "x-frame-options")
  output["referrer-policy"] = header_presence(headers, "referrer-policy")
  output["set-cookie"] = header_presence(headers, "set-cookie")
  output["access-control-allow-origin"] = header_value(headers, "access-control-allow-origin")

  if port.service == "https" or port.tunnel == "ssl" then
    output["strict-transport-security"] = header_presence(headers, "strict-transport-security")
  else
    output["strict-transport-security"] = "not assessed (HTTPS required)"
  end

  return output
end
