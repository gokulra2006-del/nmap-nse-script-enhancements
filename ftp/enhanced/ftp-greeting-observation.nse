local comm = require "comm"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Collects the initial FTP or FTPS greeting banner and returns it as structured,
sanitized output. The script performs one unauthenticated connection only; it
does not send FTP commands, attempt anonymous login, or perform brute force.
]]

---
-- @args ftp-greeting-observation.timeout Time to wait for a greeting. Default: 5s.
-- @args ftp-greeting-observation.max-length Maximum displayed banner length.
-- Default: 160.
--
-- @output
-- 21/tcp open  ftp
-- | ftp-greeting-observation:
-- |   reply-code: 220
-- |   banner: Service ready
-- |_  collection: unauthenticated initial greeting only

author = "Gokul R (student proposal)"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service({21, 990}, {"ftp", "ftps"})

local function sanitize_banner(value, maximum)
  value = value:gsub("[\r\n\t]+", " ")
  value = value:gsub("[^%g ]", "?")
  value = value:gsub("%s+", " ")
  value = value:match("^%s*(.-)%s*$")
  if #value > maximum then
    value = value:sub(1, maximum - 3) .. "..."
  end
  return value
end

action = function(host, port)
  local timeout = stdnse.parse_timespec(stdnse.get_script_args(SCRIPT_NAME .. ".timeout")) or 5
  local maximum = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".max-length")) or 160
  maximum = math.max(32, math.min(maximum, 512))

  local status, banner = comm.get_banner(host, port, {timeout = timeout * 1000})
  if not status or type(banner) ~= "string" or banner == "" then
    return nil
  end

  local output = stdnse.output_table()
  output["reply-code"] = banner:match("^(%d%d%d)") or "not observed"
  output.banner = sanitize_banner(banner, maximum)
  output.collection = "unauthenticated initial greeting only"
  return output
end
