local comm = require "comm"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Collects and normalizes the initial FTP or implicit-FTPS greeting into a small
structured observation record. It extracts the FTP reply code, identifies
multiline greeting syntax when present, and safely displays a bounded,
sanitized greeting. It then sends the standard unauthenticated FEAT command
and reports only the capabilities explicitly advertised by the server.

The script makes one unauthenticated connection and one read-only protocol
request (FEAT). It does not attempt login, enumerate files, change server
state, or perform brute force.
]]

---
-- @arg ftp-greeting-observation.timeout Time to wait for a greeting. Default: 5s.
-- @arg ftp-greeting-observation.max-length Maximum displayed banner length.
-- Default: 160.
-- @usage
-- nmap -p 21,990 --script ftp-greeting-observation <target>
--
-- @output
-- 21/tcp open  ftp
-- | ftp-greeting-observation:
-- |   reply-code: 220
-- |   greeting: Service ready
-- |   multiline: false
-- |   features:
-- |     UTF8
-- |     MDTM
-- |_  collection: greeting plus one unauthenticated FEAT request

author = "Gokul R"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = shortport.port_or_service({21, 990}, {"ftp", "ftps"})

local function bounded_number(argument, default, minimum, maximum)
  local value = tonumber(argument)
  if not value then
    return default
  end
  return math.max(minimum, math.min(value, maximum))
end

local function sanitize_greeting(value, maximum)
  value = value:gsub("[\r\n\t]+", " ")
  value = value:gsub("[^%g ]", "?")
  value = value:gsub("%s+", " ")
  value = value:match("^%s*(.-)%s*$")
  if #value > maximum then
    value = value:sub(1, maximum - 3) .. "..."
  end
  return value
end

local function reply_details(banner)
  local code, separator = banner:match("^(%d%d%d)([- ])")
  return code or "not observed", separator == "-"
end

local function receive_ftp_reply(socket, maximum_lines)
  local status, line = socket:receive_lines(1)
  if not status or type(line) ~= "string" then
    return nil
  end

  local lines = {line}
  local code, separator = line:match("^(%d%d%d)([- ])")
  if separator ~= "-" then
    return table.concat(lines, "\n")
  end

  for _ = 1, maximum_lines - 1 do
    status, line = socket:receive_lines(1)
    if not status or type(line) ~= "string" then
      break
    end
    lines[#lines + 1] = line
    if line:match("^" .. code .. " ") then
      break
    end
  end
  return table.concat(lines, "\n")
end

local function advertised_features(reply, maximum, maximum_lines)
  local features = {}
  if not reply or not reply:match("^211[- ]") then
    return features
  end

  for line in reply:gmatch("[^\r\n]+") do
    local feature = line:gsub("^211[- ]?%s*", "")
    feature = feature:match("^%s*(.-)%s*$")
    if feature ~= "" and feature:lower() ~= "features:"
        and not feature:lower():match("^end") then
      features[#features + 1] = sanitize_greeting(feature, maximum)
      if #features >= maximum_lines then
        break
      end
    end
  end
  return features
end

action = function(host, port)
  local timeout = stdnse.parse_timespec(stdnse.get_script_args(SCRIPT_NAME .. ".timeout")) or 5
  timeout = math.max(1, math.min(timeout, 30))
  local maximum = bounded_number(
    stdnse.get_script_args(SCRIPT_NAME .. ".max-length"), 160, 32, 512)

  local options = {timeout = timeout * 1000, recv_before = true}
  if port.number == 990 or port.service == "ftps" then
    options.proto = "ssl"
  end

  local socket, _, banner = comm.opencon(host, port, nil, options)
  if not socket or type(banner) ~= "string" or banner == "" then
    return nil
  end

  local output = stdnse.output_table()
  local reply_code, multiline = reply_details(banner)
  output["reply-code"] = reply_code
  output.greeting = sanitize_greeting(banner, maximum)
  output.multiline = multiline
  local sent = socket:send("FEAT\r\n")
  if sent then
    local reply = receive_ftp_reply(socket, 32)
    output["feat-reply-code"] = reply and reply:match("^(%d%d%d)") or "not observed"
    local features = advertised_features(reply, maximum, 32)
    if #features > 0 then
      output.features = features
    else
      output.features = "not advertised or not supported"
    end
  else
    output.features = "not collected"
  end
  socket:close()
  output.collection = "greeting plus one unauthenticated FEAT request"
  return output
end
