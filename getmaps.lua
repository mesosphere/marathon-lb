-- A simple Lua script which serves up the HAProxy
-- vhost to backend map file.
function check_file_exists(name)
  local f = io.open(name, "r")
  if f ~= nil then io.close(f) return true else return false end
end

function read_file(filepath)
  -- Read all of the given file, returning an empty string if the file doesn't
  -- exist.
  local content = ""
  if check_file_exists(filepath) then
    local f = io.open(filepath, "rb")
    content = f:read("*all")
    f:close()
  end
  return content
end

function detect_config_dir()
  -- Read the process's (HAProxy's) cmdline proc and parse the path to the
  -- config file so that we can determine the config directory.
  local f = io.open("/proc/self/cmdline", "rb")
  local cmdline = f:read("*all")
  f:close()

  local found = false
  local sep = package.config:sub(1, 1)
  for opt in string.gmatch(cmdline, "%g+") do
    if opt == "-f" then
      found = true
    elseif found then
      return opt:match("(.*"..sep..")")
    end
  end
end

function load_map(filename)
  local config_dir = detect_config_dir()
  return read_file(config_dir..filename)
end

function send_map(applet, map)
  applet:set_status(200)
  applet:add_header("content-length", string.len(map))
  applet:add_header("content-type", "text/plain")
  applet:start_response()
  applet:send(map)
end

core.register_service("getvhostmap", "http", function(applet)
  local haproxy_vhostmap = load_map("domain2backend.map")
  send_map(applet, haproxy_vhostmap)
end)

core.register_service("getappmap", "http", function(applet)
  local haproxy_appmap = load_map("app2backend.map")
  send_map(applet, haproxy_appmap)
end)
