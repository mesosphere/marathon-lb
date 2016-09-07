-- A simple Lua script which serves up the HAProxy
-- vhost to backend map file.
function check_file_exists(name)
   local f=io.open(name,"r")
   if f~=nil then io.close(f) return true else return false end
end

function read_map_file(filename, cmdline)
  local found = false
  local filename = ''
  for s in string.gmatch(cmdline, '%g+') do
    if s == '-f' then
      found = true
    elseif found then
      path = s
      sep = package.config:sub(1,1)
      path = path:match("(.*"..sep..")")..filename
      break
    end
  end

  local map = ''
  if check_file_exists(path) then
    local f = io.open(path, "rb")
    map = f:read("*all")
    f:close()
  else
    map = ''
  end
  return map
end

function load_map(filename)
  local f = io.open('/proc/self/cmdline', "rb")
  local cmdline = f:read("*all")
  f:close()
  return read_map_file(filename, cmdline)
end

function send_map(applet, map)
  applet:set_status(200)
  applet:add_header("content-length", string.len(map))
  applet:add_header("content-type", "text/plain")
  applet:start_response()
  applet:send(map)
end

core.register_service("getvhostmap", "http", function(applet)
  local haproxy_vhostmap = load_vhostmap("domain2backend.map")
  send_map(applet, haproxy_vhostmap)
end)

core.register_service("getappmap", "http", function(applet)
  local haproxy_appmap = load_vhostmap("app2backend.map")
  send_map(applet, haproxy_appmap)
end)
