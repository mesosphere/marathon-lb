-- A simple Lua script which serves up the HAProxy
-- vhost to backend map file.
function check_file_exists(name)
   local f=io.open(name,"r")
   if f~=nil then io.close(f) return true else return false end
end

function read_vhostmap_file(cmdline)
  local found = false
  local filename = ''
  for s in string.gmatch(cmdline, '%g+') do
    if s == '-f' then
      found = true
    elseif found then
      filename = s
      sep = package.config:sub(1,1)
      filename=filename:match("(.*"..sep..")").."domain2backend.map"
      break
    end
  end
 
  local map = ''
  if check_file_exists(filename) then
    local f = io.open(filename, "rb")
    map = f:read("*all")
    f:close()
  else
    map = ''
  end
  return map
end

function load_vhostmap()
  local f = io.open('/proc/self/cmdline', "rb")
  local cmdline = f:read("*all")
  f:close()
  return read_vhostmap_file(cmdline)
end

core.register_service("getvhostmap", "http", function(applet)
  local haproxy_vhostmap = load_vhostmap()
  applet:set_status(200)
  applet:add_header("content-length", string.len(haproxy_vhostmap))
  applet:add_header("content-type", "text/plain")
  applet:start_response()
  applet:send(haproxy_vhostmap)
end)

