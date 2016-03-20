-- A simple Lua module for HAProxy which returns
-- a list of all the current HAProxy PIDs by using
-- the unix `pidof` command.
-- :)

function os.capture(cmd)
  local f = assert(io.popen(cmd, 'r'))
  local s = assert(f:read('*a'))
  f:close()
  s = string.gsub(s, '^%s+', '')
  s = string.gsub(s, '%s+$', '')
  s = string.gsub(s, '[\n\r]+', ' ')
  return s
end

core.register_service("getpids", "http", function(applet)
  local response = os.capture("pidof haproxy", false)
  applet:set_status(200)
  applet:add_header("content-length", string.len(response))
  applet:add_header("content-type", "text/plain")
  applet:start_response()
  applet:send(response)
end)
