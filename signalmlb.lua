-- A simple Lua module for HAProxy that sends signals to the marathon-lb process

function run(cmd)
  local file = io.popen(cmd)
  local output = file:read('*a')
  local success, _, code = file:close()
  return output, success, code
end

function send_response(applet, code, response)
  applet:set_status(code)
  applet:add_header("content-length", string.len(response))
  applet:add_header("content-type", "text/plain")
  applet:start_response()
  applet:send(response)
end

core.register_service("signalmlbhup", "http", function(applet)
  local _, success, code = run("pkill -HUP -f '^python.*marathon_lb.py'")
  if not success then
    send_response(applet, 500, string.format(
    "Failed to send SIGHUP signal to marathon-lb (exit code %d). Is \z
    marathon-lb running in 'poll' mode?", code))
    return
  end

  send_response(applet, 200, "Sent SIGHUP signal to marathon-lb")
end)

core.register_service("signalmlbusr1", "http", function(applet)
  local _, success, code = run("pkill -USR1 -f '^python.*marathon_lb.py'")
  if not success then
    send_response(applet, 500, string.format(
    "Failed to send SIGUSR1 signal to marathon-lb (exit code %d). Is \z
    marathon-lb running in 'poll' mode?", code))
    return
  end

  send_response(applet, 200, "Sent SIGUSR1 signal to marathon-lb")
end)
