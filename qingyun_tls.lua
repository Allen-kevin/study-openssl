local counter = 1
local threads = {}

function setup(thread)
	thread:set("id", counter)
	table.insert(threads, thread)
	counter = counter + 1
end

function init(args)
	requests = 0
	
	local msg = "thread %d created"
	print(msg:format(id))
end

request = function ()
	requests = requests + 1
	if (math.fmod(requests,2) == 0)
	then
		wrk.method = "POST"
		wrk.body = "post, hello world"
		wrk.headers["Content-Type"] = "text/html"
	else
		wrk.method = "GET"
		wrk.body = ""
		wrk.headers["Content-Type"] = "text/html"
	end
	path = "/test?uid=" .. requests
	return wrk.format(nil, path)

end
