#Hoveroxy

A HTTP(S) proxy that support mutli-users authenticating by username and password. It works with HTTP/1.0 and HTTP/1.1, HTTP methods such as GET,POST,PUT,DELETE,HAVE,CONNECT supported.

##Usage

Hoveroxy uses `json` file to save the configurations. Here are the explanations of configurations:

`client.json`:

	{
		"server":"127.0.0.1",	//server IP address
		"server_port":2015,		//server Port
		"username":"xxx",		//for server to authenticate
		"password":"xxx",		//for server to authenticate
		"local":"127.0.0.1",	//for browser etc. to set proxy. should be local address
		"local_port":8888		//for browser etc. set proxy
	}

`server.json`:

	{
	"users":[{	//user one
		"username":"xxx",
		"password":"xxx",
		"mode":1,			//forbid mode: 0   allow mode: other numbers
		"allow":[],			//allowed urls or hosts
		"forbid":[]		 	//forbidden urls or hosts
	},{ //user two
		"username":"xxx",
		"password":"xxx",
		"mode":1,
		"allow":[],
		"forbid":[]
	}],
	"server":"127.0.0.1", //server IP
	"port":2015			  //server Port
	}

Run the command in your shell:
	
	python server.py

to act as the server, or:
	
	python client.py

to act as the client.

##Workflow

The client listen the local `(IP,PORT)` and connect to server `(IP,PORT)` use `(USERNAME,PASSWORD)` to get authenticated. If successfully, the server performs the HTTP Proxy and HTTPS Proxy. The client serves for the local applications such as Google Chrome. Steps as follows:

1. The browser sets Proxy Options to local (IP,PORT) and make a request;
2. The client gets the browser's request socket and do the authentication;
3. If success, client forwards the request to ther server, or failure and close socket;
4. The server forwards the request to the destination and return the result.

##Simplified Edition
`server.py` in HoverAgent directory is a HTTP(S) Proxy without authentication. So the browser acts as the client and there are not the client end.
