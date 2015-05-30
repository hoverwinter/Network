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
		"mode":1,			//forbid mode: 0   allow mode: 1   phishing: 2   other numbers: not dealing
		"allow":[],			//allowed urls : regex rules
		"forbid":[]		 	//forbidden urls : regex rules
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

You can use SwitchySharp in Chrome to manage the proxy easily.

##Workflow

The client listen the local `(IP,PORT)` and connect to server `(IP,PORT)` use `(USERNAME,PASSWORD)` to get authenticated. If successfully, the server performs the HTTP Proxy and HTTPS Proxy. The client serves for the local applications such as Google Chrome. Steps as follows:

1. The browser sets Proxy Options to local (IP,PORT) and make a request;
2. The client gets the browser's request socket and do the authentication;
3. If success, client forwards the request to ther server, or failure and close socket;
4. The server forwards the request to the destination and return the result.

##Filter

`server.json` specify the user's Access Control Mode, which allows the server to filter the client's http request:

- mode `0`: items in `forbid` acts and only the requests matching the patterns are forbidden.
- mode `1`: items in `allow` acts and only the requests matching the patterns are allowed.

You can set the rules throw `Python Regex Syntax`.

##Phishing

`server.json` also specify the websites to phishing, which allows the server to response with another website:

- mode `2`: items in `phishing` acts. Client requests for a website and gets another.

##Just for Link

`server.json` if mode > `2`, no filtering and phishing will be performed!

##Issues

1. Rules can be easy to collapse, and sometimes don't act as usual. A complex and convient rules shuold be set.
2. Too many request can lead the client to collapse.
3. Phishing only acts between Http requests. There is a gap between HTTP Request and HTTPS Request. And when HTTPS involved, thing will be worse.

##License

Copyright 2015  Hover Winter(carpela@163.com)

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

[http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

