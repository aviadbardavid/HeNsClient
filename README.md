# HE-NS Client Infrastructure

HE-NS is a system which enables name resolution with homogeneous encryption.\
This means that the client is encrypting the query to the server, and the server does not have the key.\
The server will be able to answer to the encrypted query without decrypting it, and with no ability to collect any statistics whatsoever about any of the queries, not even by analyzing memory access.\
 This includes:\
    1. Top hitter queries\
    2. Query contents\
The queries may be extended in the future to wildcard queries, so that the server would be able to return more than one result to a single query.\
Please note that due to this, no input validation is being done for the search query before encryption (for academic purposes).\
The client/server communication is based on RestAPI. The client front-end and back-end communicate using post requests, and the client and HE-NS remote server communicate by GET requests.

The client is synchronized to be thread-safe which enabled a large number of machines/windows to work in parallel.
In order to preserve TOTAL browsing anonymity this is done using Tor:
* The query will be encrypted on both the query and HTTPS levels prior to entering the onion circuit
* The query is still encrypted on the query level upon leaving the onion circuit to the HE-NS server and it's origin is unknown
* Upon query decryption and availability to the front-end, the result will be an IP address, but it will be onion wrapped so that the destination of the user is unknown

Client-Server workflow:
1. Client front-end webpage(html/js based) submits the query to the client back-end(Python)
2. Client back-end responds that it started handling the query and encrypting the request
3. Client back-end encrypts the request and notifies the client front-end
4. Client back-end contacts the HE-NS server and notifies the client upon success/failure. Upon success the front-end is notified that the server is decrypting the result. Otherwise processing completes.
5. Client back-end returns a list of query results

Note: This is the infrastructure for supporting completely anonymous browsing. Actual encryption is to be added in the near future.

The Client consists of the following classes:
1. LoggerMixIn: \
 Each class needs to inherits this class in order to implement its own logger.
 Usage self.log.%log level%("Log message")                                    
 For example self.log.info("This is an example log message!")                 
 Logging is both for console and for for file with higher verbosity           

2. LoggerKeeper
Keeps the instances of each class intrinsic Logger.                          
Class is a singleton object                                                  
Class contains a thread-safe synchronized dict to prevent logger duplicates  


3. Request
A class which holds the request context and logic for it's own handling    


4. RequestManager:
A class which holds all concurrent requests:
This is a singleton which saves req contexts
MUST be synchronized to be thread-safe      


5. ServerHandler:
Server Handler - Class which handles requests from the client(s)                 
For each transaction between single/multi clients a new server thread is created 
Retrieves/Creates a request handler                                              
Init handling of request                                                         
Responsed to frontent with progress/ results                                     

6. ThreadingSimpleServer
For ThreadingMixIn to occur, making the SimpleHTTPServer multithreaded for processing POST requests from webpage.

7. Extra functionalities:
* A Scheduled periodic task which purges orphaned requests from the RequestManager after timeout
* Serving requests :-)

## Installation

Python ver: 3.6.7

For the back-end:
Use the package manager [pip](https://pip.pypa.io/en/stable/) to install:
    1. requests - to support RestAPI requests
    2. requests[socks] (this installs PySocks) - to support contacting the HE-NS server using TOR for anonymity



For the front-end:
1. Install Tor Browser
2. In browser proxy settings add to "No Proxy for"(proxy exclude list): 127.0.0.0/8 or any relevant IP addresses in case the client back-end resides on a server in a local LAN, serving multiple clients from multiple IP addresses.

## Usage

The package requirements are:\
astroid==2.0.1\
certifi==2018.11.29\
chardet==3.0.4\
colorama==0.3.9\
idna==2.8\
isort==4.3.4\
lazy-object-proxy==1.3.1\
mccabe==0.6.1\
py4j==0.10.6\
pylint==2.0.1\
PySocks==1.6.8\
pyspark==2.3.0\
requests==2.21.0\
rope==0.11.0\
six==1.11.0\
typed-ast==1.1.0\
urllib3==1.24.1\
wrapt==1.10.11

## CmdLine arguments:

usage: server.py [-h] -s SERVERHENSIP [-b BINDEDIP] [-l LOCALPORT]\
                 [-r REMOTEPORT] [--serverHeNsPath SERVERHENSPATH]\
                 [--torProxySchema {socks5,http,https}]\
                 [--torProxyPort TORPROXYPORT]\
                 [--torProxyIpAddr TORPROXYIPADDR]

optional arguments:\
  -h, --help            show this help message and exit\
  -b BINDEDIP, --bindedIp BINDEDIP\
                        Local binded IP address to listen for client requests\
                        - default is localhost only\
  -l LOCALPORT, --localPort LOCALPORT\
                        set local binding ip port - default 80\
  -r REMOTEPORT, --remotePort REMOTEPORT\
                        set remote HE-NS server listening port - default 5000\
  --serverHeNsPath SERVERHENSPATH\
                        set HE-NS server path for restAPI get request\
  --torProxySchema {socks5,http,https}\
                        Schema for tor proxy protocol - Default socks5\
  --torProxyPort TORPROXYPORT\
                        set port for local tor proxy for anonymous internet\
                        access - Default 9150\
  --torProxyIpAddr TORPROXYIPADDR\
                        set IP address for tor proxy, in case resides on other\
                        LAN machine - Default localhost

Required arguments:\
  -s SERVERHENSIP, --serverHeNsIp SERVERHENSIP\
                        IP address of remote HE-NS server

## Link to HE-NS server code
[HE-NS Server](https://github.com/YohaiMor/HE-DNS-Project.git)

## License
[MIT](https://choosealicense.com/licenses/mit/)
