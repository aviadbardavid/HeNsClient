import http.server
import requests
import json
import time
import secrets
import threading
import logging
import sys

from socketserver import ThreadingMixIn
from http.server  import HTTPServer
from http.server  import urllib
from enum         import IntEnum
from threading    import Event
from argparse     import ArgumentParser
from time         import strftime


# Command line arguments parsing

parser = ArgumentParser()

requiredArgs = parser.add_argument_group('Required arguments')
requiredArgs.add_argument("-s", "--serverHeNsIp", action="store", required = True, type = str,
                    help="IP address of remote HE-NS server")

parser.add_argument("-b", "--bindedIp",            action="store", default="127.0.0.1",   type = str,
                    help="Local binded IP address to listen for client requests - default is localhost only")
parser.add_argument("-l", "--localPort",           action="store", default = 80,          type = int,
                    help="set local binding ip port - default 80")
parser.add_argument("-r", "--remotePort",          action="store", default = 5000,        type = int,
                    help="set remote HE-NS server listening port - default 5000")
parser.add_argument("--serverHeNsPath",            action="store", default = "/get/ip/",  type = str,
                    help="set HE-NS server path for restAPI get request")
parser.add_argument("--torProxySchema",            action="store", default = "socks5",    type = str,
                    help="Schema for tor proxy protocol - Default socks5",
                    choices = ["socks5","http","https"])
parser.add_argument("--torProxyPort",              action="store", default = 9150,        type = int,
                    help="set port for local tor proxy for anonymous internet access - Default 9150")
parser.add_argument("--torProxyIpAddr",            action="store", default = "127.0.0.1", type = str,
                    help="set IP address for tor proxy, in case resides on other LAN machine - Default localhost")



args = parser.parse_args()

# Start Region - Globals

def now():
    return time.time()

BINDED_IP                      =                       args.bindedIp
HENS_IP_ADDR                   = 'http://'           + args.serverHeNsIp
ON_PORT                        =                       args.localPort
HENS_PORT                      =                       args.remotePort
HENS_RELATIVE_PATH             =                       args.serverHeNsPath            
TOR_PROXY_SCHEMA               = args.torProxySchema + '://'
TOR_PROXY_PORT                 =                       args.torProxyPort
TOR_PROXY_IP_ADDR              =                       args.torProxyIpAddr
NEW_REQUEST_ID                 = '0'
INTERNAL_TOR_ENDPOINT          = TOR_PROXY_SCHEMA + TOR_PROXY_IP_ADDR + ':' + str(TOR_PROXY_PORT)
HENS_GET_IP_ENDPOINT           = HENS_IP_ADDR + ":" + str(HENS_PORT) + HENS_RELATIVE_PATH 
HENS_TIMEOUT                   = 30                     #seconds
PERIODIC_CLEANUP_TIMER         = 60                     #Every 60 seconds will cleanup orphaned requests from requests dict
MIN_TO_SEC                     = 60
ORPHANED_REQUEST_BREACH_TIME   = 2 * MIN_TO_SEC             
TIME_NEXT                      = now()
LOG_FILE_NAME_PREFIX           = 'HeNsClient'
NUM_PURGE                      = 1


#for future feature support
class RequestType(IntEnum):
    SIMPLE_REQUEST      = 1
    REQUEST_TYPE_MAX    = 2

    ERROR               = -1

class ClientState(IntEnum):
    UNINITIALIZED       = 0
    RECEIVE_REQUEST     = 25
    ENCRYPT_REQUEST     = 50
    QUERY_HE_NS_SERVER  = 75
    DECRYPT_REQUEST     = 100
    CLIENT_STATE_MAX    = 101

    ERROR               = -1

#####################################
###Start Region - Logging:       ####
#####################################

###############################################################################
#Each class needs to inherits this class in order to implement its own logger.#
#Usage self.log.%log level%("Log message")                                    #
#For example self.log.info("This is an example log message!")                 #
#Logging is both for console and for for file with higher verbosity           #
###############################################################################
class LoggerMixIn(object):
    @property
    def log(self):
        name = '.'.join([self.__class__.__name__])
        return LoggerKeeper().getLogger(name)


###############################################################################
#Keeps the instances of each class intrinsic Logger.                          #
#Class is a singleton object                                                  #
#Class contains a thread-safe synchronized dict to prevent logger duplicates  #
###############################################################################
class LoggerKeeper(object):
    class __LoggerKeeper():
        def __init__(self):
            self.singleUsageLock = Event()
            self.loggers         = dict()
            #Config root logger ---> Config all other loggers
            rootLogger = logging.getLogger()
            self.configLogger(rootLogger)

        
        def configLogger(self, newLogger):
            newLogger.setLevel(logging.DEBUG)
            formatter = logging.Formatter('%(asctime)s [%(name)-18s][%(threadName)-15s][%(levelname)-5s]: %(message)s')

            # Add verbose logging to file
            fileHandler = logging.FileHandler(strftime(LOG_FILE_NAME_PREFIX + "_%H_%M_%m_%d_%Y.log"))
            fileHandler.setLevel(logging.DEBUG)
            fileHandler.setFormatter(formatter)
            newLogger.addHandler(fileHandler)

            # Add logging to console
            consoleHandler = logging.StreamHandler()
            consoleHandler.setFormatter(formatter)
            consoleHandler.setLevel(logging.INFO)
            newLogger.addHandler(consoleHandler)

        @staticmethod
        def aquireLock():
            LoggerKeeper.loggerHolderInstance.singleUsageLock.set()

        @staticmethod
        def releaseLock():
            LoggerKeeper.loggerHolderInstance.singleUsageLock.clear()


    def __init__(self):
        if not LoggerKeeper.loggerHolderInstance:
            LoggerKeeper.loggerHolderInstance = LoggerKeeper.__LoggerKeeper()

    loggerHolderInstance = None

    #Caution: Assumes dictionary is locked by caller
    def doesLoggerExists(self, name):
        return name in self.loggerHolderInstance.loggers

    def getLogger(self, name):
        if self.loggerHolderInstance is None:
            self.loggerHolderInstance = LoggerKeeper.__LoggerKeeper()
    
        self.loggerHolderInstance.aquireLock()

        try:
            if self.doesLoggerExists(name):
                return self.loggerHolderInstance.loggers[name]
            else:
                return self.addLogger(name)

        except Exception:
            rootLogger = logging.getLogger()
            rootLogger.error("Expected logger was not found in logger dict, returning root logger!")
            return rootLogger

        finally:
            self.loggerHolderInstance.releaseLock()


    def addLogger(self, name):
        newLogger = logging.getLogger(name)
        self.loggerHolderInstance.loggers[name] = newLogger
        return newLogger



#################################################################################
###A class which holds the request context and logic for it's own handling    ###
#################################################################################
class Request(LoggerMixIn):
    def __init__(self, reqId, incomingMsg):
        self.log.info("Generating new request. Given ID: " + reqId)
        self.requestId            = reqId
        self.incomingMessage      = incomingMsg                  #The incoming JSON
        self.heNsResponseCode     = None                         #“Never make predictions, especially about the future.” - Yogi Berra
        self.responseCode         = None                         #“Never make predictions, especially about the future.” - Yogi Berra
        self.queryText            = incomingMsg['data']          #Actual query text
        self.requestType          = incomingMsg['type']          #Query type - for future support(e.g. simple query / wildcard query etc.)
        self.messageForClient     = ""                           #Message to display on frontend
        self.encryptedResultsList = None                         #List of the encrypted result(or results for wildcard query once implemented)
        self.decryptedResultsList = None                         #List of the decrypted result(or results for wildcard query once implemented)
        self.heNsQuery            = None                         #encrypted query to send to HE-NS server
        self.creationTime         = now()
        self.errorOccurred        = False
        self.unauthorisedRequest  = False
        self.previousState        = ClientState.UNINITIALIZED
        self.currentState         = ClientState.UNINITIALIZED


    #Process request context to generate the proper reply
    #Returns encoded
    def toJsonReply(self):
        jsonMessage = {'requestId': str(self.requestId), 'progress': int(self.currentState),
                       'text': self.messageForClient}
        if self.currentState == ClientState.DECRYPT_REQUEST:
            jsonMessage['resultsList'] = self.decryptedResultsList

        return json.dumps(jsonMessage).encode()


    ###################################################
    ###Start Region - Request parsing and processing###
    ###################################################
    def handle(self):

        isSuccess = False
        processingState = self.getUpdatedProcessingState()

        if processingState == ClientState.ERROR:
            return isSuccess

        if processingState == ClientState.RECEIVE_REQUEST:
            isSuccess = self.handleInitialRequest()

        elif processingState == ClientState.ENCRYPT_REQUEST:
            isSuccess = self.handleHeEncryption()

        elif processingState == ClientState.QUERY_HE_NS_SERVER:            
            isSuccess = self.handleQueryingHeNsServer()

        elif processingState == ClientState.DECRYPT_REQUEST:
            isSuccess = self.handleHeDecryption()

        self.previousState = self.currentState


        return isSuccess


    def getUpdatedProcessingState(self):

        if self.currentState == ClientState.ERROR:
            return ClientState.ERROR

        self.updateClientState()
        return self.currentState

    def getNewStateByStatusUpdate(self):

        if   self.incomingMessage['data'] == ClientState.RECEIVE_REQUEST:
            return ClientState.ENCRYPT_REQUEST

        elif self.incomingMessage['data'] == ClientState.ENCRYPT_REQUEST:
            return ClientState.QUERY_HE_NS_SERVER

        elif self.incomingMessage['data'] == ClientState.QUERY_HE_NS_SERVER:
            return ClientState.DECRYPT_REQUEST

        return ClientState.ERROR


    def updateClientState(self):

        if   self.incomingMessage['name'] == 'query':
            self.currentState = ClientState.RECEIVE_REQUEST

        elif self.incomingMessage['name'] == 'statusUpdate':
            self.currentState = self.getNewStateByStatusUpdate()

        else:
            self.currentState = ClientState.ERROR

        #verify the client sent the expected message type
        if not self.isRequestStateValid():
            self.unauthorisedRequest = True
            self.currentState        = ClientState.ERROR
            return


    ##############################################
    ###Start Region - Message handling:###########
    ##############################################
    def handleInitialRequest(self):

        self.messageForClient = "Encrypting Query with HE encryption"
        self.responseCode     = requests.codes.ok
        self.log.info("Replying to front-end: Going to handle the new request")

        return True

    def handleHeEncryption(self):

        self.log.info("Request Id: " + self.requestId +" Going to encrypt query with HE encryption")
        ######Encryption goes here#############
        time.sleep(2)  # simulate action#######
        self.heNsQuery = "$RSLAF#@!KFMAS_#$)"##
        #######################################
        self.log.info("Request Id: " + self.requestId +" - Query encryption succeded")
        self.messageForClient = "Querying HE-NS server"

        return True

    def handleQueryingHeNsServer(self):
        isHeNsQuerySuccess = False

        self.log.info("Request Id: " + self.requestId +" - Going to query HE-NS server")

        try:
            r = requests.get(
                            url     = HENS_GET_IP_ENDPOINT + urllib.parse.quote_plus(self.queryText),
                            proxies = self.getTorProxyConfigurationDict(),
                            timeout = HENS_TIMEOUT
                            )
            self.heNsResponseCode = r.status_code
            

            if self.heNsResponseCode == requests.codes.ok:
                self.log.info("Request Id: " + self.requestId +" - SUCCESS: HE-NS responded wth return code " + str(self.heNsResponseCode))
                isHeNsQuerySuccess = True
            
            else:
                self.log.error("Request Id: " + self.requestId +" - HE-NS responded wth return code " + str(self.heNsResponseCode))
                self.responseCode  = self.heNsResponseCode
                self.errorOccurred = True
                return isHeNsQuerySuccess
            
            self.log.info("Request Id: " + self.requestId +" - Parsing server JSON response")
            self.encryptedResultsList = r.json()
            print(self.encryptedResultsList)
            self.messageForClient = "Decrypting HE-NS server response"

        except requests.exceptions.Timeout:
            self.heNsResponseCode = requests.codes.request_timeout
            self.log.error("Request Id: " + self.requestId +" - Request timeout while querying HE-NS server")
            self.messageForClient = "Request timeout while querying HE-NS server"
            self.errorOccurred = True
            isHeNsQuerySuccess = False

        except Exception:
            if self.heNsResponseCode is None or self.heNsResponseCode == requests.codes.ok:
                self.log.error("Request Id: " + self.requestId +" - Exception was hit while querying HE-NS server")
                self.heNsResponseCode = requests.codes.internal_server_error

            if self.encryptedResultsList is None:
                self.heNsResponseCode = requests.codes.bad_request
                self.messageForClient = "HE-NS server provided malformed response"
            self.errorOccurred = True
            isHeNsQuerySuccess = False

        return isHeNsQuerySuccess

    @staticmethod
    def getTorProxyConfigurationDict():
        return dict(http=INTERNAL_TOR_ENDPOINT, https=INTERNAL_TOR_ENDPOINT)


    def handleHeDecryption(self):
        self.log.info("Request Id: " + self.requestId +" - Decrypting server's response")
        time.sleep(1)  # simulate action
        self.decryptedResultsList = self.encryptedResultsList #after decryption implementation place decrypt func here.
        self.log.info("Request Id: " + self.requestId +" - Server's response decrypted")

        return True

    #####################################
    ###Start Region - Error handling:####
    #####################################
    def determineErrorAndErrorMessage(self):
        if self.heNsResponseCode is None or self.heNsResponseCode == requests.codes.ok:
            self.responseCode     = requests.codes.internal_server_error
            self.messageForClient = "Unexpected client error occurred"

        elif self.heNsResponseCode < requests.codes.bad_request:
            self.responseCode     = requests.codes.internal_server_error
            self.messageForClient = "HE-NS server returned illegal response code: " + str(self.heNsResponseCode)

        else:
            self.responseCode     = self.heNsResponseCode

        if self.messageForClient is None or self.messageForClient == '':
            self.messageForClient = "Error getting results from HE-NS server"

        self.log.error("Request ID " + self.requestId + ": " + self.messageForClient)




    def updateErrorCodeAndErrorMessage(self):
        if self.unauthorisedRequest:
            self.log.warn("Request ID " + self.requestId + ": Received request with unexpected state from client!")
            self.responseCode     = requests.codes.forbidden
            self.messageForClient = "Unauthorized Request"

        elif self.errorOccurred:
            self.determineErrorAndErrorMessage()

    def didAnErrorOccur(self):
        return self.errorOccurred or self.unauthorisedRequest

    def isRequestStateValid(self):
        requestStateValid = False
        #Validate allowed transitions in server "mini state machine"
        if (self.currentState == ClientState.RECEIVE_REQUEST    and self.previousState == ClientState.UNINITIALIZED     )    or \
           (self.currentState == ClientState.ENCRYPT_REQUEST    and self.previousState == ClientState.RECEIVE_REQUEST   )    or \
           (self.currentState == ClientState.QUERY_HE_NS_SERVER and self.previousState == ClientState.ENCRYPT_REQUEST   )    or \
           (self.currentState == ClientState.DECRYPT_REQUEST    and self.previousState == ClientState.QUERY_HE_NS_SERVER):
                requestStateValid = True

        return requestStateValid



###################################################
###A class which holds all concurrent requests:####
###This is a singleton which saves req contexts####
###MUST be synchronized to be thread-safe      ####
###################################################
class RequestManager(LoggerMixIn):
    class __RequestManager():
        def __init__(self):
            self.singleUsageLock = Event()
            self.requests        = dict()

        @staticmethod
        def acquireLock():
            RequestManager.instance.singleUsageLock.set()

        @staticmethod
        def releaseLock():
            RequestManager.instance.singleUsageLock.clear()

    instance = None


    def __init__(self):
        if not RequestManager.instance:
            RequestManager.instance = RequestManager.__RequestManager()

    #Caution: Assumes dictionary is locked by caller
    def doesRequestExists(self, requestId):
        return requestId in self.instance.requests

    def getRequestById(self, requestId):
        self.instance.acquireLock()

        try:
            if self.doesRequestExists(requestId):
                return self.instance.requests[requestId]

        finally:
            self.instance.releaseLock()

        return None

    def addRequest(self, requestHandler):

        self.instance.acquireLock()

        try:
            id = str(requestHandler.requestId)
            if self.doesRequestExists(id):
                self.log.error("Request already exists: " + id)
                return False

            self.log.info("Inserting to dict request : " + id )
            self.instance.requests[id] = requestHandler

        finally:
            self.instance.releaseLock()


        return True

    def generateNewRequest(self, incomingMessage):
        newRequestId   = self.generateNewRequestId()
        requestHandler = Request(newRequestId, incomingMessage)

        if not self.addRequest(requestHandler):
            return None

        return requestHandler

    def generateNewRequestId(self):
        requestId = secrets.token_urlsafe(20)
        return requestId

    def removeRequest(self, requestId):
        removalSuccessful = False
        self.instance.acquireLock()
        try:

            if requestId == '-1':
                return removalSuccessful

            self.log.debug("Removing from dict request : " + requestId) 
            if self.doesRequestExists(requestId):
                del self.instance.requests[requestId]
                removalSuccessful = True
            else:
                self.log.error("Failed to remove from dict request : " + requestId) 


        finally:
            self.instance.releaseLock()

        return removalSuccessful

    def clearRequests(self):
        self.instance.requests.clear()

    def purgeOrphanedRequests(self):
        self.log.debug("Purging orphaned requests")
        self.purgeOrphanedRequestsFromDict()

    def getOrphanedRequestIDs(self):
        #dictionary size cannot be changed while iterating over it.
        #In order to prevent a runtime error if a request is added or deleted from another thread we:
        #   1.Lock the dictionary while collecting all orphaned request IDs.
        #   2.Remove all orphaned requests after dict iteration completion
        #This should be extremely quick so it won't raise a performance issue here.
        orphanedRequestsList = []
        self.instance.acquireLock()
        try:
            for requestId, request in self.instance.requests.items():
                self.addRequestToOrphanedListIfExpired(orphanedRequestsList, requestId, request)
        finally:
            self.instance.releaseLock()

        return orphanedRequestsList
        

    def addRequestToOrphanedListIfExpired(self, orphanedRequestsList, requestId, request):
        requestAgeInSeconds = now() - request.creationTime
        if requestAgeInSeconds > ORPHANED_REQUEST_BREACH_TIME:
            orphanedRequestsList.append(requestId)

    def purgeOrphanedRequestsFromDict(self):
        orphanedRequestsList       = self.getOrphanedRequestIDs()
        numOrphanedRequestsToPurge = len(orphanedRequestsList)

        if numOrphanedRequestsToPurge > 0:
            self.log.warn("Purging " + str(numOrphanedRequestsToPurge) + " orphaned requests from requests dictionary")
        else:
            self.log.debug("No orphaned requests - Life is good!")

        for orphanedRequestId in orphanedRequestsList:
            removalString = "Purged request: " if self.removeRequest(orphanedRequestId) else "Request was already removed: "
            self.log.warn("\t" + removalString + orphanedRequestId)


#######################################################################################
###This is where the threading magic happens - Using Threading Mix in                 #
###This enables the Python HTTP simple server to serve multiple request simultaneously#
#######################################################################################
class ThreadingSimpleServer(ThreadingMixIn, HTTPServer, LoggerMixIn):
    pass

######################################################################################
###Server Handler - Class which handles requests from the client(s)                 ##
###For each transaction between single/multi clients a new server thread is created ##
###Retrieves/Creates a request handler                                              ##
###Init handling of request                                                         ##
###Responsed to frontent with progress/ results                                     ##
######################################################################################
class ServerHandler(http.server.SimpleHTTPRequestHandler, LoggerMixIn):

    def do_POST(self):

        isSuccess = False

        try:
            request = self.getUpdatedRequestHandler()
            if request is not None:
                isSuccess = request.handle()

        except Exception:
            request = self.makeTempErroneousRequestHandler()

        self.respondToFrontEnd(request, isSuccess)




    def respondToFrontEnd(self, request, isSuccess):
        isSuccess = isSuccess and self.handleInternalErrorsIfOccurred(request)

        if isSuccess:
            self.handleSuccess(request)
        else:
            self.handleError(request)


    def handleInternalErrorsIfOccurred(self, request):
        isSuccess = True

        #The below should never happen, but here to make sure reply on error always works
        if request is None:
            self.log.error("Since when did pigs started to fly? THIS SHOULD NEVER HAPPEN! if we're here something is severly wrong")
            request  = self.makeTempErroneousRequestHandler()
            isSuccess = False

        if request.currentState == ClientState.QUERY_HE_NS_SERVER and request.heNsResponseCode is None:
            request.heNsResponseCode = requests.codes.internal_server_error
            isSuccess                = False


        return isSuccess



    def handleSuccess(self, successfulRequest):
        self.log.info("Request ID: "+ successfulRequest.requestId +" - Responding success to client")
        self.send_response(successfulRequest.responseCode)
        self.end_headers()
        self.wfile.write(successfulRequest.toJsonReply())
        if successfulRequest.currentState == ClientState.DECRYPT_REQUEST:
            RequestManager().removeRequest(successfulRequest.requestId)

    def handleError(self, erroneousRequest):
        self.log.error("Responding to frontend on error!")
        erroneousRequest.updateErrorCodeAndErrorMessage()
        self.send_response(erroneousRequest.responseCode)
        self.end_headers()
        self.wfile.write(erroneousRequest.toJsonReply())

        RequestManager().removeRequest(erroneousRequest.requestId)

    @staticmethod
    def generateIncomingError():
        jsonErrorMessage =  '{ "requestId" : -1, "data" : -1, "type" : -1 }'
        
        return json.loads(jsonErrorMessage)

    def parseIncomingMessage(self):
        content_length = int(self.headers['Content-Length'])
        body           = self.rfile.read(content_length)
        decodedMessage = body.decode('utf-8')

        self.log.info("Received from client: " + decodedMessage)

        return json.loads(decodedMessage)

    def getUpdatedRequestHandler(self):
        incomingMessage = self.parseIncomingMessage()

        if incomingMessage is None:
            self.log.error("Could not parse request")
            return self.makeTempErroneousRequestHandler()

        requestId = incomingMessage['requestId']

        if requestId == NEW_REQUEST_ID:
            return RequestManager().generateNewRequest(incomingMessage)
        else:
            requestHandler = RequestManager().getRequestById(requestId)

        if requestHandler is None:
            self.log.error("Failed to create or get the request's handler")
            return self.makeTempErroneousRequestHandler()
        
        requestHandler.incomingMessage = incomingMessage

        return requestHandler

    def makeTempErroneousRequestHandler(self):
        self.log.error("Generating a temporary errored request")
        erroneousRequestHandler               = Request('-1', self.generateIncomingError())
        erroneousRequestHandler.errorOccurred = True
        erroneousRequestHandler.currentState  = ClientState.ERROR
        erroneousRequestHandler.responseCode  = requests.codes.internal_server_error
        self.log.debug("Errored request generated")

        return erroneousRequestHandler

#####################################
###Start Region - Periodic tasks:####
#####################################

#This method inits a periodic requests dictionary cleanup for orphaned requests
#this is done by calling the request manager to cleanup the dictionary and schedule it again according to the timer repeatedly
def initPeriodicRequestsDictCleaner():
    RequestManager().purgeOrphanedRequests()
    scheduleExpiredRequestsPurging()


def scheduleExpiredRequestsPurging():
    global TIME_NEXT
    global NUM_PURGE
    TIME_NEXT = TIME_NEXT + PERIODIC_CLEANUP_TIMER
    periodicCleanupThread = threading.Timer(TIME_NEXT - now(), initPeriodicRequestsDictCleaner)
    periodicCleanupThread.setDaemon(True)
    periodicCleanupThread.setName('Sched-Purge-' +str(NUM_PURGE))
    periodicCleanupThread.start()
    NUM_PURGE = NUM_PURGE + 1 if NUM_PURGE < 999 else 1

def printRunningConfiguration(httpd):
    httpd.log.info("Dynamic server config:")
    httpd.log.info("\t\tIP:Port socket to serve on:\t" + "http://" + BINDED_IP + ":" + str(ON_PORT))
    httpd.log.info("\t\tLocal Tor Proxy endpoint:\t" + INTERNAL_TOR_ENDPOINT)
    httpd.log.info("\t\tHE-NS server endpoint:\t\t" + HENS_GET_IP_ENDPOINT)
    httpd.log.info("")
    httpd.log.info("")
    httpd.log.info("")
    httpd.log.info("Let the fun begin!")
    httpd.log.info("")
    httpd.log.info("")
    httpd.log.info("")


#####################################
###Start Region - HTTP server main:##
#####################################

########################################
###Serves the HTTP requests           ##
########################################
multiThreadedHttpServer = ThreadingSimpleServer((BINDED_IP, ON_PORT), ServerHandler, LoggerMixIn)
with multiThreadedHttpServer as httpd:
    sa = httpd.socket.getsockname()

    
    httpd.log.info("Serving HTTP on " + str(sa[0]) + " port "+ str(sa[1]) +  "...")

    printRunningConfiguration(httpd)

    scheduleExpiredRequestsPurging()

    httpd.serve_forever()