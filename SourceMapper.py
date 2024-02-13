from burp import IBurpExtender
from burp import IBurpExtenderCallbacks
from burp import IHttpListener
from burp import ITab
from burp import IScanIssue, IScannerCheck
from burp import IHttpRequestResponse, IHttpService
import re
import unicodedata
from os.path import exists
from jarray import array
from javax.swing import (GroupLayout, JPanel, JCheckBox, JTextField, JLabel, JButton)
import json


class BurpExtender(IBurpExtender, IHttpListener, ITab, IScannerCheck, IBurpExtenderCallbacks, IHttpRequestResponse, IScanIssue):


    def debug(self, message, lvl=1):
        if int(self.debugLevel.text) >= lvl:
            try:
                print(message)
            except UnicodeEncodeError:
                encodedMessage = message.encode('utf-8')
                print(encodedMessage)
        return


    def registerExtenderCallbacks(self, callbacks):

        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        # define all the options for the config tab
        self.onlyInScope = self.defineCheckBox('Only in scope resources', True)
        self.onlyInScope.setToolTipText('Check to only work within the defined scope')
        #automatically set the program to inject into header but leave the alternative body comment method disabled
        self.header = self.defineCheckBox('Sourcemap directive to header', True)
        self.header.setToolTipText('Check to inject sourcemap directive to header')
        self.body = self.defineCheckBox('Sourcemap directive to body', False)
        self.body.setToolTipText('Check to inject sourcemap directive to body')

        self.debugLevel = JTextField(str(1), 1)
        self.debugLevelLabel = JLabel('Debug level (0-3)')
        self.debugLevel.setToolTipText('Values 0-3, bigger number is more debug output, 0 is zero debug output')
        self.debugLevelGroup = JPanel()
        self.debugLevelGroup.add(self.debugLevelLabel)
        self.debugLevelGroup.add(self.debugLevel)

        self.mapInjectionFilesPath = JTextField('/home/user/mapfiles/')
        self.mapInjectionFilesPathLabel = JLabel('Location to map files on local disk')
        self.mapInjectionFilesPath.setToolTipText('Absolute paths recommended.  Files must have the same name and '
                                                  'file extension as original resource with the additional \'.map\' '
                                                  'file extension')
        self.mapInjectionFilesPathGroup = JPanel()
        self.mapInjectionFilesPathGroup.add(self.mapInjectionFilesPathLabel)
        self.mapInjectionFilesPathGroup.add(self.mapInjectionFilesPath)

        # build the settings tab
        self.tab = JPanel()
        layout = GroupLayout(self.tab)
        self.tab.setLayout(layout)
        layout.setAutoCreateGaps(True)
        layout.setAutoCreateContainerGaps(True)
        layout.setHorizontalGroup(
            layout.createSequentialGroup()
            .addGroup(layout.createParallelGroup()
                .addComponent(self.onlyInScope, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                .addComponent(self.mapInjectionFilesPathGroup, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                .addComponent(self.debugLevelGroup, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                .addComponent(self.header, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                .addComponent(self.body, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
                      )
        )
        layout.setVerticalGroup(
            layout.createSequentialGroup()
            .addComponent(self.onlyInScope, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
            .addComponent(self.mapInjectionFilesPathGroup, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
            .addComponent(self.debugLevelGroup, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
            .addComponent(self.header, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
            .addComponent(self.body, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE, GroupLayout.PREFERRED_SIZE)
        )



        # start "doing" things for real
        self.debug('Loading extension...')
        
        callbacks.setExtensionName('SourceMapper')
        callbacks.registerHttpListener(self)
        callbacks.addSuiteTab(self)
        callbacks.registerScannerCheck(self)

        global issueDict
        issueDict = {}


    def defineCheckBox(self, caption, selected=True, enabled=True):
        checkBox = JCheckBox(caption)
        checkBox.setSelected(selected)
        checkBox.setEnabled(enabled)
        return checkBox


    def getTabCaption(self):
        return ('Source Mapper')


    def getUiComponent(self):
        return self.tab


    def processHttpMessage(self, toolFlag, messageIsRequest, message):

        global intStatus
        global sourceMapDirectiveFound
        global embeddedSourceMapDirectiveFound
        global invalid200
    
        intStatus = None
        sourceMapDirectiveFound = None
        embeddedSourceMapDirectiveFound = None
        invalid200 = None

        self.debug('Processing message...', 3)
        # we only process the responses (and get the bits of the request we need when they are responded to)
        if messageIsRequest:
            self.debug('Message is a REQ so discarding', 3)
            return

        httpService = message.getHttpService()
        request = self._helpers.analyzeRequest(httpService, message.getRequest())
        reqURL = request.getUrl()
        

        # check if the requested resource is within permitted scope
        if self.onlyInScope.isSelected() and not self._callbacks.isInScope(reqURL):
            self.debug('Not in-scope and only in-scope permitted', 2)
            return 
        else:
            # ignore any query string parameters
            reqResource = str(reqURL).split('?')[0]
            self.debug('Resource in full: ' + reqResource, 3)

        # if the resource requested is either a JS file or a CSS file then mark it for processing
        isTargetResource = False
        isMapResource = False
        resourceIsJS = False
        resourceIsCSS = False

        # pull the headers fairly early so that we can check for MIME types as well as file extensions to identify
        # source mappable content
        resInfo = self._helpers.analyzeResponse(message.getResponse())
        resHeaderBytes = message.getResponse()[:resInfo.getBodyOffset()]
        resHeaderStr = self._helpers.bytesToString(resHeaderBytes)

        #check type of resource
        if re.search("\.js$", reqResource) or re.search('Content-Type: text/javascript', resHeaderStr,
                                                        flags=re.IGNORECASE):
            isTargetResource = True
            resourceIsJS = True
        if re.search("\.css$", reqResource):
            isTargetResource = True
            resourceIsCSS = True
        if re.search("\.map$", reqResource):
            isMapResource = True
        else:
            mapFileFound = False

            
        if isTargetResource or isMapResource:
            resBodyBytes = message.getResponse()[resInfo.getBodyOffset():]
            resBodyStr = self._helpers.bytesToString(resBodyBytes)
            self.debug("Res body: " + resBodyStr[:40], 3)

            #find source map directive
            sourceMapDirectiveFound = False
        
            if resourceIsJS or resourceIsCSS:
                #check whether a source map exists
                if re.search('X-SourceMap:', resHeaderStr):
                    sourceMapDirectiveFound = True
                    issueDict.update({str(reqURL): "directive"})
                    
                    
                elif re.search('//# sourceMappingURL=', resBodyStr):
                    embeddedSourceMapDirectiveFound = True
                    issueDict.update({str(reqURL): "embedded"})
                    
                
                else:
                    self.debug("No sourcemap directive found", 2)

                #check whether the header checkbox is selected
                #if so inject sourcemap into header
                #if header & body checkboxes both selected, inject into header
                if self.header.isSelected():
                    #insert source map directive into header
                    sourcemapHeader = '\r\nX-SourceMap: ' + reqResource + '.map\r\n\r\n'
                    resHeaderStr = resHeaderStr.strip()
                    newResHeaderStr = resHeaderStr + sourcemapHeader
                    newResHeaderBytes = array(bytearray(newResHeaderStr.encode('utf-8')), 'b')
                    message.setResponse(newResHeaderBytes + resBodyBytes)
                    self.debug('Sourcemap directive injected into header', 1)
                    self.debug('New Res header: ' + str(newResHeaderStr.strip()), 2)
                    
                #if SRI header checkbox not selected, check whether body checkbox is selected
                #if so inject sourcemap into body
                elif self.body.isSelected():
                    sourcemapDirectiveStr = '//# sourceMappingURL=' + reqResource + '.map' + '\n'
                    sourcemapDirectiveBytes = array(bytearray(sourcemapDirectiveStr.encode('utf-8')), 'b')
                    newResBodyBytes = sourcemapDirectiveBytes + resBodyBytes
                    newResBodyStr = self._helpers.bytesToString(newResBodyBytes)
                    sourceMapDirectiveLen = len(sourcemapDirectiveStr)
                    self.debug('New Res body: ' + str(newResBodyStr[:40]), 2)
                    
                    # body has been changed so Content-Length headers probably need changing
                    # Update the Content-Length headers, if needed
                    if re.search('Content-Length: ', resHeaderStr, re.IGNORECASE):
                        self.debug('Content-Length header needs update, sending new body with updated headers', 2)

                        self.debug('Full headers from request are:\n{}'.format(resHeaderStr), 3)
                        originalContentLengthHeader = re.findall(r'^Content-Length: (?:[0-9]+)', resHeaderStr,
                                                                flags=re.IGNORECASE | re.MULTILINE)
                        self.debug('Content length header is: {}'.format(originalContentLengthHeader))
                        if len(originalContentLengthHeader) > 1:
                            self.debug('Multiple Content-Length headers found, only updated the first', 2)
                        self.debug('The whole rsplit identifying the header: {}'.
                                format(originalContentLengthHeader[0].rsplit(' ')))
                        # calculate the length of the body following the additional content being injected
                        # we don't want to blat the original value with a newly calculated value because
                        # we want to retain any original application behaviour
                        originalContentLengthHeaderKey = originalContentLengthHeader[0].rsplit(' ', 1)[0] + ' '
                        originalContentLengthHeaderValue = int(originalContentLengthHeader[0].split(' ')[-1])
                        newContentLengthHeaderValue = originalContentLengthHeaderValue + sourceMapDirectiveLen
                        self.debug('Original content length header is: {}'.format(originalContentLengthHeader[0]), 2)
                        self.debug('Injected header is {} bytes.  New Content-Length header should be {} bytes'.
                                format(sourceMapDirectiveLen, newContentLengthHeaderValue), 2)
                        newResHeaderStr = re.sub(r'^Content-Length: (?:[0-9]+)', originalContentLengthHeaderKey +
                                                str(newContentLengthHeaderValue), resHeaderStr, count=1,
                                                flags=re.IGNORECASE | re.MULTILINE)
                        newResHeaderBytes = array(bytearray(newResHeaderStr.encode('utf-8')), 'b') 
                        
                        message.setResponse(newResHeaderBytes + newResBodyBytes)
                        self.debug('Sourcemap directive injected into body', 1)

                    #if Content-Length headers don't need changing, inject with original headers
                    else:
                        self.debug('No Content-Length header to update, sending new body with original headers', 2)
                        message.setResponse(resHeaderBytes + newResBodyBytes)
                        self.debug('Sourcemap directive injected into body', 1)
                
                #if neither checkbox is selected, prompt user to specify
                else:
                    self.debug('Specify where to inject source map directive', 0)

            # eventually the browser will request a map file, either because it was going to anyway or because we
            # injected the directive, we must handle it
            if isMapResource:
                self.debug('Map resource requested: ' + reqResource, 1)
                invalid200 = False
                statusCheck = False
                intStatus = 0

                #turn the header into a list to make it easier to iterate over
                L1 = resHeaderStr.split(' ')
                for i in range(len(L1)-1):
                    listVariable = L1[i]
                    listVariable = str(listVariable)
                    x = re.search("Status", listVariable, re.IGNORECASE)
                    StatusOK = re.search("200 OK", resHeaderStr, re.IGNORECASE)
                    StatusNotModified = re.search("304 Not Modified", resHeaderStr, re.IGNORECASE)

                    if x != None:
                        #the status of the URL will be the next list item
                        status = L1[i+1]
                        #we just need the number
                        status, y = status.split('\n')

                        try:
                            intStatus = int(status)
                            statusCheck = True
                        except:
                            pass
                    
                    if StatusOK != None:
                        intStatus = 200
                        statusCheck = True

                    if StatusNotModified != None:
                        intStatus = 304
                        statusCheck = True

                    if statusCheck == True and (intStatus == 200 or intStatus == 304):
                        if intStatus == 200:
                            self.debug("Status OK - 200", 3)
                            try:
                                #load the map file
                                mapFile = json.loads(resBodyStr)

                                #a source map should have all of these
                                if ("version" in mapFile) and ("names" in mapFile) and ("mappings" in mapFile):
                                    intStatus = 200
                                    issueDict.update({str(reqURL): "200"})
                                else:
                                    self.debug("Cannot confirm validility of source map", 1)
                                    invalid200 = True
                                    issueDict.update({str(reqURL): "invalid"})

                            except json.JSONDecodeError:
                                self.debug("JSON decode error")
                                invalid200 = True
                                issueDict.update({str(reqURL): "invalid"})

                        if intStatus == 304:
                            self.debug("Status 304 Not Modified. Source map is unable to be validated.", 3)
                            issueDict.update({str(reqURL): "304"})

                    if statusCheck == False:
                        self.debug("Status not found", 3)

                            
                                                                
                # check the map being downloaded looks syntactically valid before attempting to inject ours
                if re.search('^var map = {"version"', resBodyStr):
                    self.debug('Map file start is valid, skipping', 2)


                #attempt to inject map file from own folders (file path as entered in mapInjectionFilesPath variable)
                else:
                    self.debug('Requested map file not valid, attempting to inject', 2)
                    resourceFileName = str(reqResource).split('/')[-1]
                    injectableMapFile = self.mapInjectionFilesPath.text + resourceFileName
                    self.debug(injectableMapFile)

                    #if file path exists...
                    if exists(injectableMapFile):
                        
                        self.debug('Injectable map file found at: ' + injectableMapFile, 1)
                    
                        # load the file
                        injectableMapFileHandle = open(injectableMapFile, 'r')
                        injectableMapFileStr = injectableMapFileHandle.read()

                        # identify what encoding it is using if it isn't something "normal"
                        injectableMapFileStrEncoding = self.detectStringEncoding(injectableMapFileStr)
                        self.debug('Source map for injection is ' + str(injectableMapFileStrEncoding) + ' encoded', 3)

                        # flatten any undesirable characters, such "left double quotes" that just screw up the bytearray conversion
                        injectableMapFileBytes_step0 = unicodedata.normalize('NFKD', injectableMapFileStr).encode('ascii', 'ignore')

                        # finally, make sure everything is in utf-8 (as this is what the spec says it should be), probably a bit mute by this point though
                        # in any case it needs to be converted to a Python bytearray, ready to be converted into a Java array
                        if injectableMapFileStrEncoding:
                            injectableMapFileBytes_step1 = bytearray(injectableMapFileBytes_step0.decode(injectableMapFileStrEncoding).encode('utf-8'))
                        else:
                            self.debug('!!!Unknown charset encountered - may not be able to inject source map!!!', 0)
                            injectableMapFileBytes_step1 = bytearray(injectableMapFileBytes_step0.encode('utf-8'))

                        # convert into a Java array (the joys of working in Jython I suppose)
                        injectableMapFileBytes_step2 = array(injectableMapFileBytes_step1, 'b')

                        # ensure that the content type is specified correctly (may not matter but good to be sure)
                        newResHeaderStr = resHeaderStr.replace('Content-Type: text/html', 'Content-Type: application/javascript; charset=utf-8')
                        self.debug('Inserted Content-Type header', 2)

                        # inject the local response!  Phew...
                        # convert the new header string back into a bytearray and then into a Java array
                        newResHeaderBytes = array(bytearray(newResHeaderStr.encode('utf-8')), 'b')
                        message.setResponse(newResHeaderBytes + injectableMapFileBytes_step2)
                        self.debug('!!!Offline source map file injected!!!', 1)
                        #alert that a source map has been found
                        
                    else:
                        self.debug('No injectable map file found (' + injectableMapFile + ' attempted)', 1)
            
            else:
                self.debug('Request is not for a target resource or it\'s a map', 3)
        
        # end of function - return!
        return None

    def doPassiveScan(self, baseRequestResponse):
        httpService = baseRequestResponse.getHttpService()
        request = self._helpers.analyzeRequest(httpService, baseRequestResponse.getRequest())
        reqURL = request.getUrl()

        if len(issueDict) == 0:
            self.debug("No issues", 3)
            return None
        
        if str(reqURL) in issueDict:
       
            if issueDict[str(reqURL)] == "directive":
                self.debug('Source map directive found, no need for intervention', 1)
                
                issueName = 'Source Map Directive Found'
                issueDetail = 'A source map directive has been found'
                issueSeverity = 'Information'
                issueConfidence = 'Certain'
                issueBackground = """Source maps allow developers to debug minified code more easily.
                Source maps provide a mapping from the minified client-side code, such as Javascript, back to the original source code.
                This finding reflects the fact that the references to the client-side code's source maps were found."""
                remediationDetail = """Checks should be performed to determune if the source maps are accessible,
                or whether they are just references and are effectively unlinked."""
                remediationBackground = None
                issueURL = self._helpers.analyzeRequest(baseRequestResponse).getUrl()

                self.debug('Burp issue queued to be raised - source map directive found: ' + str(issueURL), 2)
            
            elif issueDict[str(reqURL)] == "embedded":
                issueName = ' Embedded Source Map Directive Found'
                issueDetail = 'An embedded source map directive has been found'
                issueSeverity = 'Information'
                issueConfidence = 'Certain'
                issueBackground = """Source maps allow developers to debug minified code more easily.
                Source maps provide a mapping from the minified client-side code, such as Javascript, back to the original source code.
                This finding reflects the fact that the references to the client-side code's source maps were found."""
                remediationDetail = """Checks should be performed to determune if the source maps are accessible,
                or whether they are just references and are effectively unlinked."""
                remediationBackground = None
                issueURL = self._helpers.analyzeRequest(baseRequestResponse).getUrl()

                self.debug('Burp issue queued to be raised - embedded source map found: ' + str(issueURL), 2)
            
            elif issueDict[str(reqURL)] == "200":
                issueName = 'Source Map Found'
                issueDetail = 'A public source map has been found'
                issueSeverity = 'Low'
                issueConfidence = 'Certain'
                issueBackground = """JavaScript source maps allow developers to debug minified code more easily.
                Source maps provide a mapping from the minified code back to the original source code.
                To achieve this source map files contain details of how the source files are structured 
                and data on how to map from the minified versions back to the original source code.
                If source maps are advertised, they can be automatically detected and parsed by the development tools
                that are shipped with modern browsers such as Chrome or Firefox.
                Furthermore, tools exist which probe for the existence of Source Map files that are unlinked or are otherwise not advertised.
                This makes the level of technical skill required to discover and make use of them very low,
                and the likelihood of them being discovered, relatively high.
                The impact of having a source map file varies depending on the context of the application. 
                More often than not, the impact is low as the code is effectively already public, just not easy to read."""
                remediationDetail = """As part of a defence in depth approach, it may be desirable to make the process
                of analysing the client-side source code more difficult."""
                remediationBackground = None
                issueURL = self._helpers.analyzeRequest(baseRequestResponse).getUrl()
                
                self.debug('Burp issue queued to be raised - source map found: ' + str(issueURL), 2)
            
            elif issueDict[str(reqURL)] == "invalid":
                issueName = 'Map file flagged as invalid'
                issueDetail = 'A map file appears to be syntactically incorrect'
                issueSeverity = 'Low'
                issueConfidence = 'Certain'
                issueBackground = """A map file with a HTTP 200 response has been found,
                but appears to be syntactically incorrect."""
                remediationDetail = None
                remediationBackground = None
                issueURL = self._helpers.analyzeRequest(baseRequestResponse).getUrl()
                
                self.debug('Burp issue queued to be raised - map file syntactically incorrect ' + str(issueURL), 2)
            
            elif issueDict[str(reqURL)] == "304":
                issueName = 'Source Map Found (cached)'
                issueDetail = 'A public source map has been found'
                issueSeverity = 'Low'
                issueConfidence = 'Tentative'
                issueBackground = """JavaScript source maps allow developers to debug minified code more easily.
                Source maps provide a mapping from the minified code back to the original source code.
                To achieve this source map files contain details of how the source files are structured 
                and data on how to map from the minified versions back to the original source code.
                If source maps are advertised, they can be automatically detected and parsed by the development tools
                that are shipped with modern browsers such as Chrome or Firefox.
                Furthermore, tools exist which probe for the existence of Source Map files that are unlinked or are otherwise not advertised.
                This makes the level of technical skill required to discover and make use of them very low,
                and the likelihood of them being discovered, relatively high.
                The impact of having a source map file varies depending on the context of the application. 
                More often than not, the impact is low as the code is effectively already public, just not easy to read."""
                remediationDetail = """As part of a defence in depth approach, it may be desirable to make the process
                of analysing the client-side source code more difficult."""
                remediationBackground = None
                issueURL = self._helpers.analyzeRequest(baseRequestResponse).getUrl()
                
                self.debug('Burp issue queued to be raised - source map found (cached): ' + str(issueURL), 2)

            else:
                self.debug("No issues", 3)
                return None
        else:
            self.debug("No issues", 3)
            return None
        
        return[issue(
            httpService,
            issueURL,
            [baseRequestResponse],
            issueName,
            issueDetail,
            issueSeverity,
            issueConfidence,
            issueBackground,
            remediationDetail,
            remediationBackground
            )]

    def doActiveScan():
        return None      
        
    def detectStringEncoding(self, string):
        codecs = ['ASCII', 'UTF-8', 'cp1252', 'latin-1', 'ISO 8859-1', 'ISO 8859-15', 'GBK', 'JIS', 'UCS-2', 'UCS-4', 'UTF-16', 'UTF-32', 'UTF-42']
        for i in codecs:
            try:
                string.decode(i)
                return i
            except UnicodeDecodeError:
                pass
        return False
    
    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getIssueName() == newIssue.getIssueName():
            self.debug("Issue already raised for this URL", 2)
            return -1
        self.debug("Extension generated burp issue raised", 1)
        return 0
                
    def extensionUnloaded(self):
        self.debug('Unloading extension...')


#IScanIssue imbedded class
class issue(IScanIssue):

    #generate a burp issue when 'issue' is called AKA when a source map or source map directive is found
    def __init__(self, httpService, reqURL, httpMessages, issueName, issueDetail, issueSeverity, issueConfidence, issueBackground, remediationDetail, remediationBackground):
        self._issueName = issueName
        self._httpService = httpService
        self._url = reqURL
        self._httpMessages = httpMessages
        self._issueDetail = issueDetail
        self._issueBackground = issueBackground
        self._severity = issueSeverity
        self._confidence = issueConfidence
        self._remediationDetail = remediationDetail
        self._remediationBackground = remediationBackground

        #identify the issue as an extension generated issue
        self._issueType = int(134217728)

        
    
    def getConfidence(self):
        return self._confidence

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService

    def getIssueBackground(self):
        return self._issueBackground

    def getIssueDetail(self):
        return self._issueDetail

    def getIssueName(self):
        return self._issueName
    
    def getIssueType(self):
        return self._issueType

    def getRemediationBackground(self):
        return self._remediationBackground

    def getRemediationDetail(self):
        return self._remediationDetail

    def getSeverity(self):
        return self._severity

    def getUrl(self):
        return self._url

