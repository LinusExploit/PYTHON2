#!/usr/bin/python
file = open('response.html','w+')
import sys
import urllib2
import urllib
import cookielib

url = sys.argv[1]
### The page to which we are doing the authentication.
auth_url = 'https://sso.cisco.com/autho/login/loginaction.html'
print url
print auth_url

### The Data we are sending in our post authentication .
values = {'userid':'xxxxx', 'password':'xxxxx', 'target':'', 'xxxxxxx':'',
'xxxxx':'', 'xxxxxx':'','xxxxxx':'', 'xxxxxxx':''}

### encode the post data into the url.
data = urllib.urlencode(values)

### cookies handler
jar = cookielib.FileCookieJar("cookie") 
opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(jar)) 

### fetch topic.cisco.com
###response = urllib2.urlopen(url)
request1 = urllib2.request(url)
response = opener.open(url)

### perform authentication
##req = urllib2.Request(auth_url, data)

 

####response2 = urllib2.urlopen(req)

### print the first result.
###print response.read()

### print second response
print response2.read()
#file.write(response.read())
