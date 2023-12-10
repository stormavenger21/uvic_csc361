'''
CSC361 Fall2023
MVO
'''
import io
import socket
import ssl
import sys
import re

#HTTP/2 tester:
#https://tools.keycdn.com/http2-test

PORT=443
'''
#HOST="www.amazon.com"
HOST="https://www.bcauction.ca"
#HOST="www.gcsurplus.ca"
HOST="docs.engr.uvic.ca/docs"
HOST="www.uvic.ca/index.html"
HOST="accounts.google.com"
HOST="mail.google.com"
HOST="ttgf45"
HOST="https://tools.keycdn.com/http2-test"
HOST="WWW.GOOGLE.COM"
HOST="WWW.YOUTUBE.COM"
#HOST="bctransit.com/victoria/home"
HOST="https://www.microsoft.com/en-ca"
#HOST="https://www.python.org"
HOST="https://www.ebay.ca"
HOST="www.amazon.com"
'''

def main():
    if len(sys.argv) < 2:
        print("Error: invalid length. Enter a URI/URL")
        sys.exit()
    url=sys.argv[1]
    #url=HOST
    try:
        start(url)
    except:
        print("Error: unable to connect with server")



'''
print webserver info

param url:      the URI
returns:        nothing
'''
def start(url):
    result=" "
    list=parse(url)
    if list is None:
        print("Error: invalid URI. Format incorrect ")
        exit(0)
    url=list[0]
    path=list[1]
    password_protect=False
    redirect=False

    print("Website: "+url)
    print("Supports HTTP/2: " + str(support_HTTP2(url)))
    try:
        result=get_HTTP_request(url, path)
    except:
        print("unable to perform GET, please try again")
    print("Newest version of HTTP supported: "+str(get_HTTP_version(result)[0])) #error with https://www.netflix.com 

    status_code=get_HTTP_redir(result)[0]
    if '302' in status_code:
        redirect_code_pattern=r'https?://(\S+)' #'http://(.*?)/|https://(.*?)/'         #r'https://(.*?)/'
        new_host=re.findall(redirect_code_pattern,result.decode('utf-8'))
        list=parse(str(new_host[0]))
        if list is None:
            print("Error: invalid URI")
            exit(0)
        url=list[0]
        path=list[1]
        print("new URL: "+str(url))
        path=""
        result=get_HTTP_request(url, path)
        redirect=True
    elif '301' in status_code:
        print("Error: website moved. Unable to find server")
    elif '401' in status_code:
        password_protect=True
    elif '400' in status_code:
        print("bad request")
    
    print("Redirected: "+str(redirect))
    print("Password protected: " +str(password_protect))
    print("List of cookies: ")
    print(*format_cookies(result),sep='\n') 
    



'''
separate host and path from URI

param url:      the URI/URL
returns:        <list> containing host and path, if any
                <None> if incorrect URL
'''
def parse(url):
    p1_host=r'^http://(.*)|^https://(.*)'
    p2_path=r'/{1}(.*)'     #'(?<=[\..*])(\w*)'
    p3_correct_URI_format='.*(\.).*' #'.*(www.).*'
    path=""
    #test for stuff that is not a URI
    if(re.search(p3_correct_URI_format,url)) is None:
        return None
    #check if http/https present
    if(re.search(p1_host,url)) is not None:
        strip_http=re.split(p1_host,url)
        url=str(strip_http[2])
    #check if path present
    if(re.search(p2_path,url)) is not None:
        x=re.split(p2_path,url)
        url=x[0]
        path=x[1]
    return [url,path]




'''
find HTTP status code from response 

param response:     large chunk of text from HTTP request. This contains 
                    HTTP status code and other information that is of no interest
returns:            HTTP status code
'''
def get_HTTP_redir(response):
    pattern=r'HTTP/.*\s([1-5].[0-7])\s'
    redirect=re.findall(pattern, str(response),re.IGNORECASE)#(pattern, response.decode('utf-8'))
    return(redirect)





'''
determine what version of HTTP server is using

param response:     large chunk of text from HTTP request. This contains 
                    version and other information that is of no interest
returns:            version number 
'''
def get_HTTP_version(response):
    pattern=r'HTTP/(.*?)\s'
    version=re.findall(pattern, str(response),re.IGNORECASE)
    return(version)





'''
format cookies into a list for easy viewing

param blarg:    large chunk of text from HTTP request. This contains 
                cookies but mostly other information that is of no interest
returns:        list of dictionaries containing [name, domain, expire]
'''
def format_cookies(blarg):
    array_of_dict=[]
    cookie_p1=r'Set-Cookie:\s.*?\n'  #r'Set-Cookie:\s(.*?);'
    cookies=re.findall(cookie_p1, blarg.decode('utf-8'),re.IGNORECASE)
    #print(blarg)
    for cookie in cookies:
        cookie_dict={
            "COOKIE":"",
            "DOMAIN":"",
            "EXPIRES":""
        }
        cookie_name='Set-Cookie:\s(.*?)='
        x=re.findall(cookie_name,cookie,re.IGNORECASE)
        cookie_dict.update({"COOKIE":x})

        cookie_domain='Domain=.(.*?);'
        y=re.findall(cookie_domain,cookie,re.IGNORECASE)
        cookie_dict.update({"DOMAIN":y})

        cookie_expire='Expires=(.*?);'
        z=re.findall(cookie_expire,cookie,re.IGNORECASE)
        cookie_dict.update({"EXPIRES":z})

        array_of_dict.append(cookie_dict)
    #print(*array_of_dict,sep='\n')

    return(array_of_dict)





'''
send a get request and capture the response

param url:    the address of a website passed by stdin
returns:      the response from the webserver
'''
def get_HTTP_request(url,address):
    HTTP_request=""
    context=ssl.create_default_context()
    conn=context.wrap_socket(socket.socket(socket.AF_INET,socket.SOCK_STREAM),server_hostname=url)
    try:
        conn.connect((url,PORT))
    except:
        print("SSLCertVerificationError: certificate verify failed")
        exit(0)
    req="HEAD /" + address  + " HTTP/1.1\r\nHOST:"+ url +"\r\nCONNECTION:Keep-Alive\r\n\r\n"
    #req="GET /" + address  + " HTTP/1.1\r\nHOST:"+ url +"\r\nCONNECTION:Keep-Alive\r\n\r\n"
    conn.send(req.encode('utf-8'))
    HTTP_request=conn.recv(20000)
    conn.close()
    #conn.send("GET /HTTP/1.1\r\n\r\n")
    #req="GET /index.html"  + " HTTP/1.1\r\nHOST:"+ url +"\r\nCONNECTION:Keep-Alive\r\n\r\n"

    
    return(HTTP_request)






'''
test for HTTP2 support

param url:  address of website from stdin
returns:    true if supports HTTP2, false otherwise
'''
def support_HTTP2(url):
    HTTP_protocol=" "
   # try:
    context=ssl.create_default_context()
    context.set_alpn_protocols(['h2', 'spdy/3', 'http/1.1','spdy/2'])
    conn=context.wrap_socket(socket.socket(socket.AF_INET,socket.SOCK_STREAM),server_hostname=url)
    try:
        conn.connect((url,PORT))
    except:
        print("SSLCertVerificationError: certificate verify failed")
        exit(0)
    HTTP_protocol=conn.selected_alpn_protocol()
    if HTTP_protocol=="h2":
        return True
    else:
        return False



if __name__=='__main__':
    main()
