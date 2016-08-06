import httplib
import urllib
import json
import Cookie


class SendAndGetter:

    def __init__(self, show_traffic=True):
        self.show_traffic = show_traffic

    def send_and_get(self, conn, method, url, body=None, cookies=None):
        headers = {}
    
        if body != None:
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
    
        if cookies != None:
            cookies_str = cookies.output(header='',sep=';')
            if len(cookies_str) > 1 and cookies_str[0] == ' ':
                # A leading space appears for some reason.
                cookies_str = cookies_str[1:]
    
            headers['Cookie'] = cookies_str
    
        if self.show_traffic:
            print 'Send:'
            print method
            print url
            print headers
            print body
    
        conn.connect()
        conn.request(method, url, body, headers)
        resp = conn.getresponse()
        body = resp.read()
    
        resp_cookies = Cookie.SimpleCookie()
        for (header, value) in resp.getheaders():
            if header == 'set-cookie':
                resp_cookies.load(value)
    
        conn.close()
    
        if self.show_traffic:
            print 'Recv:', resp.status, resp.reason, resp.getheaders(), str(resp_cookies)
            print body
    
        return json.loads(body), resp_cookies


def blank_nones(obj):
    for key in obj.keys():
        if obj[key] == None:
            obj[key] = ''
    return obj

def encode(obj):
    return urllib.urlencode(blank_nones(obj))

