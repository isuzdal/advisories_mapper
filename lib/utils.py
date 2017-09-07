try:
    # Python 2
    import urllib2
except ImportError:
    # Python 3
    import urllib.request as urllib2

def fetch_content(uri,tmout=30):
    try:
        body = urllib2.urlopen(uri,timeout=tmout).read()
    except:
        body = str()
    return body
